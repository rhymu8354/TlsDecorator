/**
 * @file TlsDecorator.cpp
 *
 * This module contains the implementation of the
 * TlsDecorator::TlsDecorator class.
 *
 * © 2018 by Richard Walters
 */

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <stddef.h>
#include <stdio.h>
#include <SystemAbstractions/DiagnosticsSender.hpp>
#include <thread>
#include <TlsDecorator/TlsShim.hpp>
#include <TlsDecorator/TlsDecorator.hpp>

namespace {

    /**
     * This is the number of bytes to allocate for receiving decrypted
     * data from the TLS layer.
     */
    constexpr size_t DECRYPTED_BUFFER_SIZE = 65536;

}

namespace TlsDecorator {

    struct TlsDecorator::Impl {
        // Properties

        /**
         * This is a helper object used to publish diagnostic messages.
         */
        SystemAbstractions::DiagnosticsSender diagnosticsSender;

        /**
         * This is the lower-level client connection to decorate.
         */
        std::shared_ptr< SystemAbstractions::INetworkConnection > lowerLayer;

        /**
         * When configured to operate TLS in client mode, this is the name
         * of the server with which to connect as a TLS client.
         */
        std::string serverName;

        /**
         * This is the method to call to deliver data received
         * and decrypted from the TLS layer.
         */
        MessageReceivedDelegate messageReceivedDelegate;

        /**
         * This is the method to call whenever the underlying
         * connection has been broken.
         */
        BrokenDelegate brokenDelegate;

        /**
         * This implements the TLS layer.
         */
        std::unique_ptr< tls, std::function< void(tls*) > > tlsImpl;

        /**
         * This is used to configure the TLS layer.
         */
        std::unique_ptr< tls_config, std::function< void(tls_config*) > > tlsConfig;

        /**
         * This is used to synchronize access to the state of this object.
         */
        std::recursive_mutex mutex;

        /**
         * This is used to alert any threads that might be waiting on
         * changes to the state of this object.
         */
        std::condition_variable_any wakeCondition;

        /**
         * This holds data sent from the lower-level client connection
         * before it's written to the TLS layer.
         */
        std::vector< uint8_t > sendBuffer;

        /**
         * This holds data received from the lower-level client connection
         * before it's read by the TLS layer.
         */
        std::vector< uint8_t > receiveBufferSecure;

        /**
         * This holds data received from the TLS layer, to be delivered
         * to the data received delegate.
         */
        std::vector< uint8_t > receiveBufferDecrypted;

        /**
         * This flag keeps track of whether or not the lower-level client
         * connection is still open.
         */
        bool open = true;

        /**
         * This flag indicates whether or not we should attempt to write
         * data to the TLS layer.  It's cleared if tls_write returns
         * TLS_WANT_POLLIN, and set again when the read callback is able
         * to deliver more data to the TLS layer.
         */
        bool canWrite = true;

        /**
         * This thread performs all TLS read/write asynchronously.
         */
        std::thread worker;

        /**
         * This flag is set whenever the worker thread should stop.
         */
        bool stopWorker = true;

        // Methods

        /**
         * This is the constructor for the structure.
         */
        Impl()
            : diagnosticsSender("TlsDecorator")
        {
        }

        /**
         * This method is called when secure data comes in from the TLS layer.
         *
         * @param[in] data
         *     This is the data that was received from the remote peer.
         */
        void SecureMessageReceived(const std::vector< uint8_t >& data) {
            std::lock_guard< decltype(mutex) > lock(mutex);
            printf("received secure data (%zu more bytes, %zu total)\n", data.size(), data.size() + receiveBufferSecure.size());
            receiveBufferSecure.insert(
                receiveBufferSecure.end(),
                data.begin(),
                data.end()
            );
            wakeCondition.notify_all();
        }

        /**
         * This method is called when the lower-layer connection is broken.
         */
        void ConnectionBroken() {
            printf("other end broke\n");
            {
                std::lock_guard< decltype(mutex) > lock(mutex);
                open = false;
                wakeCondition.notify_all();
            }
            if (
                receiveBufferSecure.empty()
                && (brokenDelegate != nullptr)
            ) {
                brokenDelegate(false);
            }
        }

        /**
         * This method runs in a separate thread, performing all
         * I/O with the TLS layer.
         */
        void Worker() {
            printf("worker: starting\n");
            std::unique_lock< decltype(mutex) > lock(mutex);
            bool tryRead = true;
            while (!stopWorker) {
                if (
                    !sendBuffer.empty()
                    && canWrite
                    && open
                ) {
                    printf("tls_write (%zu)\n", sendBuffer.size());
                    const auto amount = selectedTlsShim->tls_write(
                        tlsImpl.get(),
                        sendBuffer.data(),
                        sendBuffer.size()
                    );
                    if (amount == TLS_WANT_POLLIN) {
                        // Can't write any more until we read some more...
                        printf("tls_write returned: TLS_WANT_POLLIN\n");
                        canWrite = false;
                    } else if (amount < 0) {
                        printf("tls_write returned %d -- ERROR?\n", (int)amount);
                        lowerLayer->Close(false);
                    } else {
                        printf("tls_write returned %zd\n", (size_t)amount);
                        if ((size_t)amount == sendBuffer.size()) {
                            sendBuffer.clear();
                        } else {
                            sendBuffer.erase(
                                sendBuffer.begin(),
                                sendBuffer.begin() + (size_t)amount
                            );
                        }
                    }
                }
                if (
                    !receiveBufferSecure.empty()
                    || tryRead
                ) {
                    printf("tls_read (%zu)\n", DECRYPTED_BUFFER_SIZE);
                    tryRead = true;
                    receiveBufferDecrypted.resize(DECRYPTED_BUFFER_SIZE);
                    const auto amount = selectedTlsShim->tls_read(
                        tlsImpl.get(),
                        receiveBufferDecrypted.data(),
                        receiveBufferDecrypted.size()
                    );
                    if (amount == TLS_WANT_POLLIN) {
                        printf("tls_read returned: TLS_WANT_POLLIN\n");
                        // Can't read any more because we're out of data.
                    } else if (amount == TLS_WANT_POLLOUT) {
                        // Can't read any more until we write some more...
                        // (I think we shouldn't ever get here, but let's see...
                        printf("TLS_WANT_POLLOUT\n");
                    } else if (amount < 0) {
                        const auto tlsErrorMessage = selectedTlsShim->tls_error(tlsImpl.get());
                        printf("tls_read returned %d -- ERROR? tls_error says: \"%s\"\n", (int)amount, tlsErrorMessage);
                        lowerLayer->Close(false);
                    } else if (amount > 0) {
                        printf("tls_read returned %zd\n", (size_t)amount);
                        receiveBufferDecrypted.resize((size_t)amount);
                        if (messageReceivedDelegate != nullptr) {
                            lock.unlock();
                            messageReceivedDelegate(receiveBufferDecrypted);
                            lock.lock();
                        }
                        if (
                            receiveBufferSecure.empty()
                            && !open
                        ) {
                            if (brokenDelegate != nullptr) {
                                brokenDelegate(false);
                            }
                        }
                    } else {
                        tryRead = false;
                    }
                }
                wakeCondition.wait(
                    lock,
                    [this]{
                        return (
                            stopWorker
                            || !receiveBufferSecure.empty()
                            || (
                                !sendBuffer.empty()
                                && canWrite
                            )
                        );
                    }
                );
                printf("worker: wake up\n");
            }
            printf("worker: stopping\n");
        }
    };

    TlsDecorator::~TlsDecorator() noexcept {
        if (impl_->worker.joinable()) {
            {
                std::lock_guard< decltype(impl_->mutex) > lock(impl_->mutex);
                impl_->stopWorker = true;
                impl_->wakeCondition.notify_all();
            }
            impl_->worker.join();
        }
    }

    TlsDecorator::TlsDecorator()
        : impl_(new Impl())
    {
        impl_->receiveBufferDecrypted.reserve(DECRYPTED_BUFFER_SIZE);
    }

    void TlsDecorator::Configure(
        std::shared_ptr< SystemAbstractions::INetworkConnection > lowerLayer,
        const std::string& serverName
    ) {
        if (impl_->worker.joinable()) {
            return;
        }
        impl_->lowerLayer = lowerLayer;
        impl_->serverName = serverName;
    }

    SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate TlsDecorator::SubscribeToDiagnostics(
        SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
        size_t minLevel
    ) {
        return impl_->diagnosticsSender.SubscribeToDiagnostics(delegate, minLevel);
    }

    bool TlsDecorator::Connect(uint32_t peerAddress, uint16_t peerPort) {
        return impl_->lowerLayer->Connect(peerAddress, peerPort);
    }

    bool TlsDecorator::Process(
        MessageReceivedDelegate messageReceivedDelegate,
        BrokenDelegate brokenDelegate
    ) {
        impl_->messageReceivedDelegate = messageReceivedDelegate;
        impl_->brokenDelegate = brokenDelegate;
        impl_->tlsConfig = decltype(impl_->tlsConfig)(
            selectedTlsShim->tls_config_new(),
            [](tls_config* p){
                selectedTlsShim->tls_config_free(p);
            }
        );
        impl_->tlsImpl = decltype(impl_->tlsImpl)(
            selectedTlsShim->tls_client(),
            [](tls* p) {
                selectedTlsShim->tls_close(p);
                selectedTlsShim->tls_free(p);
            }
        );
        printf("tls_configure()...\n");

        // ----------------------------------
        // I don't know about this, but it was in the example....
        selectedTlsShim->tls_config_insecure_noverifycert(impl_->tlsConfig.get());
        selectedTlsShim->tls_config_insecure_noverifyname(impl_->tlsConfig.get());
        // ----------------------------------

        selectedTlsShim->tls_config_set_protocols(impl_->tlsConfig.get(), TLS_PROTOCOLS_DEFAULT);

        if (selectedTlsShim->tls_configure(impl_->tlsImpl.get(), impl_->tlsConfig.get()) != 0) {
            return false;
        }
        printf("tls_connect_cbs()...\n");
        if (
            selectedTlsShim->tls_connect_cbs(
                impl_->tlsImpl.get(),
                [](struct tls *_ctx, void *_buf, size_t _buflen, void *_cb_arg){
                    const auto self = (TlsDecorator*)_cb_arg;
                    std::lock_guard< decltype(self->impl_->mutex) > lock(self->impl_->mutex);
                    printf("_read_cb(%zu) -- %zu is available\n", _buflen, self->impl_->receiveBufferSecure.size());
                    const auto amt = std::min(_buflen, self->impl_->receiveBufferSecure.size());
                    if (
                        (amt == 0)
                        && self->impl_->open
                    ) {
                        return (ssize_t)TLS_WANT_POLLIN;
                    }
                    self->impl_->canWrite = true;
                    (void)memcpy(_buf, self->impl_->receiveBufferSecure.data(), amt);
                    if (amt == self->impl_->receiveBufferSecure.size()) {
                        self->impl_->receiveBufferSecure.clear();
                    } else {
                        self->impl_->receiveBufferSecure.erase(
                            self->impl_->receiveBufferSecure.begin(),
                            self->impl_->receiveBufferSecure.begin() + amt
                        );
                    }
                    return (ssize_t)amt;
                },
                [](struct tls *_ctx, const void *_buf, size_t _buflen, void *_cb_arg){
                    printf("_write_cb(%zu)\n", _buflen);
                    const auto self = (TlsDecorator*)_cb_arg;
                    std::lock_guard< decltype(self->impl_->mutex) > lock(self->impl_->mutex);
                    if (self->impl_->open) {
                        const auto bufBytes = (const uint8_t*)_buf;
                        self->impl_->lowerLayer->SendMessage(
                            std::vector< uint8_t >(bufBytes, bufBytes + _buflen)
                        );
                    }
                    return (ssize_t)_buflen;
                },
                this,
                impl_->serverName.c_str()
            ) != 0
        ) {
            return false;
        }
        printf("TLS connected... starting worker\n");
        impl_->stopWorker = false;
        impl_->worker = std::thread(&TlsDecorator::Impl::Worker, impl_.get());
        return true;
    }

    uint32_t TlsDecorator::GetPeerAddress() const {
        return impl_->lowerLayer->GetPeerAddress();
    }

    uint16_t TlsDecorator::GetPeerPort() const {
        return impl_->lowerLayer->GetPeerPort();
    }

    bool TlsDecorator::IsConnected() const {
        return false;
    }

    uint32_t TlsDecorator::GetBoundAddress() const {
        return 0;
    }

    uint16_t TlsDecorator::GetBoundPort() const {
        return 0;
    }

    void TlsDecorator::SendMessage(const std::vector< uint8_t >& message) {
        printf("queueing %zu to send to TLS\n", message.size());
        std::unique_lock< decltype(impl_->mutex) > lock(impl_->mutex);
        impl_->sendBuffer.insert(
            impl_->sendBuffer.end(),
            message.begin(),
            message.end()
        );
        impl_->wakeCondition.notify_all();
    }

    void TlsDecorator::Close(bool clean) {
        impl_->diagnosticsSender.SendDiagnosticInformationString(
            1, "Close was called"
        );
        if (impl_->lowerLayer == nullptr) {
            return;
        }
        impl_->lowerLayer->Close(false);
    }

}
