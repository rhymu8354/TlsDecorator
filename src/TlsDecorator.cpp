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
         * This flag indicates whether or not the upper layer has indicated
         * a graceful close should be done.
         */
        bool upperLayerClosed = false;

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
            diagnosticsSender.SendDiagnosticInformationFormatted(
                0, "receive(%zu)", data.size()
            );
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
            std::unique_lock< decltype(mutex) > lock(mutex);
            diagnosticsSender.SendDiagnosticInformationString(
                0, "Remote closed"
            );
            open = false;
            wakeCondition.notify_all();
            if (
                receiveBufferSecure.empty()
                && (brokenDelegate != nullptr)
            ) {
                lock.unlock();
                brokenDelegate(false);
            }
        }

        /**
         * This method runs in a separate thread, performing all
         * I/O with the TLS layer.
         */
        void Worker() {
            std::unique_lock< decltype(mutex) > lock(mutex);
            bool tryRead = true;
            while (!stopWorker) {
                if (
                    !sendBuffer.empty()
                    && canWrite
                    && open
                ) {
                    diagnosticsSender.SendDiagnosticInformationFormatted(
                        0, "tls_write(%zu)", sendBuffer.size()
                    );
                    const auto amount = selectedTlsShim->tls_write(
                        tlsImpl.get(),
                        sendBuffer.data(),
                        sendBuffer.size()
                    );
                    if (amount == TLS_WANT_POLLIN) {
                        // Can't write any more until we read some more...
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            0, "tls_write(%zu) -> TLS_WANT_POLLIN", sendBuffer.size()
                        );
                        canWrite = false;
                    } else if (amount < 0) {
                        const auto tlsErrorMessage = selectedTlsShim->tls_error(tlsImpl.get());
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                            "tls_write(%zu) -> error: %s",
                            sendBuffer.size(),
                            tlsErrorMessage
                        );
                        lowerLayer->Close(false);
                        break;
                    } else {
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            0, "tls_write(%zu) -> %zu", sendBuffer.size(), (size_t)amount
                        );
                        if ((size_t)amount == sendBuffer.size()) {
                            sendBuffer.clear();
                            if (upperLayerClosed) {
                                break;
                            }
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
                    tryRead = true;
                    receiveBufferDecrypted.resize(DECRYPTED_BUFFER_SIZE);
                    diagnosticsSender.SendDiagnosticInformationString(
                        0, "tls_read"
                    );
                    const auto amount = selectedTlsShim->tls_read(
                        tlsImpl.get(),
                        receiveBufferDecrypted.data(),
                        receiveBufferDecrypted.size()
                    );
                    if (amount == TLS_WANT_POLLIN) {
                        // Can't read any more because we're out of data.
                        diagnosticsSender.SendDiagnosticInformationString(
                            0, "tls_read -> TLS_WANT_POLLIN"
                        );
                    } else if (amount < 0) {
                        const auto tlsErrorMessage = selectedTlsShim->tls_error(tlsImpl.get());
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                            "tls_read -> error: %s",
                            tlsErrorMessage
                        );
                        lowerLayer->Close(false);
                        break;
                    } else if (amount > 0) {
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            0, "tls_read -> %zu", (size_t)amount
                        );
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
            }
            if (upperLayerClosed) {
                diagnosticsSender.SendDiagnosticInformationString(
                    0, "Closed gracefully"
                );
                if (lowerLayer != nullptr) {
                    lowerLayer->Close(true);
                }
            }
        }
    };

    TlsDecorator::~TlsDecorator() noexcept {
        Close(false);
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

        // ----------------------------------
        // I don't know about this, but it was in the example....
        selectedTlsShim->tls_config_insecure_noverifycert(impl_->tlsConfig.get());
        selectedTlsShim->tls_config_insecure_noverifyname(impl_->tlsConfig.get());
        // ----------------------------------

        selectedTlsShim->tls_config_set_protocols(impl_->tlsConfig.get(), TLS_PROTOCOLS_DEFAULT);

        if (selectedTlsShim->tls_configure(impl_->tlsImpl.get(), impl_->tlsConfig.get()) != 0) {
            return false;
        }
        if (
            selectedTlsShim->tls_connect_cbs(
                impl_->tlsImpl.get(),
                [](struct tls *_ctx, void *_buf, size_t _buflen, void *_cb_arg){
                    const auto self = (TlsDecorator*)_cb_arg;
                    std::lock_guard< decltype(self->impl_->mutex) > lock(self->impl_->mutex);
                    const auto amt = std::min(_buflen, self->impl_->receiveBufferSecure.size());
                    if (
                        (amt == 0)
                        && self->impl_->open
                    ) {
                        self->impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                            0, "_read_cb(%zu) -> TLS_WANT_POLLIN", _buflen
                        );
                        return (ssize_t)TLS_WANT_POLLIN;
                    }
                    self->impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                        0, "_read_cb(%zu) -> %zu (of %zu)", _buflen, amt, self->impl_->receiveBufferSecure.size()
                    );
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
                    const auto self = (TlsDecorator*)_cb_arg;
                    std::lock_guard< decltype(self->impl_->mutex) > lock(self->impl_->mutex);
                    self->impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                        0, "_write_cb(%zu)", _buflen
                    );
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
            const auto tlsErrorMessage = selectedTlsShim->tls_error(impl_->tlsImpl.get());
            impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                "tls_connect_cbs -> error: %s",
                tlsErrorMessage
            );
            return false;
        }
        if (
            !impl_->lowerLayer->Process(
                std::bind(&Impl::SecureMessageReceived, impl_.get(), std::placeholders::_1),
                std::bind(&Impl::ConnectionBroken, impl_.get())
            )
        ) {
            return false;
        }
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
        return impl_->lowerLayer->IsConnected();
    }

    uint32_t TlsDecorator::GetBoundAddress() const {
        return impl_->lowerLayer->GetBoundAddress();
    }

    uint16_t TlsDecorator::GetBoundPort() const {
        return impl_->lowerLayer->GetBoundPort();
    }

    void TlsDecorator::SendMessage(const std::vector< uint8_t >& message) {
        std::unique_lock< decltype(impl_->mutex) > lock(impl_->mutex);
        impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
            0, "send(%zu)", message.size()
        );
        impl_->sendBuffer.insert(
            impl_->sendBuffer.end(),
            message.begin(),
            message.end()
        );
        impl_->wakeCondition.notify_all();
    }

    void TlsDecorator::Close(bool clean) {
        std::unique_lock< decltype(impl_->mutex) > lock(impl_->mutex);
        if (!impl_->worker.joinable()) {
            return;
        }
        impl_->upperLayerClosed = true;
        if (
            !impl_->sendBuffer.empty()
            && clean
        ) {
            impl_->diagnosticsSender.SendDiagnosticInformationString(
                0, "Closing gracefully"
            );
            return;
        }
        impl_->stopWorker = true;
        if (std::this_thread::get_id() != impl_->worker.get_id()) {
            impl_->wakeCondition.notify_all();
            lock.unlock();
            impl_->worker.join();
        }
    }

}
