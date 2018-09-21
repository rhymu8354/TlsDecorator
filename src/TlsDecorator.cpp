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
        // Types

        /**
         * These are the different modes the decorator can be in.
         */
        enum class Mode {
            /**
             * In this mode, the decorator is not yet configured.
             */
            None,

            /**
             * In this mode, the decorator is operating the TLS layer
             * as a client.
             */
            Client,

            /**
             * In this mode, the decorator is operating the TLS layer
             * as a server.
             */
            Server,
        };

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
         * This indiates the current mode of the decorator.
         */
        Mode mode = Mode::None;

        /**
         * This is the concatenation of the root Certificate Authority
         * (CA) certificates to trust, in PEM format.
         */
        std::vector< uint8_t > caCerts;

        /**
         * This is the server's certificate, in PEM format.
         */
        std::vector< uint8_t > cert;

        /**
         * This is the server's private key, in PEM format.
         */
        std::vector< uint8_t > key;

        /**
         * This is the password for the server's private key.
         */
        std::string password;

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
            std::vector< uint8_t > buffer;
            while (!stopWorker) {
                if (
                    !sendBuffer.empty()
                    && canWrite
                    && open
                ) {
                    diagnosticsSender.SendDiagnosticInformationFormatted(
                        0, "tls_write(%zu)", sendBuffer.size()
                    );
                    buffer.assign(sendBuffer.begin(), sendBuffer.end());
                    lock.unlock();
                    const auto amount = selectedTlsShim->tls_write(
                        tlsImpl.get(),
                        buffer.data(),
                        buffer.size()
                    );
                    lock.lock();
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
                        lock.unlock();
                        lowerLayer->Close(false);
                        lock.lock();
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
                    buffer.resize(DECRYPTED_BUFFER_SIZE);
                    diagnosticsSender.SendDiagnosticInformationString(
                        0, "tls_read"
                    );
                    lock.unlock();
                    const auto amount = selectedTlsShim->tls_read(
                        tlsImpl.get(),
                        buffer.data(),
                        buffer.size()
                    );
                    lock.lock();
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
                        lock.unlock();
                        lowerLayer->Close(false);
                        lock.lock();
                        break;
                    } else if (amount > 0) {
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            0, "tls_read -> %zu", (size_t)amount
                        );
                        buffer.resize((size_t)amount);
                        if (messageReceivedDelegate != nullptr) {
                            lock.unlock();
                            messageReceivedDelegate(buffer);
                            lock.lock();
                        }
                        if (
                            receiveBufferSecure.empty()
                            && !open
                        ) {
                            if (brokenDelegate != nullptr) {
                                lock.unlock();
                                brokenDelegate(false);
                                lock.lock();
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
                lock.unlock();
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
    }

    void TlsDecorator::ConfigureAsClient(
        std::shared_ptr< SystemAbstractions::INetworkConnection > lowerLayer,
        const std::string& caCerts,
        const std::string& serverName
    ) {
        if (impl_->worker.joinable()) {
            return;
        }
        impl_->lowerLayer = lowerLayer;
        impl_->caCerts.assign(caCerts.begin(), caCerts.end());
        impl_->serverName = serverName;
        impl_->mode = Impl::Mode::Client;
    }

    void TlsDecorator::ConfigureAsServer(
        std::shared_ptr< SystemAbstractions::INetworkConnection > lowerLayer,
        const std::string& cert,
        const std::string& key,
        const std::string& password
    ) {
        if (impl_->worker.joinable()) {
            return;
        }
        impl_->lowerLayer = lowerLayer;
        impl_->cert.assign(cert.begin(), cert.end());
        impl_->key.assign(key.begin(), key.end());
        impl_->password = password;
        impl_->mode = Impl::Mode::Server;
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
        if (impl_->worker.joinable()) {
            impl_->diagnosticsSender.SendDiagnosticInformationString(
                SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                "Process called while already processing"
            );
            return false;
        }
        if (impl_->mode == Impl::Mode::None) {
            impl_->diagnosticsSender.SendDiagnosticInformationString(
                SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                "Process called without first configuring"
            );
            return false;
        }
        impl_->messageReceivedDelegate = messageReceivedDelegate;
        impl_->brokenDelegate = brokenDelegate;
        impl_->tlsConfig = decltype(impl_->tlsConfig)(
            selectedTlsShim->tls_config_new(),
            [](tls_config* p){
                selectedTlsShim->tls_config_free(p);
            }
        );
        const auto tlsImplDeleter = [](tls* p) {
            selectedTlsShim->tls_close(p);
            selectedTlsShim->tls_free(p);
        };
        if (impl_->mode == Impl::Mode::Client) {
            impl_->tlsImpl = decltype(impl_->tlsImpl)(
                selectedTlsShim->tls_client(),
                tlsImplDeleter
            );
            (void)selectedTlsShim->tls_config_set_ca_mem(
                impl_->tlsConfig.get(),
                impl_->caCerts.data(),
                impl_->caCerts.size()
            );
        } else {
            impl_->tlsImpl = decltype(impl_->tlsImpl)(
                selectedTlsShim->tls_server(),
                tlsImplDeleter
            );
            (void)selectedTlsShim->tls_config_set_cert_mem(
                impl_->tlsConfig.get(),
                impl_->cert.data(),
                impl_->cert.size()
            );
            std::unique_ptr< BIO, std::function< void(BIO*) > > encryptedKeyInput(
                selectedTlsShim->BIO_new_mem_buf(
                    impl_->key.data(),
                    (int)impl_->key.size()
                ),
                [](BIO* p){ selectedTlsShim->BIO_free_all(p); }
            );
            std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > key(
                selectedTlsShim->PEM_read_bio_PrivateKey(
                    encryptedKeyInput.get(),
                    NULL,
                    NULL,
                    (void*)impl_->password.c_str()
                ),
                [](EVP_PKEY* p){ selectedTlsShim->EVP_PKEY_free(p); }
            );
            if (key == NULL) {
                impl_->diagnosticsSender.SendDiagnosticInformationString(
                    SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                    "error reading private key"
                );
                return false;
            }
            std::unique_ptr< BIO, std::function< void(BIO*) > > decryptedKeyOutput(
                selectedTlsShim->BIO_new(BIO_s_mem()),
                [](BIO* p){ selectedTlsShim->BIO_free_all(p); }
            );
            if (
                !selectedTlsShim->PEM_write_bio_PrivateKey(
                    decryptedKeyOutput.get(),
                    key.get(),
                    NULL, NULL, 0, NULL, NULL
                )
            ) {
                impl_->diagnosticsSender.SendDiagnosticInformationString(
                    SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                    "error decrypting private key"
                );
                return false;
            }
            char* decryptedKeyContents;
            const auto decryptedKeySize = selectedTlsShim->BIO_get_mem_data(
                decryptedKeyOutput.get(),
                &decryptedKeyContents
            );
            if (decryptedKeySize < 0) {
                impl_->diagnosticsSender.SendDiagnosticInformationString(
                    SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                    "error extracting decrypted private key"
                );
                return false;
            }
            (void)selectedTlsShim->tls_config_set_key_mem(
                impl_->tlsConfig.get(),
                (const uint8_t*)decryptedKeyContents,
                decryptedKeySize
            );
        }

        selectedTlsShim->tls_config_set_protocols(impl_->tlsConfig.get(), TLS_PROTOCOLS_DEFAULT);

        if (selectedTlsShim->tls_configure(impl_->tlsImpl.get(), impl_->tlsConfig.get()) != 0) {
            const auto tlsErrorMessage = selectedTlsShim->tls_error(impl_->tlsImpl.get());
            impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                "tls_configure -> error: %s",
                tlsErrorMessage
            );
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
                    std::unique_lock< decltype(self->impl_->mutex) > lock(self->impl_->mutex);
                    self->impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                        0, "_write_cb(%zu)", _buflen
                    );
                    if (self->impl_->open) {
                        const auto bufBytes = (const uint8_t*)_buf;
                        lock.unlock();
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
