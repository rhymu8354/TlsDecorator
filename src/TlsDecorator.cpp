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
#include <string.h>
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
         * This is an optional function to call when the initial TLS
         * handshake is complete.
         */
        HandshakeCompleteDelegate handshakeCompleteDelegate;

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
         * This implements the TLS layer server context.
         */
        std::unique_ptr< tls, std::function< void(tls*) > > tlsServerImpl;

        /**
         * This implements the TLS layer connection context.
         */
        std::unique_ptr< tls, std::function< void(tls*) > > tlsConnectionImpl;

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
         * This flag keeps track of whether or not the TLS handshake
         * has been completed.
         */
        bool handshakeComplete = false;

        /**
         * This flag keeps track of whether or not the lower-level client
         * connection is still open.
         */
        bool open = true;

        /**
         * This flag keeps track of whether or not the upper-level user
         * has been notified of the connection having been broken.
         */
        bool brokenPublished = false;

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
            if (!open) {
                return;
            }
            open = false;
            wakeCondition.notify_all();
            if (receiveBufferSecure.empty()) {
                diagnosticsSender.SendDiagnosticInformationString(
                    0, "Remote closed, no more data received left to process"
                );
                brokenPublished = true;
                if (brokenDelegate != nullptr) {
                    lock.unlock();
                    brokenDelegate(false);
                }
            } else {
                diagnosticsSender.SendDiagnosticInformationString(
                    0, "Remote closed, received data left to be processed"
                );
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
                if (!handshakeComplete) {
                    diagnosticsSender.SendDiagnosticInformationString(
                        0, "tls_handshake"
                    );
                    lock.unlock();
                    const auto handshakeResult = selectedTlsShim->tls_handshake(tlsConnectionImpl.get());
                    lock.lock();
                    if (handshakeResult == 0) {
                        diagnosticsSender.SendDiagnosticInformationString(
                            0, "tls_handshake -> complete"
                        );
                        handshakeComplete = true;
                        if (handshakeCompleteDelegate != nullptr) {
                            if (selectedTlsShim->tls_peer_cert_provided(tlsConnectionImpl.get())) {
                                size_t len;
                                const auto cert = (const char*)selectedTlsShim->tls_peer_cert_chain_pem(tlsConnectionImpl.get(), &len);
                                handshakeCompleteDelegate(std::string(cert, len));
                            } else {
                                handshakeCompleteDelegate("");
                            }
                        }
                    } else if (handshakeResult == TLS_WANT_POLLIN) {
                        diagnosticsSender.SendDiagnosticInformationString(
                            0, "tls_handshake -> TLS_WANT_POLLIN"
                        );
                    } else {
                        const auto tlsErrorMessage = selectedTlsShim->tls_error(tlsConnectionImpl.get());
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                            "tls_handshake -> error: %s",
                            tlsErrorMessage
                        );
                        break;
                    }
                }
                if (
                    handshakeComplete
                    && !sendBuffer.empty()
                    && canWrite
                    && open
                ) {
                    diagnosticsSender.SendDiagnosticInformationFormatted(
                        0, "tls_write(%zu)", sendBuffer.size()
                    );
                    buffer.assign(sendBuffer.begin(), sendBuffer.end());
                    lock.unlock();
                    const auto amount = selectedTlsShim->tls_write(
                        tlsConnectionImpl.get(),
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
                        const auto tlsErrorMessage = selectedTlsShim->tls_error(tlsConnectionImpl.get());
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                            "tls_write(%zu) -> error: %s",
                            sendBuffer.size(),
                            tlsErrorMessage
                        );
                        break;
                    } else {
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            0, "tls_write(%zu) -> %zu", sendBuffer.size(), (size_t)amount
                        );
                        if ((size_t)amount == sendBuffer.size()) {
                            sendBuffer.clear();
                            if (upperLayerClosed) {
                                diagnosticsSender.SendDiagnosticInformationString(
                                    0, "Last data to write is written; closing lower layer gracefully"
                                );
                                lock.unlock();
                                lowerLayer->Close(true);
                                lock.lock();
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
                    handshakeComplete
                    && (
                        !receiveBufferSecure.empty()
                        || tryRead
                    )
                ) {
                    tryRead = true;
                    buffer.resize(DECRYPTED_BUFFER_SIZE);
                    diagnosticsSender.SendDiagnosticInformationString(
                        0, "tls_read"
                    );
                    lock.unlock();
                    const auto amount = selectedTlsShim->tls_read(
                        tlsConnectionImpl.get(),
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
                        const auto tlsErrorMessage = selectedTlsShim->tls_error(tlsConnectionImpl.get());
                        diagnosticsSender.SendDiagnosticInformationFormatted(
                            SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                            "tls_read -> error: %s",
                            tlsErrorMessage
                        );
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
                    } else {
                        tryRead = false;
                    }
                }
                if (
                    receiveBufferSecure.empty()
                    && !open
                ) {
                    diagnosticsSender.SendDiagnosticInformationString(
                        0, "Last received data processed before remote end closed"
                    );
                    break;
                }
                wakeCondition.wait(
                    lock,
                    [this]{
                        return (
                            stopWorker
                            || !receiveBufferSecure.empty()
                            || (
                                handshakeComplete
                                && !sendBuffer.empty()
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
            } else {
                diagnosticsSender.SendDiagnosticInformationString(
                    0, "Closed abruptly"
                );
            }
            if (!brokenPublished) {
                brokenPublished = true;
                if (brokenDelegate != nullptr) {
                    lock.unlock();
                    brokenDelegate(false);
                    lock.lock();
                }
            }
            lock.unlock();
            lowerLayer->Close(false);
        }
    };

    TlsDecorator::~TlsDecorator() noexcept {
        Close(false);
        if (impl_->worker.joinable()) {
            impl_->worker.join();
        }
    }

    TlsDecorator::TlsDecorator()
        : impl_(new Impl())
    {
    }

    void TlsDecorator::SetHandshakeCompleteDelegate(HandshakeCompleteDelegate handshakeCompleteDelegate) {
        impl_->handshakeCompleteDelegate = handshakeCompleteDelegate;
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
        impl_->lowerLayer->SubscribeToDiagnostics(impl_->diagnosticsSender.Chain());
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
        impl_->lowerLayer->SubscribeToDiagnostics(impl_->diagnosticsSender.Chain());
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
        if (impl_->mode != Impl::Mode::Client) {
            impl_->diagnosticsSender.SendDiagnosticInformationString(
                SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                "Connect called without first configuring as client"
            );
            return false;
        }
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

        selectedTlsShim->tls_config_set_protocols(impl_->tlsConfig.get(), TLS_PROTOCOLS_DEFAULT);
        (void)selectedTlsShim->tls_config_set_ca_mem(
            impl_->tlsConfig.get(),
            impl_->caCerts.data(),
            impl_->caCerts.size()
        );

        const auto tlsImplDeleter = [](tls* p) {
            selectedTlsShim->tls_close(p);
            selectedTlsShim->tls_free(p);
        };
        if (impl_->mode == Impl::Mode::Client) {
            impl_->tlsConnectionImpl = decltype(impl_->tlsConnectionImpl)(
                selectedTlsShim->tls_client(),
                tlsImplDeleter
            );
            if (selectedTlsShim->tls_configure(impl_->tlsConnectionImpl.get(), impl_->tlsConfig.get()) != 0) {
                const auto tlsErrorMessage = selectedTlsShim->tls_error(impl_->tlsConnectionImpl.get());
                impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                    SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                    "tls_configure -> error: %s",
                    tlsErrorMessage
                );
                return false;
            }
        } else {
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
                [](BIO* p){
                    selectedTlsShim->BIO_free_all(p);
                }
            );
            std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > key(
                selectedTlsShim->PEM_read_bio_PrivateKey(
                    encryptedKeyInput.get(),
                    NULL,
                    NULL,
                    (void*)impl_->password.c_str()
                ),
                [](EVP_PKEY* p){
                    selectedTlsShim->EVP_PKEY_free(p);
                }
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
                [](BIO* p){
                    selectedTlsShim->BIO_free_all(p);
                }
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
            impl_->tlsServerImpl = decltype(impl_->tlsServerImpl)(
                selectedTlsShim->tls_server(),
                tlsImplDeleter
            );
            if (selectedTlsShim->tls_configure(impl_->tlsServerImpl.get(), impl_->tlsConfig.get()) != 0) {
                const auto tlsErrorMessage = selectedTlsShim->tls_error(impl_->tlsServerImpl.get());
                impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                    SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                    "tls_configure -> error: %s",
                    tlsErrorMessage
                );
                return false;
            }
        }
        tls_read_cb _read_cb = [](struct tls *_ctx, void *_buf, size_t _buflen, void *_cb_arg){
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
        };
        tls_write_cb _write_cb = [](struct tls *_ctx, const void *_buf, size_t _buflen, void *_cb_arg){
            const auto self = (TlsDecorator*)_cb_arg;
            std::unique_lock< decltype(self->impl_->mutex) > lock(self->impl_->mutex);
            self->impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                0, "_write_cb(%zu) while %s", _buflen, (self->impl_->open ? "open" : "closed")
            );
            if (self->impl_->open) {
                const auto bufBytes = (const uint8_t*)_buf;
                lock.unlock();
                self->impl_->lowerLayer->SendMessage(
                    std::vector< uint8_t >(bufBytes, bufBytes + _buflen)
                );
            }
            return (ssize_t)_buflen;
        };
        if (impl_->mode == Impl::Mode::Client) {
            if (
                selectedTlsShim->tls_connect_cbs(
                    impl_->tlsConnectionImpl.get(),
                    _read_cb,
                    _write_cb,
                    this,
                    impl_->serverName.c_str()
                ) != 0
            ) {
                const auto tlsErrorMessage = selectedTlsShim->tls_error(impl_->tlsConnectionImpl.get());
                impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                    SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                    "tls_connect_cbs -> error: %s",
                    tlsErrorMessage
                );
                return false;
            }
        } else {
            tls* clientContext;
            if (
                selectedTlsShim->tls_accept_cbs(
                    impl_->tlsServerImpl.get(),
                    &clientContext,
                    _read_cb,
                    _write_cb,
                    this
                ) != 0
            ) {
                const auto tlsErrorMessage = selectedTlsShim->tls_error(impl_->tlsServerImpl.get());
                impl_->diagnosticsSender.SendDiagnosticInformationFormatted(
                    SystemAbstractions::DiagnosticsSender::Levels::ERROR,
                    "tls_accept_cbs -> error: %s",
                    tlsErrorMessage
                );
                return false;
            }
            impl_->tlsConnectionImpl = decltype(impl_->tlsConnectionImpl)(
                clientContext,
                tlsImplDeleter
            );
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
        if (impl_->lowerLayer == nullptr) {
            return 0;
        }
        return impl_->lowerLayer->GetPeerAddress();
    }

    uint16_t TlsDecorator::GetPeerPort() const {
        if (impl_->lowerLayer == nullptr) {
            return 0;
        }
        return impl_->lowerLayer->GetPeerPort();
    }

    bool TlsDecorator::IsConnected() const {
        if (impl_->lowerLayer == nullptr) {
            return false;
        }
        return impl_->lowerLayer->IsConnected();
    }

    uint32_t TlsDecorator::GetBoundAddress() const {
        if (impl_->lowerLayer == nullptr) {
            return 0;
        }
        return impl_->lowerLayer->GetBoundAddress();
    }

    uint16_t TlsDecorator::GetBoundPort() const {
        if (impl_->lowerLayer == nullptr) {
            return 0;
        }
        return impl_->lowerLayer->GetBoundPort();
    }

    void TlsDecorator::SendMessage(const std::vector< uint8_t >& message) {
        std::unique_lock< decltype(impl_->mutex) > lock(impl_->mutex);
        if (
            impl_->upperLayerClosed
            || (
                impl_->stopWorker
                && impl_->worker.joinable()
            )
        ) {
            impl_->diagnosticsSender.SendDiagnosticInformationString(
                SystemAbstractions::DiagnosticsSender::Levels::WARNING,
                "send, but already closing"
            );
            return;
        }
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
            if (impl_->lowerLayer != nullptr) {
                impl_->lowerLayer->Close(clean);
            }
            return;
        }
        if (
            clean
            && !impl_->upperLayerClosed
        ) {
            impl_->upperLayerClosed = true;
            if (!impl_->sendBuffer.empty()) {
                impl_->diagnosticsSender.SendDiagnosticInformationString(
                    0, "Closing gracefully"
                );
                return;
            }
        }
        impl_->stopWorker = true;
        impl_->wakeCondition.notify_all();
    }

}
