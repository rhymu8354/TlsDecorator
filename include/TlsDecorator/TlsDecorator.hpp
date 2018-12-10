#ifndef TLS_DECORATOR_TLS_DECORATOR_HPP
#define TLS_DECORATOR_TLS_DECORATOR_HPP

/**
 * @file TlsDecorator.hpp
 *
 * This module declares the TlsDecorator::TlsDecorator class.
 *
 * © 2018 by Richard Walters
 */

#include <functional>
#include <memory>
#include <stdint.h>
#include <string>
#include <SystemAbstractions/INetworkConnection.hpp>
#include <vector>

namespace TlsDecorator {

    /**
     * This is a decorator for SystemAbstractions::INetworkConnection which
     * passes all data through a TLS layer.
     */
    class TlsDecorator
        : public SystemAbstractions::INetworkConnection
    {
        // Types
    public:
        /**
         * This is the type of function used to publish information
         * when the TLS handshake for the connection is complete.
         *
         * @param[in] certificate
         *     This is the PEM-encoded certificate, if any, provided by
         *     the connection peer.
         */
        typedef std::function<
            void(const std::string& certificate)
        > HandshakeCompleteDelegate;

        // Lifecycle management
    public:
        ~TlsDecorator() noexcept;
        TlsDecorator(const TlsDecorator&) = delete;
        TlsDecorator(TlsDecorator&&) noexcept = delete;
        TlsDecorator& operator=(const TlsDecorator&) = delete;
        TlsDecorator& operator=(TlsDecorator&&) noexcept = delete;

        // Public Methods
    public:
        /**
         * This is the default constructor.
         */
        TlsDecorator();

        /**
         * This method sets up a function to be called when the TLS
         * handshake is complete.
         *
         * @param[in] handshakeCompleteDelegate
         *     This is the function to call when the TLS handshake
         *     is complete.
         */
        void SetHandshakeCompleteDelegate(HandshakeCompleteDelegate handshakeCompleteDelegate);

        /**
         * This method sets up the decorator to insert a TLS layer
         * and configure it for client mode (connecting to a server).
         *
         * @param[in] lowerLayer
         *     This is the lower-level connection to decorate.
         *
         * @param[in] caCerts
         *     This is the concatenation of the root Certificate Authority
         *     (CA) certificates to trust, in PEM format.
         *
         * @param[in] serverName
         *     This is the name of the server with which to connect
         *     as a TLS client.
         */
        void ConfigureAsClient(
            std::shared_ptr< SystemAbstractions::INetworkConnection > lowerLayer,
            const std::string& caCerts,
            const std::string& serverName
        );

        /**
         * This method sets up the decorator to insert a TLS layer
         * and configure it for server mode (receiving a connection
         * from a client).
         *
         * @param[in] lowerLayer
         *     This is the lower-level connection to decorate.
         *
         * @param[in] cert
         *     This is the server's certificate, in PEM format.
         *
         * @param[in] key
         *     This is the server's private key, in PEM format.
         *
         * @param[in] password
         *     This is the password for the server's private key.
         */
        void ConfigureAsServer(
            std::shared_ptr< SystemAbstractions::INetworkConnection > lowerLayer,
            const std::string& cert,
            const std::string& key,
            const std::string& password
        );

        // SystemAbstractions::INetworkConnection
    public:
        virtual SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnostics(
            SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
            size_t minLevel = 0
        ) override;
        virtual bool Connect(uint32_t peerAddress, uint16_t peerPort) override;
        virtual bool Process(
            MessageReceivedDelegate messageReceivedDelegate,
            BrokenDelegate brokenDelegate
        ) override;
        virtual uint32_t GetPeerAddress() const override;
        virtual uint16_t GetPeerPort() const override;
        virtual bool IsConnected() const override;
        virtual uint32_t GetBoundAddress() const override;
        virtual uint16_t GetBoundPort() const override;
        virtual void SendMessage(const std::vector< uint8_t >& message) override;
        virtual void Close(bool clean = false) override;

        // Private Properties
    private:
        /**
         * This is the type of structure that contains the private
         * properties of the instance.  It is defined in the implementation
         * and declared here to ensure that it is scoped inside the class.
         */
        struct Impl;

        /**
         * This contains the private properties of the instance.
         */
        std::shared_ptr< Impl > impl_;
    };

}

#endif /* TLS_DECORATOR_TLS_DECORATOR_HPP */
