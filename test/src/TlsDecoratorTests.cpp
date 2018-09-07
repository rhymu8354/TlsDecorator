/**
 * @file TlsDecoratorTests.cpp
 *
 * This module contains the unit tests of the TlsDecorator functions.
 *
 * © 2018 by Richard Walters
 */

#include <gtest/gtest.h>
#include <stddef.h>
#include <string>
#include <SystemAbstractions/DiagnosticsSender.hpp>
#include <SystemAbstractions/StringExtensions.hpp>
#include <TlsDecorator/TlsDecorator.hpp>
#include <TlsDecorator/TlsShim.hpp>
#include <vector>

namespace {

    /**
     * This is an alternative TlsShim which mocks the libtls
     * library completely.
     */
    struct MockTls
        : public TlsDecorator::TlsShim
    {
        // Properties

        bool tlsConnectCalled = false;

        // Methods

        // TlsDecorator::TlsShim

        virtual const char *tls_error(struct tls *_ctx) override {
            return nullptr;
        }

        virtual struct tls_config *tls_config_new(void) override {
            return nullptr;
        }

        virtual int tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols) override {
            return 0;
        }

        virtual void tls_config_insecure_noverifycert(struct tls_config *_config) override {
        }

        virtual void tls_config_insecure_noverifyname(struct tls_config *_config) override {
        }

        virtual int tls_configure(struct tls *_ctx, struct tls_config *_config) override {
            return 0;
        }

        virtual void tls_config_free(struct tls_config *_config) override {
        }

        virtual struct tls *tls_client(void) override {
            return nullptr;
        }

        virtual int tls_connect_cbs(struct tls *_ctx, tls_read_cb _read_cb,
            tls_write_cb _write_cb, void *_cb_arg, const char *_servername) override
        {
            tlsConnectCalled = true;
            return 0;
        }

        virtual ssize_t tls_read(struct tls *_ctx, void *_buf, size_t _buflen) override {
            return 0;
        }

        virtual ssize_t tls_write(struct tls *_ctx, const void *_buf, size_t _buflen) {
            return 0;
        }

        virtual int tls_close(struct tls *_ctx) {
            return 0;
        }

        virtual void tls_free(struct tls *_ctx) {
        }
    };

    /**
     * This is a substitute for a real connection, and used to test
     * the TLS decorator, which needs a connecion to decorate.
     */
    struct MockConnection
        : public SystemAbstractions::INetworkConnection
    {
        // Properties

        bool connectCalled = false;
        uint32_t peerAddressGiven = 0;
        uint16_t peerPortGiven = 0;

        // Methods

        // SystemAbstractions::INetworkConnection

        virtual SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnostics(
            SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
            size_t minLevel = 0
        ) override {
            return []{};
        }

        virtual bool Connect(uint32_t peerAddress, uint16_t peerPort) override {
            connectCalled = true;
            peerAddressGiven = peerAddress;
            peerPortGiven = peerPort;
            return true;
        }

        virtual bool Process(
            MessageReceivedDelegate messageReceivedDelegate,
            BrokenDelegate brokenDelegate
        ) override {
            return false;
        }

        virtual uint32_t GetPeerAddress() const override{
            return 0;
        }

        virtual uint16_t GetPeerPort() const override {
            return 0;
        }

        virtual bool IsConnected() const override {
            return false;
        }

        virtual uint32_t GetBoundAddress() const override {
            return 0;
        }

        virtual uint16_t GetBoundPort() const override {
            return 0;
        }

        virtual void SendMessage(const std::vector< uint8_t >& message) override {
        }

        virtual void Close(bool clean = false) override {
        }
    };

}

/**
 * This is the test fixture for these tests, providing common
 * setup and teardown for each test.
 */
struct TlsDecoratorTests
    : public ::testing::Test
{
    // Properties

    /**
     * This holds any state in the mock shim layer representing
     * the TLS library.
     */
    static MockTls mockTls;

    /**
     * This is used to simulate an actual network connection
     * which is wrapped by the TLS decorator.
     */
    MockConnection mockConnection;

    /**
     * This is the unit under test.
     */
    TlsDecorator::TlsDecorator decorator;

    /**
     * These are the diagnostic messages that have been
     * received from the unit under test.
     */
    std::vector< std::string > diagnosticMessages;

    /**
     * This is the delegate obtained when subscribing
     * to receive diagnostic messages from the unit under test.
     * It's called to terminate the subscription.
     */
    SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate diagnosticsUnsubscribeDelegate;

    // Methods

    // ::testing::Test

    virtual void SetUp() {
        TlsDecorator::selectedTlsShim = &mockTls;
        diagnosticsUnsubscribeDelegate = decorator.SubscribeToDiagnostics(
            [this](
                std::string senderName,
                size_t level,
                std::string message
            ){
                diagnosticMessages.push_back(
                    SystemAbstractions::sprintf(
                        "%s[%zu]: %s",
                        senderName.c_str(),
                        level,
                        message.c_str()
                    )
                );
            },
            0
        );
    }

    virtual void TearDown() {
        diagnosticsUnsubscribeDelegate();
    }
};
MockTls TlsDecoratorTests::mockTls;

TEST_F(TlsDecoratorTests, DiagnosticsSubscription) {
    std::vector< std::string > capturedDiagnosticMessages;
    decorator.SubscribeToDiagnostics(
        [&capturedDiagnosticMessages](
            std::string senderName,
            size_t level,
            std::string message
        ){
            capturedDiagnosticMessages.push_back(
                SystemAbstractions::sprintf(
                    "%s[%zu]: %s",
                    senderName.c_str(),
                    level,
                    message.c_str()
                )
            );
        }
    );
    decorator.Close();
    EXPECT_EQ(
        (std::vector< std::string >{
            "TlsDecorator[1]: Close was called"
        }),
        capturedDiagnosticMessages
    );
}

TEST_F(TlsDecoratorTests, DiagnosticsUnsubscription) {
    std::vector< std::string > capturedDiagnosticMessages;
    const auto unsubscribe = decorator.SubscribeToDiagnostics(
        [&capturedDiagnosticMessages](
            std::string senderName,
            size_t level,
            std::string message
        ){
            capturedDiagnosticMessages.push_back(
                SystemAbstractions::sprintf(
                    "%s[%zu]: %s",
                    senderName.c_str(),
                    level,
                    message.c_str()
                )
            );
        }
    );
    unsubscribe();
    decorator.Close();
    EXPECT_EQ(
        (std::vector< std::string >{
        }),
        capturedDiagnosticMessages
    );
}

TEST_F(TlsDecoratorTests, ConnectForwardedWithoutStartingTls) {
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    EXPECT_TRUE(mockConnection.connectCalled);
    EXPECT_EQ(42, mockConnection.peerAddressGiven);
    EXPECT_EQ(99, mockConnection.peerPortGiven);
    EXPECT_FALSE(mockTls.tlsConnectCalled);
}

TEST_F(TlsDecoratorTests, ProcessStartsTlsAndConnectionProcessing) {
}

TEST_F(TlsDecoratorTests, PeerAddressAndPortAreForwarded) {
}

TEST_F(TlsDecoratorTests, IsConnectedForwarded) {
}

TEST_F(TlsDecoratorTests, BoundAddressAndPortAreForwarded) {
}

TEST_F(TlsDecoratorTests, SendMessageQueuesDataWithTlsWrite) {
}

TEST_F(TlsDecoratorTests, SecureDataReceivedResultsInDecryptedDataDelivered) {
}

TEST_F(TlsDecoratorTests, RemoteConnectionBreakForwardedWhenNoSecureDataBuffered) {
}

TEST_F(TlsDecoratorTests, CleanCloseProcessesAllQueuedTlsWritesBeforeActuallyClosing) {
}

TEST_F(TlsDecoratorTests, UncleanCloseForwarded) {
}
