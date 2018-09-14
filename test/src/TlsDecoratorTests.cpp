/**
 * @file TlsDecoratorTests.cpp
 *
 * This module contains the unit tests of the TlsDecorator functions.
 *
 * © 2018 by Richard Walters
 */

#include <condition_variable>
#include <gtest/gtest.h>
#include <mutex>
#include <stddef.h>
#include <stdint.h>
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
        bool tlsConfigProtocolSetCalled = false;
        uint32_t tlsConfigProtocolSetProtocols = 0;
        bool tlsConfigureCalled = false;
        std::string caCerts;
        bool tlsReadCalled = false;
        bool tlsWriteCalled = false;
        bool stallTlsWrite = false;
        tls_read_cb tlsReadCb = NULL;
        tls_write_cb tlsWriteCb = NULL;
        void* tlsCbArg = NULL;
        std::vector< uint8_t > tlsWriteDecryptedBuf;
        std::vector< uint8_t > tlsWriteEncryptedBuf;
        std::vector< uint8_t > tlsReadEncryptedBuf;
        std::vector< uint8_t > tlsReadDecryptedBuf;
        std::condition_variable wakeCondition;
        std::mutex mutex;

        // Methods

        /**
         * This method waits on the mock's wait condition until
         * the given predicate evaluates to true.
         *
         * @note
         *     Ensure that the predicate used is associated with
         *     the mock's wait condition.  Otherwise, the method
         *     may wait the full timeout period unnecessarily.
         *
         * @param[in] predicate
         *     This is the function to call to determine whether
         *     or not the condition we're waiting for is true.
         *
         * @param[in] timeout
         *     This is the maximum amount of time to wait.
         *
         * @return
         *     An indication of whether or not the given condition
         *     became true before a reasonable timeout period is returned.
         */
        bool Await(
            std::function< bool() > predicate,
            std::chrono::milliseconds timeout = std::chrono::milliseconds(1000)
        ) {
            std::unique_lock< decltype(mutex) > lock(mutex);
            return wakeCondition.wait_for(
                lock,
                timeout,
                predicate
            );
        }

        // TlsDecorator::TlsShim

        virtual const char *tls_error(struct tls *_ctx) override {
            return nullptr;
        }

        virtual struct tls_config *tls_config_new(void) override {
            return nullptr;
        }

        virtual int tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols) override {
            tlsConfigProtocolSetCalled = true;
            tlsConfigProtocolSetProtocols = _protocols;
            return 0;
        }

        virtual void tls_config_insecure_noverifycert(struct tls_config *_config) override {
        }

        virtual void tls_config_insecure_noverifyname(struct tls_config *_config) override {
        }

        virtual int tls_config_set_ca_mem(struct tls_config *_config, const uint8_t *_ca,
            size_t _len) override
        {
            caCerts = std::string(
                (const char*)_ca,
                _len
            );
            return 0;
        }

        virtual int tls_configure(struct tls *_ctx, struct tls_config *_config) override {
            tlsConfigureCalled = true;
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
            tlsReadCb = _read_cb;
            tlsWriteCb = _write_cb;
            tlsCbArg = _cb_arg;
            return 0;
        }

        virtual ssize_t tls_read(struct tls *_ctx, void *_buf, size_t _buflen) override {
            tlsReadCalled = true;
            if (tlsReadEncryptedBuf.empty()) {
                tlsReadEncryptedBuf.resize(65536);
                const auto encryptedAmount = tlsReadCb(_ctx, tlsReadEncryptedBuf.data(), tlsReadEncryptedBuf.size(), tlsCbArg);
                std::lock_guard< decltype(mutex) > lock(mutex);
                if (encryptedAmount >= 0) {
                    tlsReadEncryptedBuf.resize((size_t)encryptedAmount);
                } else {
                    tlsReadEncryptedBuf.clear();
                }
                wakeCondition.notify_all();
            }
            const auto decryptedAmount = std::min(tlsReadDecryptedBuf.size(), _buflen);
            if (decryptedAmount == 0) {
                return TLS_WANT_POLLIN;
            } else {
                (void)memcpy(_buf, tlsReadDecryptedBuf.data(), decryptedAmount);
                if (decryptedAmount == tlsReadDecryptedBuf.size()) {
                    tlsReadDecryptedBuf.clear();
                } else {
                    (void)tlsReadDecryptedBuf.erase(
                        tlsReadDecryptedBuf.begin(),
                        tlsReadDecryptedBuf.begin() + decryptedAmount
                    );
                }
                return decryptedAmount;
            }
        }

        virtual ssize_t tls_write(struct tls *_ctx, const void *_buf, size_t _buflen) override {
            std::lock_guard< decltype(mutex) > lock(mutex);
            tlsWriteCalled = true;
            if (stallTlsWrite) {
                return TLS_WANT_POLLIN;
            }
            const auto bufAsBytes = (const uint8_t*)_buf;
            tlsWriteDecryptedBuf.assign(bufAsBytes, bufAsBytes + _buflen);
            const auto encryptedAmount = tlsWriteCb(_ctx, tlsWriteEncryptedBuf.data(), tlsWriteEncryptedBuf.size(), tlsCbArg);
            if (encryptedAmount == tlsWriteEncryptedBuf.size()) {
                tlsWriteEncryptedBuf.clear();
            } else {
                (void)tlsWriteEncryptedBuf.erase(
                    tlsWriteEncryptedBuf.begin(),
                    tlsWriteEncryptedBuf.begin() + encryptedAmount
                );
            }
            wakeCondition.notify_all();
            return _buflen;
        }

        virtual int tls_close(struct tls *_ctx) override {
            return 0;
        }

        virtual void tls_free(struct tls *_ctx) override {
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
        bool processCalled = false;
        MessageReceivedDelegate upperLayerMessageReceivedDelegate;
        BrokenDelegate upperLayerBrokenDelegate;
        mutable bool isConnectedCalled = false;
        bool isConnected = false;
        bool closeCalled = false;
        std::condition_variable wakeCondition;
        std::mutex mutex;

        // Methods

        /**
         * This method waits on the mock's wait condition until
         * the given predicate evaluates to true.
         *
         * @note
         *     Ensure that the predicate used is associated with
         *     the mock's wait condition.  Otherwise, the method
         *     may wait the full timeout period unnecessarily.
         *
         * @param[in] predicate
         *     This is the function to call to determine whether
         *     or not the condition we're waiting for is true.
         *
         * @return
         *     An indication of whether or not the given condition
         *     became true before a reasonable timeout period is returned.
         */
        bool Await(std::function< bool() > predicate) {
            std::unique_lock< decltype(mutex) > lock(mutex);
            return wakeCondition.wait_for(
                lock,
                std::chrono::milliseconds(100),
                predicate
            );
        }

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
            isConnected = true;
            return true;
        }

        virtual bool Process(
            MessageReceivedDelegate messageReceivedDelegate,
            BrokenDelegate brokenDelegate
        ) override {
            upperLayerMessageReceivedDelegate = messageReceivedDelegate;
            upperLayerBrokenDelegate = brokenDelegate;
            processCalled = true;
            return true;
        }

        virtual uint32_t GetPeerAddress() const override{
            return peerAddressGiven;
        }

        virtual uint16_t GetPeerPort() const override {
            return peerPortGiven;
        }

        virtual bool IsConnected() const override {
            isConnectedCalled = true;
            return isConnected;
        }

        virtual uint32_t GetBoundAddress() const override {
            return 1234;
        }

        virtual uint16_t GetBoundPort() const override {
            return 4321;
        }

        virtual void SendMessage(const std::vector< uint8_t >& message) override {
        }

        virtual void Close(bool clean = false) override {
            std::lock_guard< decltype(mutex) > lock(mutex);
            closeCalled = true;
            wakeCondition.notify_all();
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
    MockTls mockTls;

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
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    (void)decorator.Process(
        [](const std::vector< uint8_t >& message){},
        [](bool graceful){}
    );
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    decorator.Close();
    EXPECT_EQ(
        (std::vector< std::string >{
            "TlsDecorator[0]: tls_read",
            "TlsDecorator[0]: _read_cb(65536) -> TLS_WANT_POLLIN",
            "TlsDecorator[0]: tls_read -> TLS_WANT_POLLIN",
            "TlsDecorator[0]: Closed gracefully"
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
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    EXPECT_TRUE(mockConnection.connectCalled);
    EXPECT_EQ(42, mockConnection.peerAddressGiven);
    EXPECT_EQ(99, mockConnection.peerPortGiven);
    EXPECT_FALSE(mockTls.tlsConnectCalled);
}

TEST_F(TlsDecoratorTests, ProcessStartsTlsAndConnectionProcessing) {
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    EXPECT_TRUE(
        decorator.Process(
            [](const std::vector< uint8_t >& message){},
            [](bool graceful){}
        )
    );
    EXPECT_TRUE(mockTls.tlsConfigProtocolSetCalled);
    EXPECT_EQ(TLS_PROTOCOLS_DEFAULT, mockTls.tlsConfigProtocolSetProtocols);
    EXPECT_TRUE(mockTls.tlsConfigureCalled);
    EXPECT_TRUE(mockTls.tlsConnectCalled);
    EXPECT_TRUE(mockConnection.processCalled);
}

TEST_F(TlsDecoratorTests, PeerAddressAndPortAreForwarded) {
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    EXPECT_EQ(mockConnection.peerAddressGiven, decorator.GetPeerAddress());
    EXPECT_EQ(mockConnection.peerPortGiven, decorator.GetPeerPort());
}

TEST_F(TlsDecoratorTests, IsConnectedForwarded) {
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    mockConnection.isConnectedCalled = false;
    EXPECT_FALSE(decorator.IsConnected());
    EXPECT_TRUE(mockConnection.isConnectedCalled);
    mockConnection.isConnectedCalled = false;
    (void)decorator.Connect(42, 99);
    mockConnection.isConnectedCalled = false;
    EXPECT_TRUE(decorator.IsConnected());
    EXPECT_TRUE(mockConnection.isConnectedCalled);
    mockConnection.isConnectedCalled = false;
}

TEST_F(TlsDecoratorTests, BoundAddressAndPortAreForwarded) {
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    EXPECT_EQ(1234, decorator.GetBoundAddress());
    EXPECT_EQ(4321, decorator.GetBoundPort());
}

TEST_F(TlsDecoratorTests, SendMessageQueuesDataWithTlsWrite) {
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    const std::string encryptedDataAsString("Hello, World!");
    const std::vector< uint8_t > encryptedDataAsVector(encryptedDataAsString.begin(), encryptedDataAsString.end());
    const std::string decrpytedDataAsString("PogChamp");
    const std::vector< uint8_t > decrpytedDataAsVector(decrpytedDataAsString.begin(), decrpytedDataAsString.end());
    mockTls.tlsWriteEncryptedBuf = encryptedDataAsVector;
    decorator.SendMessage(decrpytedDataAsVector);
    (void)decorator.Process(
        [](const std::vector< uint8_t >& message){},
        [](bool graceful){}
    );
    EXPECT_TRUE(
        mockTls.Await(
            [this]{
                return mockTls.tlsWriteCalled;
            }
        )
    );
    decorator.Close(false);
    EXPECT_EQ(decrpytedDataAsVector, mockTls.tlsWriteDecryptedBuf);
    EXPECT_EQ(
        (std::vector< std::string >{
            "TlsDecorator[0]: send(8)",
            "TlsDecorator[0]: tls_write(8)",
            "TlsDecorator[0]: _write_cb(13)",
            "TlsDecorator[0]: tls_write(8) -> 8",
            "TlsDecorator[0]: tls_read",
            "TlsDecorator[0]: _read_cb(65536) -> TLS_WANT_POLLIN",
            "TlsDecorator[0]: tls_read -> TLS_WANT_POLLIN",
            "TlsDecorator[0]: Closed gracefully",
        }),
        diagnosticMessages
    );
}

TEST_F(TlsDecoratorTests, SecureDataReceivedResultsInDecryptedDataDelivered) {
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    std::vector< uint8_t > actualDecryptedData;
    std::condition_variable wakeCondition;
    std::mutex mutex;
    (void)decorator.Process(
        [
            &actualDecryptedData,
            &wakeCondition,
            &mutex
        ](const std::vector< uint8_t >& message){
            std::lock_guard< decltype(mutex) > lock(mutex);
            actualDecryptedData = message;
            wakeCondition.notify_all();
        },
        [](bool graceful){}
    );
    EXPECT_TRUE(
        mockTls.Await(
            [this]{
                return mockTls.tlsReadCalled;
            }
        )
    );
    const std::string encryptedDataAsString("Hello, World!");
    const std::vector< uint8_t > encryptedDataAsVector(encryptedDataAsString.begin(), encryptedDataAsString.end());
    const std::string decrpytedDataAsString("PogChamp");
    const std::vector< uint8_t > decrpytedDataAsVector(decrpytedDataAsString.begin(), decrpytedDataAsString.end());
    mockTls.tlsReadDecryptedBuf = decrpytedDataAsVector;
    ASSERT_FALSE(mockConnection.upperLayerMessageReceivedDelegate == nullptr);
    mockConnection.upperLayerMessageReceivedDelegate(encryptedDataAsVector);
    {
        std::unique_lock< decltype(mutex) > lock(mutex);
        EXPECT_TRUE(
            wakeCondition.wait_for(
                lock,
                std::chrono::milliseconds(1000),
                [&actualDecryptedData]{
                    return !actualDecryptedData.empty();
                }
            )
        );
    }
    EXPECT_EQ(encryptedDataAsVector, mockTls.tlsReadEncryptedBuf);
    EXPECT_EQ(decrpytedDataAsVector, actualDecryptedData);
    decorator.Close(false);
    EXPECT_EQ(
        (std::vector< std::string >{
            "TlsDecorator[0]: tls_read",
            "TlsDecorator[0]: _read_cb(65536) -> TLS_WANT_POLLIN",
            "TlsDecorator[0]: tls_read -> TLS_WANT_POLLIN",
            "TlsDecorator[0]: receive(13)",
            "TlsDecorator[0]: tls_read",
            "TlsDecorator[0]: _read_cb(65536) -> 13 (of 13)",
            "TlsDecorator[0]: tls_read -> 8",
            "TlsDecorator[0]: Closed gracefully",
        }),
        diagnosticMessages
    );
}

TEST_F(TlsDecoratorTests, RemoteConnectionBreakForwardedWhenNoSecureDataBuffered) {
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    std::condition_variable wakeCondition;
    std::mutex mutex;
    bool broken = false;
    std::vector< uint8_t > actualDecryptedData;
    (void)decorator.Process(
        [](const std::vector< uint8_t >& message){},
        [
            &broken,
            &mutex,
            &wakeCondition
        ](bool graceful){
            std::lock_guard< decltype(mutex) > lock(mutex);
            broken = true;
            wakeCondition.notify_all();
        }
    );
    EXPECT_TRUE(
        mockTls.Await(
            [this]{
                return mockTls.tlsReadCalled;
            }
        )
    );
    ASSERT_FALSE(mockConnection.upperLayerBrokenDelegate == nullptr);
    mockConnection.upperLayerBrokenDelegate(false);
    {
        std::unique_lock< decltype(mutex) > lock(mutex);
        EXPECT_TRUE(
            wakeCondition.wait_for(
                lock,
                std::chrono::milliseconds(100),
                [&broken]{ return broken; }
            )
        );
    }
    EXPECT_EQ(
        (std::vector< std::string >{
            "TlsDecorator[0]: tls_read",
            "TlsDecorator[0]: _read_cb(65536) -> TLS_WANT_POLLIN",
            "TlsDecorator[0]: tls_read -> TLS_WANT_POLLIN",
            "TlsDecorator[0]: Remote closed",
        }),
        diagnosticMessages
    );
}

TEST_F(TlsDecoratorTests, CleanCloseProcessesAllQueuedTlsWritesBeforeActuallyClosing) {
    // Setup
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    (void)decorator.Process(
        [](const std::vector< uint8_t >& message){},
        [](bool graceful){}
    );

    // Rig the mock so that tls_write doesn't write anything, but
    // kind of stalls the decorator for a while.
    mockTls.stallTlsWrite = true;

    // Queue up data to write to TLS, and call Close, but check
    // to make sure the connection isn't actually closed yet.
    const std::string messageAsString("Hello, World!");
    const std::vector< uint8_t > messageAsVector(messageAsString.begin(), messageAsString.end());
    decorator.SendMessage(messageAsVector);
    decorator.Close(true);
    EXPECT_FALSE(mockConnection.closeCalled);

    // Lift the stalling of TLS write.
    {
        std::lock_guard< decltype(mockTls.mutex) > lock(mockTls.mutex);
        mockTls.stallTlsWrite = false;
        mockTls.tlsWriteCalled = false;
    }

    // We have to ask TLS to read something, in order for
    // the write part of the worker thread to try writing again.
    const std::string encryptedDataAsString("Hello, World!");
    const std::vector< uint8_t > encryptedDataAsVector(encryptedDataAsString.begin(), encryptedDataAsString.end());
    ASSERT_FALSE(mockConnection.upperLayerMessageReceivedDelegate == nullptr);
    mockConnection.upperLayerMessageReceivedDelegate(encryptedDataAsVector);

    // Wait for the TLS to actually complete the write, and verify
    // that this time close is called on the underlying connection.
    (void)mockTls.Await(
        [this]{
            return mockTls.tlsWriteCalled;
        }
    );
    EXPECT_TRUE(
        mockConnection.Await(
            [this]{ return mockConnection.closeCalled; }
        )
    );
}

TEST_F(TlsDecoratorTests, ConfigureCACertificates) {
    // Pass in something for CA certificates.
    decorator.Configure(
        std::shared_ptr< MockConnection >(
            &mockConnection,
            [](MockConnection*){}
        ),
        "Pretend there are certificates here, ok?",
        "Pepe"
    );
    (void)decorator.Connect(42, 99);
    (void)decorator.Process(
        [](const std::vector< uint8_t >& message){},
        [](bool graceful){}
    );

    // Verify the CA certificates were configured.
    EXPECT_EQ(
        "Pretend there are certificates here, ok?",
        mockTls.caCerts
    );
}
