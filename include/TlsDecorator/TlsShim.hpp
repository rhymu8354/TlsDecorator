#ifndef TLS_DECORATOR_TLS_SHIM_HPP
#define TLS_DECORATOR_TLS_SHIM_HPP

/**
 * @file TlsShim.hpp
 *
 * This module declares the TlsDecorator::TlsShim class, used
 * to place a shim between the TlsDecorator class and the actual TLS
 * library, in order to support redirecting calls to a mock layer for testing.
 *
 * © 2018 by Richard Walters
 */

#include <tls.h>

namespace TlsDecorator {

    /**
     * This is the base class for the shim to place between TlsDecorator
     * and the actual TLS library.  The base class forwards
     * all calls to the real TLS library.  During testing, the test framework
     * replaces the shim with a derived class used to test without using
     * a real TLS implementation.
     *
     * @note
     *     The methods of this interface match one-to-one with the functions
     *     from libtls which are actually needed by TlsDecorator.  Please look
     *     at the documentation for libtls for descriptions of any
     *     particular method.
     */
    class TlsShim {
    public:
        virtual const char *tls_error(struct tls *_ctx);
        virtual struct tls_config *tls_config_new(void);
        virtual int tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols);
        virtual void tls_config_insecure_noverifycert(struct tls_config *_config);
        virtual void tls_config_insecure_noverifyname(struct tls_config *_config);
        virtual int tls_config_set_ca_mem(struct tls_config *_config, const uint8_t *_ca,
            size_t _len);
        virtual int tls_configure(struct tls *_ctx, struct tls_config *_config);
        virtual void tls_config_free(struct tls_config *_config);
        virtual struct tls *tls_client(void);
        virtual int tls_connect_cbs(struct tls *_ctx, tls_read_cb _read_cb,
            tls_write_cb _write_cb, void *_cb_arg, const char *_servername);
        virtual ssize_t tls_read(struct tls *_ctx, void *_buf, size_t _buflen);
        virtual ssize_t tls_write(struct tls *_ctx, const void *_buf, size_t _buflen);
        virtual int tls_close(struct tls *_ctx);
        virtual void tls_free(struct tls *_ctx);
    };

    /**
     * This is available for users to change the shim used to connect
     * the TlsDecorator class with the TLS implementation.
     *
     * The default value is a global instance of a class which simply
     * forwards each method to the actual libtls implementation.
     */
    extern TlsShim* selectedTlsShim;

}

#endif /* TLS_DECORATOR_TLS_SHIM_HPP */
