/**
 * @file TlsShim.cpp
 *
 * This module contains the implementation of the
 * TlsDecorator::TlsShim class.
 *
 * © 2018 by Richard Walters
 */

#include <tls.h>
#include <TlsDecorator/TlsShim.hpp>

namespace {

    /**
     * This is a singleton providing something for the global TLS shim
     * pointer to point to by default.
     */
    TlsDecorator::TlsShim tlsShimBase;

}

namespace TlsDecorator {

    const char *TlsShim::tls_error(struct tls *_ctx) {
        return ::tls_error(_ctx);
    }

    struct tls_config *TlsShim::tls_config_new(void) {
        return ::tls_config_new();
    }

    int TlsShim::tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols) {
        return ::tls_config_set_protocols(_config, _protocols);
    }

    void TlsShim::tls_config_insecure_noverifycert(struct tls_config *_config) {
        ::tls_config_insecure_noverifycert(_config);
    }

    void TlsShim::tls_config_insecure_noverifyname(struct tls_config *_config) {
        ::tls_config_insecure_noverifyname(_config);
    }

    int TlsShim::tls_config_set_ca_mem(struct tls_config *_config, const uint8_t *_ca,
        size_t _len)
    {
        return ::tls_config_set_ca_mem(_config, _ca, _len);
    }

    int TlsShim::tls_configure(struct tls *_ctx, struct tls_config *_config) {
        return ::tls_configure(_ctx, _config);
    }

    void TlsShim::tls_config_free(struct tls_config *_config) {
        ::tls_config_free(_config);
    }

    struct tls *TlsShim::tls_client(void) {
        return ::tls_client();
    }

    int TlsShim::tls_connect_cbs(struct tls *_ctx, tls_read_cb _read_cb,
        tls_write_cb _write_cb, void *_cb_arg, const char *_servername)
    {
        return ::tls_connect_cbs(_ctx, _read_cb, _write_cb, _cb_arg, _servername);
    }

    ssize_t TlsShim::tls_read(struct tls *_ctx, void *_buf, size_t _buflen) {
        return ::tls_read(_ctx, _buf, _buflen);
    }

    ssize_t TlsShim::tls_write(struct tls *_ctx, const void *_buf, size_t _buflen) {
        return ::tls_write(_ctx, _buf, _buflen);
    }

    int TlsShim::tls_close(struct tls *_ctx) {
        return ::tls_close(_ctx);
    }

    void TlsShim::tls_free(struct tls *_ctx) {
        ::tls_free(_ctx);
    }

    /**
     * Provide storage for the TLS shim pointer.
     */
    TlsShim* selectedTlsShim = &tlsShimBase;

}
