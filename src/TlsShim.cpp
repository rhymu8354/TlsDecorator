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

    BIO *TlsShim::BIO_new(const BIO_METHOD *type) {
        return ::BIO_new(type);
    }

    BIO *TlsShim::BIO_new_mem_buf(const void *buf, int len) {
        return ::BIO_new_mem_buf(buf, len);
    }

    long TlsShim::BIO_ctrl(BIO *bp, int cmd, long larg, void *parg) {
        return ::BIO_ctrl(bp, cmd, larg, parg);
    }

    void TlsShim::BIO_free_all(BIO *a) {
        ::BIO_free_all(a);
    }

    EVP_PKEY *TlsShim::PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) {
        return ::PEM_read_bio_PrivateKey(bp, x, cb, u);
    }

    int TlsShim::PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
        unsigned char *kstr, int klen, pem_password_cb *cb, void *u)
    {
        return ::PEM_write_bio_PrivateKey(bp, x, enc, kstr, klen, cb, u);
    }

    void TlsShim::EVP_PKEY_free(EVP_PKEY *pkey) {
        ::EVP_PKEY_free(pkey);
    }

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

    int TlsShim::tls_config_set_cert_mem(struct tls_config *_config, const uint8_t *_cert,
        size_t _len)
    {
        return ::tls_config_set_cert_mem(_config, _cert, _len);
    }

    int TlsShim::tls_config_set_key_mem(struct tls_config *_config, const uint8_t *_key,
        size_t _len)
    {
        return ::tls_config_set_key_mem(_config, _key, _len);
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

    struct tls *TlsShim::tls_server(void) {
        return ::tls_server();
    }

    int TlsShim::tls_connect_cbs(struct tls *_ctx, tls_read_cb _read_cb,
        tls_write_cb _write_cb, void *_cb_arg, const char *_servername)
    {
        return ::tls_connect_cbs(_ctx, _read_cb, _write_cb, _cb_arg, _servername);
    }

    int TlsShim::tls_accept_cbs(struct tls *_ctx, struct tls **_cctx,
        tls_read_cb _read_cb, tls_write_cb _write_cb, void *_cb_arg)
    {
        return ::tls_accept_cbs(_ctx, _cctx, _read_cb, _write_cb, _cb_arg);
    }

    int TlsShim::tls_handshake(struct tls *_ctx) {
        return ::tls_handshake(_ctx);
    }

    int TlsShim::tls_peer_cert_provided(struct tls *_ctx) {
        return ::tls_peer_cert_provided(_ctx);
    }

    const uint8_t *TlsShim::tls_peer_cert_chain_pem(struct tls *_ctx, size_t *_len) {
        return ::tls_peer_cert_chain_pem(_ctx, _len);
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
