// ref. https://releases.llvm.org/3.8.1/docs/LibFuzzer.html

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>

SSL_CTX *sctx;
int Init() {
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  assert (sctx = SSL_CTX_new(TLSv1_method()));
  assert (SSL_CTX_use_certificate_file(sctx, "server.pem", SSL_FILETYPE_PEM));
  assert (SSL_CTX_use_PrivateKey_file(sctx, "server.key", SSL_FILETYPE_PEM));
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  static int unused = Init();
  SSL *server = SSL_new(sctx);
  BIO *sinbio = BIO_new(BIO_s_mem());
  BIO *soutbio = BIO_new(BIO_s_mem());
  SSL_set_bio(server, sinbio, soutbio);
  SSL_set_accept_state(server);
  BIO_write(sinbio, Data, Size);
  SSL_do_handshake(server);
  SSL_free(server);
  return 0;
}
