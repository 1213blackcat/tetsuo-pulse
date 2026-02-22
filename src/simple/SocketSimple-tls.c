/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */
/**
 * @file SocketSimple-tls.c
 * @brief TLS implementation for Simple API.
 */
#include "SocketSimple-internal.h"
#include "socket/SocketCommon.h"

void
Socket_simple_tls_options_init (SocketSimple_TLSOptions *opts)
{
  if (!opts)
    return;
  memset (opts, 0, sizeof (*opts));
  opts->verify_cert = 1;
  opts->timeout_ms = SOCKET_TLS_HANDSHAKE_TIMEOUT_MS;
}

#ifdef SOCKET_HAS_TLS

static void
copy_tls_options (const SocketSimple_TLSOptions *opts_param,
                  SocketSimple_TLSOptions *opts_local,
                  int *timeout_ms,
                  const char **ca_file,
                  const char **client_cert,
                  const char **client_key,
                  int *verify_cert)
{
  if (!opts_param)
    {
      Socket_simple_tls_options_init (opts_local);
      opts_param = opts_local;
    }
  *timeout_ms = opts_param->timeout_ms;
  *ca_file = opts_param->ca_file;
  *client_cert = opts_param->client_cert;
  *client_key = opts_param->client_key;
  *verify_cert = opts_param->verify_cert;
}

static void
connect_socket_block (volatile Socket_T *sock,
                      const char *host,
                      int port,
                      int timeout_ms)
{
  if (timeout_ms > 0)
    {
      *sock = Socket_connect_tcp (host, port, timeout_ms);
    }
  else
    {
      *sock = Socket_new (AF_INET, SOCK_STREAM, 0);
      Socket_connect (*sock, host, port);
    }
}

static void
create_tls_context_block (volatile SocketTLSContext_T *ctx,
                          const char *ca_file)
{
  *ctx = SocketTLSContext_new_client (ca_file);
}

static void
load_client_cert_if_provided (SocketTLSContext_T ctx,
                              const char *client_cert,
                              const char *client_key)
{
  if (client_cert && client_key)
    {
      SocketTLSContext_load_certificate (ctx, client_cert, client_key);
    }
}

static void
set_verify_mode_if_needed (SocketTLSContext_T ctx,
                           int verify_cert)
{
  if (!verify_cert)
    {
      SocketTLSContext_set_verify_mode (ctx, TLS_VERIFY_NONE);
    }
}

static void
enable_and_handshake (Socket_T sock,
                      SocketTLSContext_T ctx,
                      const char *host)
{
  SocketTLS_enable (sock, ctx);
  SocketTLS_set_hostname (sock, host);
  SocketTLS_handshake_auto (sock);
}

static struct SocketSimple_Socket *
allocate_handle (volatile Socket_T *sock,
                 volatile SocketTLSContext_T *ctx,
                 int is_tls,
                 int is_connected)
{
  struct SocketSimple_Socket *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      SIMPLE_CLEANUP_TLS_CTX (ctx);
      SIMPLE_CLEANUP_SOCKET (sock);
      return NULL;
    }
  handle->socket = *sock;
  handle->tls_ctx = *ctx;
  handle->is_tls = is_tls;
  handle->is_connected = is_connected;
  return handle;
}

static void
handle_connect_exception (int exception_type)
{
  switch (exception_type)
  {
  case 1: // SocketTLS_Failed
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS error");
    break;
  case 2: // SocketTLS_HandshakeFailed
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE, "TLS handshake failed");
    break;
  case 3: // SocketTLS_VerifyFailed
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_VERIFY,
                      "Certificate verification failed");
    break;
  case 4: // Socket_Failed
    simple_set_error_errno (SOCKET_SIMPLE_ERR_CONNECT, "Connection failed");
    break;
  }
}

SocketSimple_Socket_T
Socket_simple_connect_tls (const char *host, int port)
{
  return Socket_simple_connect_tls_ex (host, port, NULL);
}

SocketSimple_Socket_T
Socket_simple_connect_tls_ex (const char *host,
                              int port,
                              const SocketSimple_TLSOptions *opts_param)
{
  volatile Socket_T sock = NULL;
  volatile SocketTLSContext_T ctx = NULL;
  volatile int exception_occurred = 0;
  struct SocketSimple_Socket *handle = NULL;
  SocketSimple_TLSOptions opts_local;
  int timeout_ms;
  const char *ca_file;
  const char *client_cert;
  const char *client_key;
  int verify_cert;
  Socket_simple_clear_error ();
  if (!host || port <= 0 || port > SOCKET_MAX_PORT)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid host or port");
      return NULL;
    }
  copy_tls_options (opts_param, &opts_local, &timeout_ms, &ca_file, &client_cert, &client_key, &verify_cert);
  TRY
  {
    connect_socket_block (&sock, host, port, timeout_ms);
    create_tls_context_block (&ctx, ca_file);
    load_client_cert_if_provided (ctx, client_cert, client_key);
    set_verify_mode_if_needed (ctx, verify_cert);
    enable_and_handshake (sock, ctx, host);
  }
  EXCEPT (SocketTLS_Failed)
  {
    handle_connect_exception (1);
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    handle_connect_exception (2);
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    handle_connect_exception (3);
    exception_occurred = 1;
  }
  EXCEPT (Socket_Failed)
  {
    handle_connect_exception (4);
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred)
      {
        SIMPLE_CLEANUP_TLS_CTX (&ctx);
        SIMPLE_CLEANUP_SOCKET (&sock);
      }
  }
  END_TRY;
  if (exception_occurred)
    return NULL;
  return allocate_handle (&sock, &ctx, 1, 1);
}

static void
copy_enable_tls_options (const SocketSimple_TLSOptions *opts_param,
                         SocketSimple_TLSOptions *opts_local,
                         const char **ca_file,
                         int *verify_cert)
{
  if (!opts_param)
    {
      Socket_simple_tls_options_init (opts_local);
      opts_param = opts_local;
    }
  *ca_file = opts_param->ca_file;
  *verify_cert = opts_param->verify_cert;
}

static void
handle_enable_exception (int exception_type)
{
  switch (exception_type)
  {
  case 1: // SocketTLS_Failed
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS error");
    break;
  case 2: // SocketTLS_HandshakeFailed
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE, "TLS handshake failed");
    break;
  }
}

int
Socket_simple_enable_tls (SocketSimple_Socket_T sock, const char *hostname)
{
  return Socket_simple_enable_tls_ex (sock, hostname, NULL);
}

int
Socket_simple_enable_tls_ex (SocketSimple_Socket_T sock,
                             const char *hostname,
                             const SocketSimple_TLSOptions *opts_param)
{
  volatile SocketTLSContext_T ctx = NULL;
  volatile int exception_occurred = 0;
  SocketSimple_TLSOptions opts_local;
  const char *ca_file;
  int verify_cert;
  Socket_simple_clear_error ();
  if (!sock || !sock->socket || !hostname)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }
  if (sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "TLS already enabled");
      return -1;
    }
  copy_enable_tls_options (opts_param, &opts_local, &ca_file, &verify_cert);
  TRY
  {
    create_tls_context_block (&ctx, ca_file);
    set_verify_mode_if_needed (ctx, verify_cert);
    SocketTLS_enable (sock->socket, ctx);
    SocketTLS_set_hostname (sock->socket, hostname);
    SocketTLS_handshake_auto (sock->socket);
  }
  EXCEPT (SocketTLS_Failed)
  {
    handle_enable_exception (1);
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    handle_enable_exception (2);
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred)
      {
        SIMPLE_CLEANUP_TLS_CTX (&ctx);
      }
  }
  END_TRY;
  if (exception_occurred)
    return -1;
  sock->tls_ctx = ctx;
  sock->is_tls = 1;
  return 0;
}

int
Socket_simple_is_tls (SocketSimple_Socket_T sock)
{
  return sock ? sock->is_tls : 0;
}

const char *
Socket_simple_get_alpn (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->socket || !sock->is_tls)
    {
      return NULL;
    }
  return SocketTLS_get_alpn_selected (sock->socket);
}

const char *
Socket_simple_get_tls_version (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->socket || !sock->is_tls)
    {
      return NULL;
    }
  return SocketTLS_get_version (sock->socket);
}

int
Socket_simple_get_cert_info (SocketSimple_Socket_T sock, char *buf, size_t len)
{
  if (!sock || !sock->socket || !sock->is_tls || !buf || len == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }
  SocketTLS_CertInfo info;
  int ret = SocketTLS_get_peer_cert_info (sock->socket, &info);
  if (ret == 1)
    {
      snprintf (buf,
                len,
                "Subject: %s\nIssuer: %s\nFingerprint: %s",
                info.subject,
                info.issuer,
                info.fingerprint);
      return 0;
    }
  else if (ret == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TLS, "No peer certificate");
      return -1;
    }
  simple_set_error (SOCKET_SIMPLE_ERR_TLS, "Failed to get certificate info");
  return -1;
}

int
Socket_simple_get_cert_cn (SocketSimple_Socket_T sock, char *buf, size_t len)
{
  if (!sock || !sock->socket || !sock->is_tls || !buf || len == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }
  int ret = SocketTLS_get_cert_subject (sock->socket, buf, len);
  if (ret > 0)
    {
      return 0;
    }
  else if (ret == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TLS, "No peer certificate");
      return -1;
    }
  simple_set_error (SOCKET_SIMPLE_ERR_TLS, "Failed to get certificate subject");
  return -1;
}

const char *
Socket_simple_get_cipher (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->socket || !sock->is_tls)
    {
      return NULL;
    }
  return SocketTLS_get_cipher (sock->socket);
}

int
Socket_simple_is_session_reused (SocketSimple_Socket_T sock)
{
  if (!sock || !sock->socket || !sock->is_tls)
    {
      return -1;
    }
  return SocketTLS_is_session_reused (sock->socket);
}

static void
clear_buffer_on_error (unsigned char *buf, size_t *len)
{
  if (buf && len && *len > 0)
    SocketCrypto_secure_clear (buf, *len);
}

int
Socket_simple_session_save (SocketSimple_Socket_T sock,
                            unsigned char *buf,
                            size_t *len)
{
  Socket_simple_clear_error ();
  if (!sock || !len)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      clear_buffer_on_error (buf, len);
      return -1;
    }
  if (!sock->socket || !sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS not enabled");
      clear_buffer_on_error (buf, len);
      return -1;
    }
  int ret = SocketTLS_session_save (sock->socket, buf, len);
  if (ret == -1)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TLS,
                        "No session available or handshake incomplete");
      clear_buffer_on_error (buf, len);
    }
  return ret;
}

int
Socket_simple_session_restore (SocketSimple_Socket_T sock,
                               const unsigned char *buf,
                               size_t len)
{
  Socket_simple_clear_error ();
  if (!sock || !buf || len == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid argument");
      return -1;
    }
  if (!sock->socket || !sock->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS not enabled");
      return -1;
    }
  int ret = SocketTLS_session_restore (sock->socket, buf, len);
  if (ret == -1)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TLS,
                        "Failed to restore session (handshake already done?)");
    }
  else if (ret == 0)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_TLS, "Session expired or invalid");
    }
  return ret;
}

static void
listen_socket_block (volatile Socket_T *sock,
                     const char *host,
                     int port,
                     int backlog)
{
  /* Use library convenience function - handles address family automatically */
  *sock = Socket_listen_tcp (host ? host : "0.0.0.0",
                             port,
                             backlog > 0 ? backlog
                                         : SOCKET_DEFAULT_LISTEN_BACKLOG);
}

static void
create_server_tls_context (volatile SocketTLSContext_T *ctx,
                           const char *cert_file,
                           const char *key_file)
{
  /* Create server TLS context */
  *ctx = SocketTLSContext_new_server (cert_file, key_file, NULL);
}

static void
handle_listen_exception (int exception_type, int err)
{
  if (exception_type == 1) // SocketTLS_Failed
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS,
                      "Failed to create TLS server context");
  }
  else if (exception_type == 2) // Socket_Failed
  {
    if (err == EADDRINUSE)
      {
        simple_set_error (SOCKET_SIMPLE_ERR_BIND, "Address already in use");
      }
    else
      {
        simple_set_error_errno (SOCKET_SIMPLE_ERR_LISTEN, "Listen failed");
      }
  }
}

SocketSimple_Socket_T
Socket_simple_listen_tls (const char *host,
                          int port,
                          int backlog,
                          const char *cert_file,
                          const char *key_file)
{
  volatile Socket_T sock = NULL;
  volatile SocketTLSContext_T ctx = NULL;
  volatile int exception_occurred = 0;
  struct SocketSimple_Socket *handle = NULL;
  Socket_simple_clear_error ();
  if (port <= 0 || port > SOCKET_MAX_PORT)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG, "Invalid port");
      return NULL;
    }
  if (!cert_file || !key_file)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Certificate and key files required");
      return NULL;
    }
  TRY
  {
    listen_socket_block (&sock, host, port, backlog);
    create_server_tls_context (&ctx, cert_file, key_file);
  }
  EXCEPT (SocketTLS_Failed)
  {
    handle_listen_exception (1, 0);
    exception_occurred = 1;
  }
  EXCEPT (Socket_Failed)
  {
    int err = Socket_geterrno ();
    handle_listen_exception (2, err);
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred)
      {
        SIMPLE_CLEANUP_TLS_CTX (&ctx);
        SIMPLE_CLEANUP_SOCKET (&sock);
      }
  }
  END_TRY;
  if (exception_occurred)
    return NULL;
  return allocate_handle (&sock, &ctx, 1, 0);
}

/**
 * simple_tls_accept_handshake - Accept and complete TLS handshake
 * @server: TLS server socket
 * @client_out: Output for accepted client socket
 *
 * Returns: 0 on success, -1 on failure (error already set, client cleaned up)
 */
static int
simple_tls_accept_handshake (SocketSimple_Socket_T server,
                             volatile Socket_T *client_out)
{
  volatile int exception_occurred = 0;
  TRY
  {
    *client_out = Socket_accept (server->socket);
    SocketTLS_enable (*client_out, server->tls_ctx);
    SocketTLS_handshake_auto (*client_out);
  }
  EXCEPT (SocketTLS_Failed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS, "TLS error during accept");
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_HandshakeFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_HANDSHAKE,
                      "TLS handshake failed during accept");
    exception_occurred = 1;
  }
  EXCEPT (SocketTLS_VerifyFailed)
  {
    simple_set_error (SOCKET_SIMPLE_ERR_TLS_VERIFY,
                      "Client certificate verification failed");
    exception_occurred = 1;
  }
  EXCEPT (Socket_Failed)
  {
    simple_set_error_errno (SOCKET_SIMPLE_ERR_ACCEPT, "Accept failed");
    exception_occurred = 1;
  }
  FINALLY
  {
    if (exception_occurred)
      SIMPLE_CLEANUP_TLS_CLIENT (client_out);
  }
  END_TRY;
  return exception_occurred ? -1 : 0;
}

static struct SocketSimple_Socket *
allocate_client_handle (volatile Socket_T *client)
{
  struct SocketSimple_Socket *handle = calloc (1, sizeof (*handle));
  if (!handle)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_MEMORY, "Memory allocation failed");
      SIMPLE_CLEANUP_TLS_CLIENT (client);
      return NULL;
    }
  handle->socket = *client;
  handle->tls_ctx = NULL;
  handle->is_tls = 1;
  handle->is_server = 0;
  handle->is_connected = 1;
  return handle;
}

SocketSimple_Socket_T
Socket_simple_accept_tls (SocketSimple_Socket_T server)
{
  volatile Socket_T client = NULL;
  Socket_simple_clear_error ();
  if (!server || !server->socket || !server->tls_ctx)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Invalid TLS server socket");
      return NULL;
    }
  if (!server->is_server || !server->is_tls)
    {
      simple_set_error (SOCKET_SIMPLE_ERR_INVALID_ARG,
                        "Socket is not a TLS server");
      return NULL;
    }
  if (simple_tls_accept_handshake (server, &client) != 0)
    return NULL;
  return allocate_client_handle (&client);
}

#else /* !SOCKET_HAS_TLS */

SocketSimple_Socket_T
Socket_simple_connect_tls (const char *host, int port)
{
  (void)host;
  (void)port;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return NULL;
}

SocketSimple_Socket_T
Socket_simple_connect_tls_ex (const char *host,
                              int port,
                              const SocketSimple_TLSOptions *opts)
{
  (void)host;
  (void)port;
  (void)opts;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return NULL;
}

int
Socket_simple_enable_tls (SocketSimple_Socket_T sock, const char *hostname)
{
  (void)sock;
  (void)hostname;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

int
Socket_simple_enable_tls_ex (SocketSimple_Socket_T sock,
                             const char *hostname,
                             const SocketSimple_TLSOptions *opts)
{
  (void)sock;
  (void)hostname;
  (void)opts;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

int
Socket_simple_is_tls (SocketSimple_Socket_T sock)
{
  (void)sock;
  return 0;
}

const char *
Socket_simple_get_alpn (SocketSimple_Socket_T sock)
{
  (void)sock;
  return NULL;
}

const char *
Socket_simple_get_tls_version (SocketSimple_Socket_T sock)
{
  (void)sock;
  return NULL;
}

int
Socket_simple_get_cert_info (SocketSimple_Socket_T sock, char *buf, size_t len)
{
  (void)sock;
  (void)buf;
  (void)len;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

int
Socket_simple_get_cert_cn (SocketSimple_Socket_T sock, char *buf, size_t len)
{
  (void)sock;
  (void)buf;
  (void)len;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

const char *
Socket_simple_get_cipher (SocketSimple_Socket_T sock)
{
  (void)sock;
  return NULL;
}

int
Socket_simple_is_session_reused (SocketSimple_Socket_T sock)
{
  (void)sock;
  return -1;
}

int
Socket_simple_session_save (SocketSimple_Socket_T sock,
                            unsigned char *buf,
                            size_t *len)
{
  (void)sock;
  (void)buf;
  (void)len;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

int
Socket_simple_session_restore (SocketSimple_Socket_T sock,
                               const unsigned char *buf,
                               size_t len)
{
  (void)sock;
  (void)buf;
  (void)len;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return -1;
}

SocketSimple_Socket_T
Socket_simple_listen_tls (const char *host,
                          int port,
                          int backlog,
                          const char *cert_file,
                          const char *key_file)
{
  (void)host;
  (void)port;
  (void)backlog;
  (void)cert_file;
  (void)key_file;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return NULL;
}

SocketSimple_Socket_T
Socket_simple_accept_tls (SocketSimple_Socket_T server)
{
  (void)server;
  simple_set_error (SOCKET_SIMPLE_ERR_UNSUPPORTED, "TLS not enabled in build");
  return NULL;
}

#endif /* SOCKET_HAS_TLS */