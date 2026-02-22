/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */
/* SocketWSH2.c - WebSocket over HTTP/2 (RFC 8441)
 *
 * Implements WebSocket connections over HTTP/2 streams using Extended CONNECT.
 *
 * Key differences from RFC 6455:
 * - No masking required (HTTP/2 provides transport security)
 * - No Sec-WebSocket-Key/Accept exchange
 * - Uses :protocol pseudo-header instead
 * - Response is 200 (not 101)
 * - Orderly close via END_STREAM, abnormal via RST_STREAM
 */
#include "socket/SocketWSH2.h"
#include "core/Arena.h"
#include "core/Except.h"
#include "http/SocketHTTP2-private.h"
#include "http/SocketHTTP2.h"
#include "socket/SocketBuf.h"
#include "socket/SocketWS-private.h"
#include "socket/SocketWS-transport.h"
#include <assert.h>
#include <string.h>
#undef SOCKET_LOG_COMPONENT
#define SOCKET_LOG_COMPONENT "SocketWSH2"
#include "core/SocketUtil.h"
/**
 * Buffer sizes for WebSocket-over-HTTP/2
 *
 * Uses smaller buffers (16KB) compared to standard WebSocket (64KB) to optimize
 * memory usage in HTTP/2 multiplexing scenarios where many concurrent WebSocket
 * streams may exist on a single connection.
 *
 * References SOCKET_BUFFER_SIZE_16KB from SocketConfig.h for consistency.
 */
#ifndef SOCKETWSH2_RECV_BUFFER_SIZE
#define SOCKETWSH2_RECV_BUFFER_SIZE SOCKET_BUFFER_SIZE_16KB
#endif
#ifndef SOCKETWSH2_SEND_BUFFER_SIZE
#define SOCKETWSH2_SEND_BUFFER_SIZE SOCKET_BUFFER_SIZE_16KB
#endif
/* Helper: Prepare config for WS context */
static void
prepare_ws_config (SocketWS_Config *cfg, const SocketWS_Config *config, SocketWS_Role role)
{
  if (config)
    memcpy (cfg, config, sizeof (*cfg));
  else
    SocketWS_config_defaults (cfg);
  cfg->role = role;
}
/* Helper: Allocate and init WS struct */
static SocketWS_T
alloc_ws_struct (Arena_T arena)
{
  SocketWS_T ws = ALLOC (arena, sizeof (*ws));
  if (!ws)
    {
      SOCKET_LOG_ERROR_MSG ("Failed to allocate WebSocket context");
      return NULL;
    }
  memset (ws, 0, sizeof (*ws));
  ws->arena = arena;
  return ws;
}
/* Helper: Create I/O buffers */
static int
create_ws_buffers (SocketWS_T ws, Arena_T arena)
{
  ws->recv_buf = SocketBuf_new (arena, SOCKETWSH2_RECV_BUFFER_SIZE);
  if (!ws->recv_buf)
    {
      SOCKET_LOG_ERROR_MSG ("Failed to create recv buffer");
      return -1;
    }
  ws->send_buf = SocketBuf_new (arena, SOCKETWSH2_SEND_BUFFER_SIZE);
  if (!ws->send_buf)
    {
      SocketBuf_release (&ws->recv_buf);
      SOCKET_LOG_ERROR_MSG ("Failed to create send buffer");
      return -1;
    }
  return 0;
}
/* Helper: Init parsers and timers */
static void
init_ws_parsers (SocketWS_T ws)
{
  ws_frame_reset (&ws->frame);
  ws_message_reset (&ws->message);
  ws->last_pong_received_time = Socket_get_monotonic_ms ();
}
/* Helper: Create H2 transport */
static SocketWS_Transport_T
create_h2_transport (Arena_T arena, SocketHTTP2_Stream_T stream)
{
  SocketWS_Transport_T transport = SocketWS_Transport_h2stream (arena, stream);
  if (!transport)
    {
      SOCKET_LOG_ERROR_MSG ("Failed to create H2 stream transport");
      return NULL;
    }
  return transport;
}
static SocketWS_T
wsh2_create_ws_context (Arena_T arena,
                        SocketHTTP2_Stream_T stream,
                        const SocketWS_Config *config,
                        SocketWS_Role role)
{
  SocketWS_T ws;
  SocketWS_Config cfg;
  SocketWS_Transport_T transport;
  assert (arena);
  assert (stream);
  prepare_ws_config (&cfg, config, role);
  ws = alloc_ws_struct (arena);
  if (!ws)
    return NULL;
  memcpy (&ws->config, &cfg, sizeof (ws->config));
  ws->role = role;
  if (create_ws_buffers (ws, arena) < 0)
    return NULL;
  init_ws_parsers (ws);
  transport = create_h2_transport (arena, stream);
  if (!transport)
    {
      SocketBuf_release (&ws->recv_buf);
      SocketBuf_release (&ws->send_buf);
      return NULL;
    }
  ws->transport = transport;
  /* WebSocket over HTTP/2 starts in OPEN state (no handshake needed) */
  ws->state = WS_STATE_OPEN;
  SOCKET_LOG_DEBUG_MSG ("Created WebSocket over HTTP/2 stream %u", stream->id);
  return ws;
}
int
SocketWSH2_is_websocket_request (SocketHTTP2_Stream_T stream)
{
  if (!stream)
    return 0;
  /* Must be Extended CONNECT with :protocol=websocket */
  if (!stream->is_extended_connect)
    return 0;
  if (strcmp (stream->protocol, "websocket") != 0)
    return 0;
  return 1;
}
SocketWS_T
SocketWSH2_server_accept (SocketHTTP2_Stream_T stream,
                          const SocketWS_Config *config)
{
  SocketHTTP2_Conn_T conn;
  Arena_T arena;
  SocketWS_T ws;
  SocketHPACK_Header response_headers[2];
  int send_result;
  assert (stream);
  /* Validate this is a WebSocket request */
  if (!SocketWSH2_is_websocket_request (stream))
    {
      SOCKET_LOG_ERROR_MSG ("Stream is not a WebSocket upgrade request");
      return NULL;
    }
  conn = stream->conn;
  if (!conn)
    {
      SOCKET_LOG_ERROR_MSG ("Stream has no connection");
      return NULL;
    }
  /* Verify Extended CONNECT is enabled */
  if (conn->local_settings[SETTINGS_IDX_ENABLE_CONNECT_PROTOCOL] == 0)
    {
      SOCKET_LOG_ERROR_MSG ("Extended CONNECT not enabled on this connection");
      return NULL;
    }
  /* Use connection's arena for allocations */
  arena = conn->arena;
  /* Create WebSocket context with H2 transport */
  ws = wsh2_create_ws_context (arena, stream, config, WS_ROLE_SERVER);
  if (!ws)
    return NULL;
  /* Send 200 response (RFC 8441: NOT 101) */
  response_headers[0].name = ":status";
  response_headers[0].name_len = 7;
  response_headers[0].value = "200";
  response_headers[0].value_len = 3;
  response_headers[0].never_index = 0;
  send_result = SocketHTTP2_Stream_send_headers (
      stream, response_headers, 1, 0 /* no END_STREAM */);
  if (send_result < 0)
    {
      SOCKET_LOG_ERROR_MSG ("Failed to send WebSocket accept response");
      /* WebSocket will be freed when arena is disposed */
      return NULL;
    }
  SOCKET_LOG_DEBUG_MSG ("Accepted WebSocket connection on stream %u",
                        stream->id);
  return ws;
}
int
SocketWSH2_is_supported (SocketHTTP2_Conn_T conn)
{
  if (!conn)
    return 0;
  /* Check if peer sent SETTINGS_ENABLE_CONNECT_PROTOCOL=1 */
  return conn->peer_settings[SETTINGS_IDX_ENABLE_CONNECT_PROTOCOL] != 0;
}
static int
send_connect_request (SocketHTTP2_Stream_T stream, const char *path)
{
  SocketHPACK_Header request_headers[5];
  size_t header_count;
  int send_result;
  assert (stream);
  assert (path);
  /* Build Extended CONNECT request headers (RFC 8441 Section 4) */
  header_count = 0;
  request_headers[header_count].name = ":method";
  request_headers[header_count].name_len = 7;
  request_headers[header_count].value = "CONNECT";
  request_headers[header_count].value_len = 7;
  request_headers[header_count].never_index = 0;
  header_count++;
  request_headers[header_count].name = ":protocol";
  request_headers[header_count].name_len = 9;
  request_headers[header_count].value = "websocket";
  request_headers[header_count].value_len = 9;
  request_headers[header_count].never_index = 0;
  header_count++;
  request_headers[header_count].name = ":scheme";
  request_headers[header_count].name_len = 7;
  request_headers[header_count].value = "https";
  request_headers[header_count].value_len = 5;
  request_headers[header_count].never_index = 0;
  header_count++;
  request_headers[header_count].name = ":path";
  request_headers[header_count].name_len = 5;
  request_headers[header_count].value = path;
  request_headers[header_count].value_len = strlen (path);
  request_headers[header_count].never_index = 0;
  header_count++;
  /* :authority would be set from connection context in production */
  /* Send request headers */
  send_result = SocketHTTP2_Stream_send_headers (
      stream, request_headers, header_count, 0 /* no END_STREAM */);
  if (send_result < 0)
    {
      SOCKET_LOG_ERROR_MSG ("Failed to send WebSocket connect request");
      return -1;
    }
  return 0;
}
static int
receive_connect_response (SocketHTTP2_Stream_T stream,
                          SocketHPACK_Header *headers,
                          size_t max_headers,
                          size_t *header_count)
{
  int recv_result;
  int end_stream;
  assert (stream);
  assert (headers);
  assert (header_count);
  /* Wait for response headers (blocking for simplicity) */
  /* In production, this should be integrated with event loop */
  recv_result = SocketHTTP2_Stream_recv_headers (
      stream, headers, max_headers, header_count, &end_stream);
  if (recv_result <= 0)
    {
      SOCKET_LOG_ERROR_MSG ("Failed to receive WebSocket connect response");
      return -1;
    }
  return 0;
}
static const char *
validate_websocket_response (SocketHPACK_Header *headers, size_t header_count)
{
  const char *status;
  size_t i;
  assert (headers);
  /* Check for 200 response */
  status = NULL;
  for (i = 0; i < header_count; i++)
    {
      if (headers[i].name_len == 7
          && memcmp (headers[i].name, ":status", 7) == 0)
        {
          status = headers[i].value;
          break;
        }
    }
  if (!status || strncmp (status, "200", 3) != 0)
    {
      SOCKET_LOG_ERROR_MSG ("WebSocket connect rejected: status=%s",
                            status ? status : "missing");
      return NULL;
    }
  return status;
}
/* Helper: Create new stream */
static SocketHTTP2_Stream_T
create_new_stream (SocketHTTP2_Conn_T conn)
{
  SocketHTTP2_Stream_T stream = SocketHTTP2_Stream_new (conn);
  if (!stream)
    {
      SOCKET_LOG_ERROR_MSG ("Failed to create HTTP/2 stream");
      return NULL;
    }
  return stream;
}
/* Helper: Validate peer support */
static int
validate_peer_support (SocketHTTP2_Conn_T conn)
{
  if (!SocketWSH2_is_supported (conn))
    {
      SOCKET_LOG_ERROR_MSG ("Peer does not support Extended CONNECT");
      return -1;
    }
  return 0;
}
/* Helper: Send request and receive response */
static int
handle_connect_request_response (SocketHTTP2_Stream_T stream, const char *path,
                                 SocketHPACK_Header *response_headers, size_t *response_count)
{
  if (send_connect_request (stream, path) < 0)
    return -1;
  if (receive_connect_response (stream, response_headers, 16, response_count) < 0)
    return -1;
  return 0;
}
/* Helper: Validate response and create WS */
static SocketWS_T
validate_and_create_ws (Arena_T arena, SocketHTTP2_Stream_T stream,
                         SocketHPACK_Header *response_headers, size_t response_count,
                         const SocketWS_Config *config)
{
  const char *status = validate_websocket_response (response_headers, response_count);
  if (!status)
    return NULL;
  SocketWS_T ws = wsh2_create_ws_context (arena, stream, config, WS_ROLE_CLIENT);
  if (!ws)
    return NULL;
  SOCKET_LOG_DEBUG_MSG ("WebSocket client connected on stream %u", stream->id);
  return ws;
}
SocketWS_T
SocketWSH2_client_connect (SocketHTTP2_Conn_T conn,
                           const char *path,
                           const SocketWS_Config *config)
{
  SocketHTTP2_Stream_T stream;
  Arena_T arena;
  SocketWS_T ws;
  SocketHPACK_Header response_headers[16];
  size_t response_count;
  const char *status;
  assert (conn);
  assert (path);
  if (validate_peer_support (conn) < 0)
    return NULL;
  arena = conn->arena;
  stream = create_new_stream (conn);
  if (!stream)
    return NULL;
  if (handle_connect_request_response (stream, path, response_headers, &response_count) < 0)
    {
      SocketHTTP2_Stream_close (stream, HTTP2_CANCEL);
      return NULL;
    }
  ws = validate_and_create_ws (arena, stream, response_headers, response_count, config);
  if (!ws)
    {
      SocketHTTP2_Stream_close (stream, HTTP2_CANCEL);
      return NULL;
    }
  return ws;
}
SocketHTTP2_Stream_T
SocketWSH2_get_stream (SocketWS_T ws)
{
  if (!ws || !ws->transport)
    return NULL;
  if (SocketWS_Transport_type (ws->transport) != SOCKETWS_TRANSPORT_H2STREAM)
    return NULL;
  return SocketWS_Transport_get_h2stream (ws->transport);
}
SocketHTTP2_Conn_T
SocketWSH2_get_connection (SocketWS_T ws)
{
  SocketHTTP2_Stream_T stream;
  stream = SocketWSH2_get_stream (ws);
  if (!stream)
    return NULL;
  return SocketHTTP2_Stream_get_connection (stream);
}