/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */
/**
 * @file SocketGRPCClient-h3.c
 * @brief gRPC client transport integration over HTTP/3.
 */
#ifdef SOCKET_HAS_TLS
#include "grpc/SocketGRPC-private.h"
#include "grpc/SocketGRPCWire.h"
#include "core/SocketCrypto.h"
#include "core/SocketMetrics.h"
#include "core/SocketUtil/Timeout.h"
#include "http/SocketHTTP3-client.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define GRPC_MAX_PATH_LEN 512
#define GRPC_MAX_AUTHORITY_LEN 320
#define GRPC_MAX_HOST_LEN 256
typedef struct
{
  Arena_T arena;
  SocketHTTP3_Client_T http3_client;
  SocketHTTP3_Request_T request;
  unsigned char *recv_buffer;
  size_t recv_len;
  size_t recv_cap;
  int headers_received;
  int remote_end_stream;
  int trailers_ingested;
  int status_finalized;
  int http_status_code;
  int64_t deadline_ms;
  int64_t opened_at_ms;
  int metrics_stream_active;
  int observability_started;
  SocketGRPC_Compression response_compression;
} SocketGRPC_H3CallStream;
struct SocketGRPC_ClientUnaryInterceptorEntry
{
  SocketGRPC_ClientUnaryInterceptor interceptor;
  void *userdata;
  struct SocketGRPC_ClientUnaryInterceptorEntry *next;
};
struct SocketGRPC_ClientStreamInterceptorEntry
{
  SocketGRPC_ClientStreamInterceptor interceptor;
  void *userdata;
  struct SocketGRPC_ClientStreamInterceptorEntry *next;
};
static void
grpc_client_stream_observability_started (SocketGRPC_Call_T call,
                                          SocketGRPC_H3CallStream *ctx)
{
  if (ctx == NULL || ctx->observability_started)
    return;
  if (!grpc_client_observability_enabled (call))
    return;
  ctx->opened_at_ms = SocketTimeout_now_ms ();
  ctx->observability_started = 1;
  ctx->metrics_stream_active = 1;
  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_CLIENT_CALLS_STARTED);
  SocketMetrics_gauge_inc (SOCKET_GAU_GRPC_CLIENT_ACTIVE_STREAMS);
  grpc_client_emit_observability_event (call,
                                        SOCKET_GRPC_LOG_EVENT_CLIENT_CALL_START,
                                        SOCKET_GRPC_STATUS_OK,
                                        NULL,
                                        0,
                                        1U,
                                        -1);
}
static void grpc_handle_metrics_stream_active(SocketGRPC_H3CallStream *ctx) {
  if (ctx->metrics_stream_active)
    {
      SocketMetrics_gauge_dec (SOCKET_GAU_GRPC_CLIENT_ACTIVE_STREAMS);
      ctx->metrics_stream_active = 0;
    }
}
static int grpc_check_observability_started(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx) {
  if (!ctx->observability_started)
    return 0;
  if (!grpc_client_observability_enabled (call))
    {
      ctx->observability_started = 0;
      return 0;
    }
  return 1;
}
static void grpc_get_status_code_message(SocketGRPC_Call_T call, SocketGRPC_StatusCode *code, const char **message) {
  SocketGRPC_Status status = SocketGRPC_Call_status (call);
  *code = grpc_normalize_status_code (status.code);
  *message = (status.message != NULL && status.message[0] != '\0')
                ? status.message
                : SocketGRPC_status_default_message (*code);
}
static int64_t grpc_calculate_duration(SocketGRPC_H3CallStream *ctx) {
  int64_t duration_ms = -1;
  if (ctx->opened_at_ms > 0)
    {
      duration_ms = SocketTimeout_elapsed_ms (ctx->opened_at_ms);
      if (duration_ms < 0)
        duration_ms = 0;
    }
  return duration_ms;
}
static void grpc_observe_histograms(int64_t duration_ms) {
  if (duration_ms >= 0) {
    SocketMetrics_histogram_observe (
          SOCKET_HIST_GRPC_CLIENT_STREAM_OPEN_DURATION_MS, (double)duration_ms);
      SocketMetrics_histogram_observe (SOCKET_HIST_GRPC_CLIENT_CALL_LATENCY_MS,
                                       (double)duration_ms);
  }
}
static void grpc_emit_observability_finished(SocketGRPC_Call_T call, SocketGRPC_StatusCode code, const char *message, int64_t duration_ms) {
  SocketMetrics_counter_inc (SOCKET_CTR_GRPC_CLIENT_CALLS_COMPLETED);
  SocketMetrics_counter_inc (grpc_client_status_counter_metric (code));
  grpc_client_emit_observability_event (
      call,
      SOCKET_GRPC_LOG_EVENT_CLIENT_CALL_FINISH,
      code,
      message,
      0,
      1U,
      duration_ms);
}
static void
grpc_client_stream_observability_finished (SocketGRPC_Call_T call,
                                           SocketGRPC_H3CallStream *ctx)
{
  SocketGRPC_StatusCode code;
  const char *message;
  int64_t duration_ms;
  if (ctx == NULL)
    return;
  grpc_handle_metrics_stream_active(ctx);
  if (grpc_check_observability_started(call, ctx) == 0)
    return;
  grpc_get_status_code_message(call, &code, &message);
  duration_ms = grpc_calculate_duration(ctx);
  grpc_observe_histograms(duration_ms);
  grpc_emit_observability_finished(call, code, message, duration_ms);
  ctx->observability_started = 0;
}
static int
grpc_parse_port_str (const char *value, int *port_out)
{
  char *end = NULL;
  long parsed;
  if (value == NULL || value[0] == '\0' || port_out == NULL)
    return -1;
  errno = 0;
  parsed = strtol (value, &end, 10);
  if (errno != 0 || end == value || end == NULL || *end != '\0')
    return -1;
  if (parsed <= 0 || parsed > SOCKET_MAX_PORT)
    return -1;
  *port_out = (int)parsed;
  return 0;
}
static int grpc_determine_base(const char *target, const char **base_out) {
  if (str_has_prefix (target, "https://"))
    *base_out = target + strlen ("https://");
  else if (str_has_prefix (target, "http://"))
    return -1;
  else if (str_has_prefix (target, "dns:///"))
    *base_out = target + strlen ("dns:///");
  else
    *base_out = target;
  return 0;
}
static int grpc_extract_authority(const char *base, char *authority, size_t authority_cap) {
  size_t base_len = strcspn (base, "/");
  if (base_len == 0 || base_len >= authority_cap)
    return -1;
  memcpy (authority, base, base_len);
  authority[base_len] = '\0';
  return 0;
}
static int grpc_parse_ipv6_host(char *host_part, char *host, size_t host_cap, char **port_part_out) {
  char *close = strchr (host_part, ']');
  size_t hlen;
  if (close == NULL)
    return -1;
  hlen = (size_t)(close - host_part - 1);
  if (hlen == 0 || hlen >= host_cap)
    return -1;
  memcpy (host, host_part + 1, hlen);
  host[hlen] = '\0';
  if (close[1] == ':' && close[2] != '\0')
    *port_part_out = close + 2;
  else if (close[1] != '\0')
    return -1;
  return 0;
}
static int grpc_parse_ipv4_host(char *host_part, char *host, size_t host_cap, char **port_part_out) {
  char *first_colon = strchr (host_part, ':');
  char *last_colon = strrchr (host_part, ':');
  if (first_colon != NULL && first_colon == last_colon)
    {
      *first_colon = '\0';
      *port_part_out = first_colon + 1;
    }
  if (host_part[0] == '\0' || strlen (host_part) >= host_cap)
    return -1;
  memcpy (host, host_part, strlen (host_part) + 1);
  return 0;
}
static int grpc_parse_host_part(char *authority, char *host, size_t host_cap, char **port_part_out) {
  char *host_part = authority;
  *port_part_out = NULL;
  if (host_part[0] == '[')
    return grpc_parse_ipv6_host(host_part, host, host_cap, port_part_out);
  else
    return grpc_parse_ipv4_host(host_part, host, host_cap, port_part_out);
}
static int grpc_set_port(char *port_part, int *port_out) {
  if (port_part != NULL)
    {
      if (grpc_parse_port_str (port_part, port_out) != 0)
        return -1;
    }
  else
    {
      *port_out = SOCKET_DEFAULT_HTTPS_PORT;
    }
  return 0;
}
static int
grpc_h3_parse_target (const char *target,
                      char *host,
                      size_t host_cap,
                      int *port_out)
{
  const char *base;
  char authority[GRPC_MAX_AUTHORITY_LEN];
  char *port_part;
  if (target == NULL || host == NULL || host_cap == 0 || port_out == NULL)
    return -1;
  if (grpc_determine_base(target, &base) != 0)
    return -1;
  if (base[0] == '\0')
    return -1;
  if (grpc_extract_authority(base, authority, sizeof (authority)) != 0)
    return -1;
  if (grpc_parse_host_part(authority, host, host_cap, &port_part) != 0)
    return -1;
  if (grpc_set_port(port_part, port_out) != 0)
    return -1;
  return 0;
}
static int grpc_h3_build_authority_override(SocketGRPC_Call_T call, char *authority_out, size_t authority_out_cap) {
  if (call->channel != NULL && call->channel->authority_override != NULL)
    {
      size_t len = strlen (call->channel->authority_override);
      if (len == 0 || len >= authority_out_cap)
        return -1;
      memcpy (authority_out, call->channel->authority_override, len + 1);
      return 0;
    }
  return -1;
}
static int grpc_h3_build_authority_no_override(const char *host, int port, char *authority_out, size_t authority_out_cap) {
  int has_colon = strchr (host, ':') != NULL;
  if (port == SOCKET_DEFAULT_HTTPS_PORT)
    {
      int n;
      if (has_colon)
        n = snprintf (authority_out, authority_out_cap, "[%s]", host);
      else
        n = snprintf (authority_out, authority_out_cap, "%s", host);
      if (n <= 0 || (size_t)n >= authority_out_cap)
        return -1;
      return 0;
    }
  {
    int n;
    if (has_colon)
      n = snprintf (authority_out, authority_out_cap, "[%s]:%d", host, port);
    else
      n = snprintf (authority_out, authority_out_cap, "%s:%d", host, port);
    if (n <= 0 || (size_t)n >= authority_out_cap)
      return -1;
  }
  return 0;
}
static int
grpc_h3_build_authority (SocketGRPC_Call_T call,
                         const char *host,
                         int port,
                         char *authority_out,
                         size_t authority_out_cap)
{
  if (call == NULL || host == NULL || authority_out == NULL
      || authority_out_cap == 0)
    return -1;
  if (grpc_h3_build_authority_override(call, authority_out, authority_out_cap) == 0)
    return 0;
  return grpc_h3_build_authority_no_override(host, port, authority_out, authority_out_cap);
}
static const char *
grpc_h3_method_path (SocketGRPC_Call_T call, char *buf, size_t cap)
{
  size_t method_len;
  if (call == NULL || call->full_method == NULL || buf == NULL || cap == 0)
    return NULL;
  if (call->full_method[0] == '/')
    return call->full_method;
  method_len = strlen (call->full_method);
  if (method_len + 2 > cap)
    return NULL;
  buf[0] = '/';
  memcpy (buf + 1, call->full_method, method_len + 1);
  return buf;
}
static int grpc_h3_add_binary_metadata(SocketHTTP_Headers_T headers, const SocketGRPC_MetadataEntry *entry) {
  size_t encoded_cap = SocketCrypto_base64_encoded_size (entry->value_len);
  char *encoded = (char *)malloc (encoded_cap);
  ssize_t encoded_len;
  if (encoded == NULL)
    return -1;
  encoded_len = SocketCrypto_base64_encode (
      entry->value, entry->value_len, encoded, encoded_cap);
  if (encoded_len < 0
      || SocketHTTP_Headers_add_n (headers,
                                   entry->key,
                                   strlen (entry->key),
                                   encoded,
                                   (size_t)encoded_len)
             != 0)
    {
      free (encoded);
      return -1;
    }
  free (encoded);
  return 0;
}
static int grpc_h3_add_text_metadata(SocketHTTP_Headers_T headers, const SocketGRPC_MetadataEntry *entry) {
  if (SocketHTTP_Headers_add_n (headers,
                                entry->key,
                                strlen (entry->key),
                                (const char *)entry->value,
                                entry->value_len)
      != 0)
    return -1;
  return 0;
}
static int grpc_h3_add_metadata_entry(SocketHTTP_Headers_T headers, const SocketGRPC_MetadataEntry *entry) {
  if (entry == NULL || entry->key == NULL)
    return 0;
  if (entry->is_binary)
    return grpc_h3_add_binary_metadata(headers, entry);
  else
    return grpc_h3_add_text_metadata(headers, entry);
}
static int
grpc_h3_add_metadata_headers (SocketGRPC_Call_T call,
                              SocketHTTP_Headers_T headers,
                              SocketGRPC_Metadata_T metadata)
{
  size_t count;
  size_t i;
  if (call == NULL || headers == NULL || metadata == NULL)
    return -1;
  count = SocketGRPC_Metadata_count (metadata);
  if (count > call->channel->config.max_metadata_entries)
    return -1;
  for (i = 0; i < count; i++)
    {
      const SocketGRPC_MetadataEntry *entry = SocketGRPC_Metadata_at (metadata, i);
      if (grpc_h3_add_metadata_entry(headers, entry) != 0)
        return -1;
    }
  return 0;
}
static int grpc_h3_add_pseudo_headers_p1(SocketHTTP_Headers_T headers, const char *authority) {
  if (SocketHTTP_Headers_add_pseudo_n (headers, ":method", 7, "POST", 4) != 0
      || SocketHTTP_Headers_add_pseudo_n (headers, ":scheme", 7, "https", 5) != 0
      || SocketHTTP_Headers_add_pseudo_n (headers, ":authority", 10, authority, strlen (authority)) != 0)
    return -1;
  return 0;
}
static int grpc_h3_add_pseudo_headers_p2(SocketHTTP_Headers_T headers, const char *path) {
  if (SocketHTTP_Headers_add_pseudo_n (headers, ":path", 5, path, strlen (path)) != 0)
    return -1;
  return 0;
}
static int grpc_h3_add_standard_headers(SocketHTTP_Headers_T headers) {
  if (SocketHTTP_Headers_add (headers, "content-type", GRPC_CONTENT_TYPE) != 0
      || SocketHTTP_Headers_add (headers, "te", "trailers") != 0
      || SocketHTTP_Headers_add (headers, "grpc-accept-encoding", GRPC_ACCEPT_ENCODING_VALUE) != 0)
    return -1;
  return 0;
}
static int
grpc_h3_add_pseudo_headers (SocketGRPC_Call_T call,
                            SocketHTTP_Headers_T headers,
                            const char *host,
                            int port)
{
  char path_buf[GRPC_MAX_PATH_LEN];
  const char *path;
  char authority[GRPC_MAX_AUTHORITY_LEN];
  if (grpc_h3_build_authority (call, host, port, authority, sizeof (authority))
      != 0)
    return -1;
  if (grpc_h3_add_pseudo_headers_p1(headers, authority) != 0)
    return -1;
  path = grpc_h3_method_path (call, path_buf, sizeof (path_buf));
  if (path == NULL)
    return -1;
  if (grpc_h3_add_pseudo_headers_p2(headers, path) != 0)
    return -1;
  if (grpc_h3_add_standard_headers(headers) != 0)
    return -1;
  return 0;
}
static int grpc_h3_add_compression_header(SocketGRPC_Call_T call, SocketHTTP_Headers_T headers) {
  if (call->channel->config.enable_request_compression
      && SocketHTTP_Headers_add (headers, "grpc-encoding", GRPC_ENCODING_GZIP) != 0)
    return -1;
  return 0;
}
static int grpc_h3_add_user_agent(SocketGRPC_Call_T call, SocketHTTP_Headers_T headers) {
  if (call->channel->user_agent != NULL
      && SocketHTTP_Headers_add (headers, "user-agent", call->channel->user_agent) != 0)
    return -1;
  return 0;
}
static int grpc_h3_add_timeout(SocketGRPC_Call_T call, SocketHTTP_Headers_T headers) {
  char timeout_buf[GRPC_TIMEOUT_HEADER_MAX];
  if (call->config.deadline_ms > 0)
    {
      if (SocketGRPC_Timeout_format ((int64_t)call->config.deadline_ms,
                                     timeout_buf,
                                     sizeof (timeout_buf))
              != 0
          || SocketHTTP_Headers_add (headers, "grpc-timeout", timeout_buf) != 0)
        return -1;
    }
  return 0;
}
static int grpc_h3_add_retry_attempt(SocketGRPC_Call_T call, SocketHTTP_Headers_T headers) {
  char attempt_buf[16];
  if (call->retry_attempt > 0)
    {
      int n = snprintf (
          attempt_buf, sizeof (attempt_buf), "%u", call->retry_attempt);
      if (n <= 0 || (size_t)n >= sizeof (attempt_buf)
          || SocketHTTP_Headers_add (
                 headers, "grpc-previous-rpc-attempts", attempt_buf)
                 != 0)
        return -1;
    }
  return 0;
}
static int
grpc_h3_add_optional_headers (SocketGRPC_Call_T call,
                              SocketHTTP_Headers_T headers)
{
  if (grpc_h3_add_compression_header(call, headers) != 0)
    return -1;
  if (grpc_h3_add_user_agent(call, headers) != 0)
    return -1;
  if (grpc_h3_add_timeout(call, headers) != 0)
    return -1;
  if (grpc_h3_add_retry_attempt(call, headers) != 0)
    return -1;
  return 0;
}
static int grpc_create_headers(Arena_T arena, SocketHTTP_Headers_T *headers) {
  *headers = SocketHTTP_Headers_new (arena);
  if (*headers == NULL)
    return -1;
  return 0;
}
static int grpc_add_all_headers(SocketGRPC_Call_T call, SocketHTTP_Headers_T headers, const char *host, int port) {
  if (grpc_h3_add_pseudo_headers (call, headers, host, port) != 0)
    return -1;
  if (grpc_h3_add_optional_headers (call, headers) != 0)
    return -1;
  if (grpc_h3_add_metadata_headers (call, headers, call->request_metadata) != 0)
    return -1;
  return 0;
}
static int
grpc_h3_build_request_headers (SocketGRPC_Call_T call,
                               Arena_T arena,
                               const char *host,
                               int port,
                               SocketHTTP_Headers_T *headers_out)
{
  SocketHTTP_Headers_T headers;
  if (call == NULL || arena == NULL || host == NULL || headers_out == NULL)
    return -1;
  *headers_out = NULL;
  if (grpc_create_headers(arena, &headers) != 0)
    return -1;
  if (grpc_add_all_headers(call, headers, host, port) != 0)
    return -1;
  *headers_out = headers;
  return 0;
}
static int
grpc_h3_buffer_append (unsigned char **buffer,
                       size_t *len,
                       size_t *cap,
                       const unsigned char *chunk,
                       size_t chunk_len,
                       size_t max_cap)
{
  size_t needed;
  if (buffer == NULL || len == NULL || cap == NULL
      || (chunk == NULL && chunk_len != 0))
    return -1;
  if (chunk_len == 0)
    return 0;
  needed = *len + chunk_len;
  if (needed > max_cap)
    return -1;
  if (needed > *cap)
    {
      size_t new_cap = (*cap == 0) ? GRPC_STREAM_RECV_BUFFER_INITIAL : *cap;
      unsigned char *tmp;
      while (new_cap < needed)
        {
          if (new_cap > max_cap / 2U)
            {
              new_cap = max_cap;
              break;
            }
          new_cap *= 2U;
        }
      if (new_cap < needed)
        return -1;
      tmp = (unsigned char *)realloc (*buffer, new_cap);
      if (tmp == NULL)
        return -1;
      *buffer = tmp;
      *cap = new_cap;
    }
  memcpy (*buffer + *len, chunk, chunk_len);
  *len += chunk_len;
  return 0;
}
static int
grpc_h3_poll_until_data (SocketHTTP3_Client_T client, int64_t deadline_ms)
{
  int timeout_ms = 25;
  if (deadline_ms > 0)
    {
      int64_t remaining = SocketTimeout_remaining_ms (deadline_ms);
      if (remaining <= 0)
        return -1;
      if (remaining < timeout_ms)
        timeout_ms = (int)remaining;
      if (timeout_ms <= 0)
        timeout_ms = 1;
    }
  return SocketHTTP3_Client_poll (client, timeout_ms) >= 0 ? 0 : -1;
}
static void grpc_cleanup_h3_client(SocketGRPC_H3CallStream *ctx) {
  if (ctx->http3_client != NULL)
    (void)SocketHTTP3_Client_close (ctx->http3_client);
}
static void grpc_cleanup_recv_buffer(SocketGRPC_H3CallStream *ctx) {
  free (ctx->recv_buffer);
  ctx->recv_buffer = NULL;
  ctx->recv_len = 0;
  ctx->recv_cap = 0;
}
static void grpc_cleanup_arena(SocketGRPC_H3CallStream *ctx) {
  if (ctx->arena != NULL)
    Arena_dispose (&ctx->arena);
}
static void
grpc_h3_stream_context_cleanup (SocketGRPC_Call_T call,
                                int success,
                                int cancel_stream)
{
  SocketGRPC_H3CallStream *ctx;
  if (call == NULL)
    return;
  ctx = (SocketGRPC_H3CallStream *)call->h3_stream_ctx;
  if (ctx == NULL)
    return;
  grpc_client_stream_observability_finished (call, ctx);
  if (cancel_stream && ctx->request != NULL)
    (void)SocketHTTP3_Request_cancel (ctx->request);
  grpc_cleanup_h3_client(ctx);
  grpc_cleanup_recv_buffer(ctx);
  grpc_cleanup_arena(ctx);
  free (ctx);
  call->h3_stream_ctx = NULL;
  call->h3_stream_state
      = success ? GRPC_CALL_STREAM_CLOSED : GRPC_CALL_STREAM_FAILED;
}
void
SocketGRPC_Call_h3_stream_abort (SocketGRPC_Call_T call)
{
  if (call == NULL)
    return;
  grpc_h3_stream_context_cleanup (call, 0, 1);
}
static int grpc_h3_stream_fail_set_trailers(SocketGRPC_Call_T call, SocketGRPC_StatusCode status, const char *message) {
  if (call->response_trailers != NULL
      && !SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      (void)SocketGRPC_Trailers_set_status (call->response_trailers, status);
    }
  if (call->response_trailers != NULL && message != NULL && message[0] != '\0'
      && SocketGRPC_Trailers_message (call->response_trailers) == NULL)
    {
      (void)SocketGRPC_Trailers_set_message (call->response_trailers, message);
    }
  return 0;
}
static int
grpc_h3_stream_fail (SocketGRPC_Call_T call,
                     SocketGRPC_StatusCode status,
                     const char *message,
                     int cancel_stream)
{
  if (call == NULL)
    return -1;
  grpc_h3_stream_fail_set_trailers(call, status, message);
  grpc_call_status_set (call, status, message);
  grpc_h3_stream_context_cleanup (call, 0, cancel_stream);
  return -1;
}
static int
grpc_h3_stream_finalize_status (SocketGRPC_Call_T call, int http_status_code)
{
  SocketGRPC_StatusCode status_code;
  if (call == NULL || call->response_trailers == NULL)
    return -1;
  if (!SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      status_code = SocketGRPC_http_status_to_grpc (http_status_code);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                            status_code);
    }
  status_code = (SocketGRPC_StatusCode)SocketGRPC_Trailers_status (
      call->response_trailers);
  grpc_call_status_set (
      call, status_code, SocketGRPC_Trailers_message (call->response_trailers));
  return 0;
}
static int grpc_h3_ingest_trailers(SocketGRPC_Call_T call, SocketHTTP_Headers_T trailers) {
  if (grpc_ingest_response_headers (call, trailers, 1) != 0)
    return -1;
  return 0;
}
static int
grpc_h3_stream_ingest_trailers_if_ready (SocketGRPC_Call_T call,
                                         SocketGRPC_H3CallStream *ctx)
{
  SocketHTTP_Headers_T trailers = NULL;
  if (call == NULL || ctx == NULL || ctx->trailers_ingested)
    return 0;
  if (SocketHTTP3_Request_recv_trailers (ctx->request, &trailers) == 0
      && trailers != NULL)
    {
      if (grpc_h3_ingest_trailers(call, trailers) != 0)
        return -1;
      ctx->trailers_ingested = 1;
    }
  return 0;
}
static SocketGRPC_H3CallStream *grpc_calloc_h3_ctx(void) {
  return (SocketGRPC_H3CallStream *)calloc (1, sizeof (SocketGRPC_H3CallStream));
}
static int grpc_new_arena_for_ctx(SocketGRPC_H3CallStream *ctx) {
  ctx->arena = Arena_new ();
  if (ctx->arena == NULL)
    return -1;
  return 0;
}
static int grpc_create_h3_client(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, const char *host, int port, const char **fail_message) {
  SocketHTTP3_ClientConfig cfg;
  SocketHTTP3_ClientConfig_defaults (&cfg);
  cfg.request_timeout_ms
      = call->config.deadline_ms > 0 ? (uint32_t)call->config.deadline_ms : 0U;
  cfg.verify_peer = call->channel->config.verify_peer;
  cfg.ca_file = call->channel->config.ca_file;
  ctx->http3_client = SocketHTTP3_Client_new (ctx->arena, &cfg);
  if (ctx->http3_client == NULL)
    {
      *fail_message = "HTTP/3 client allocation failed";
      return -1;
    }
  if (SocketHTTP3_Client_connect (ctx->http3_client, host, port) != 0)
    {
      *fail_message = "HTTP/3 connect failed";
      return -1;
    }
  return 0;
}
static int grpc_create_h3_request(SocketGRPC_H3CallStream *ctx, const char **fail_message) {
  ctx->request = SocketHTTP3_Client_new_request (ctx->http3_client);
  if (ctx->request == NULL)
    {
      *fail_message = "HTTP/3 stream request allocation failed";
      return -1;
    }
  return 0;
}
static int grpc_build_and_send_headers(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, const char *host, int port, const char **fail_message) {
  SocketHTTP_Headers_T headers = NULL;
  if (grpc_h3_build_request_headers (call, ctx->arena, host, port, &headers)
      != 0)
    {
      *fail_message = "Failed to build HTTP/3 request headers";
      return -1;
    }
  if (SocketHTTP3_Request_send_headers (ctx->request, headers, 0) != 0
      || SocketHTTP3_Client_flush (ctx->http3_client) != 0)
    {
      *fail_message = "Failed to send HTTP/3 stream headers";
      return -1;
    }
  return 0;
}
static void grpc_init_h3_ctx_fields(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx) {
  ctx->http_status_code = HTTP_STATUS_OK;
  ctx->deadline_ms = SocketTimeout_deadline_ms (call->config.deadline_ms);
  ctx->response_compression = GRPC_COMPRESSION_IDENTITY;
  call->h3_stream_ctx = ctx;
  call->h3_stream_state = GRPC_CALL_STREAM_OPEN;
  SocketGRPC_Trailers_clear (call->response_trailers);
  grpc_call_status_set (call, SOCKET_GRPC_STATUS_OK, NULL);
  grpc_client_stream_observability_started (call, ctx);
}
static void grpc_h3_stream_open_fail(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, const char *fail_message) {
  if (ctx != NULL)
    {
      if (ctx->http3_client != NULL)
        (void)SocketHTTP3_Client_close (ctx->http3_client);
      if (ctx->arena != NULL)
        Arena_dispose (&ctx->arena);
      free (ctx);
    }
  grpc_call_status_set (call, SOCKET_GRPC_STATUS_UNAVAILABLE, fail_message);
}
static SocketGRPC_H3CallStream *
grpc_h3_stream_open_if_needed (SocketGRPC_Call_T call)
{
  SocketGRPC_H3CallStream *ctx;
  char host[GRPC_MAX_HOST_LEN];
  int port;
  const char *fail_message = "Failed to initialize HTTP/3 stream";
  if (call == NULL || call->channel == NULL)
    return NULL;
  ctx = (SocketGRPC_H3CallStream *)call->h3_stream_ctx;
  if (ctx != NULL)
    return ctx;
  if (grpc_h3_parse_target (call->channel->target, host, sizeof (host), &port)
      != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INVALID_ARGUMENT, "Invalid channel target");
      return NULL;
    }
  ctx = grpc_calloc_h3_ctx();
  if (ctx == NULL)
    return NULL;
  if (grpc_new_arena_for_ctx(ctx) != 0) {
    fail_message = "Failed to allocate stream arena";
    goto fail;
  }
  if (grpc_create_h3_client(call, ctx, host, port, &fail_message) != 0)
    goto fail;
  if (grpc_create_h3_request(ctx, &fail_message) != 0)
    goto fail;
  if (grpc_build_and_send_headers(call, ctx, host, port, &fail_message) != 0)
    goto fail;
  grpc_init_h3_ctx_fields(call, ctx);
  return ctx;
fail:
  grpc_h3_stream_open_fail(call, ctx, fail_message);
  return NULL;
}
static int grpc_h3_validate_frame_compression(const SocketGRPC_FrameView *frame, SocketGRPC_StatusCode *error_status, const char **error_message) {
  if (frame->compressed != 0)
    {
      *error_status = SOCKET_GRPC_STATUS_INTERNAL;
      *error_message = "Compressed streaming responses unsupported over HTTP/3";
      return -1;
    }
  return 0;
}
static int grpc_h3_validate_frame_size(const SocketGRPC_FrameView *frame, size_t max_inbound_bytes, SocketGRPC_StatusCode *error_status, const char **error_message) {
  if (frame->payload_len > max_inbound_bytes)
    {
      *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
      *error_message = "Response message exceeds configured limit";
      return -1;
    }
  return 0;
}
static int
grpc_h3_validate_frame (const SocketGRPC_FrameView *frame,
                        size_t max_inbound_bytes,
                        SocketGRPC_StatusCode *error_status,
                        const char **error_message)
{
  if (grpc_h3_validate_frame_compression(frame, error_status, error_message) != 0)
    return -1;
  if (grpc_h3_validate_frame_size(frame, max_inbound_bytes, error_status, error_message) != 0)
    return -1;
  return 0;
}
static int grpc_h3_copy_frame_payload_check_len(const SocketGRPC_FrameView *frame) {
  if (frame->payload_len == 0)
    return 0;
  return 1;
}
static int
grpc_h3_copy_frame_payload (Arena_T arena,
                            const SocketGRPC_FrameView *frame,
                            uint8_t **response_payload,
                            size_t *response_payload_len,
                            SocketGRPC_StatusCode *error_status,
                            const char **error_message)
{
  uint8_t *copy;
  if (grpc_h3_copy_frame_payload_check_len(frame) == 0)
    return 0;
  copy = (uint8_t *)ALLOC (arena, frame->payload_len);
  if (copy == NULL)
    {
      *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
      *error_message = "Out of memory decoding response frame";
      return -1;
    }
  memcpy (copy, frame->payload, frame->payload_len);
  *response_payload = copy;
  *response_payload_len = frame->payload_len;
  return 0;
}
static int grpc_check_parse_message_inputs(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, Arena_T arena, uint8_t **response_payload, size_t *response_payload_len, int *has_message, SocketGRPC_StatusCode *error_status, const char **error_message) {
  if (call == NULL || ctx == NULL || arena == NULL || response_payload == NULL
      || response_payload_len == NULL || has_message == NULL
      || error_status == NULL || error_message == NULL)
    return -1;
  *error_status = SOCKET_GRPC_STATUS_INTERNAL;
  *error_message = "Malformed streaming response frame";
  *has_message = 0;
  if (ctx->recv_len == 0)
    return 0;
  return 1;
}
static int grpc_parse_stream_frame(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, SocketGRPC_FrameView *frame, size_t *consumed, SocketGRPC_StatusCode *error_status, const char **error_message) {
  size_t max_frame_payload = call->channel->config.max_cumulative_inflight_bytes;
  SocketGRPC_WireResult rc;
  if (max_frame_payload == 0)
    max_frame_payload = call->channel->config.max_inbound_message_bytes;
  rc = SocketGRPC_Frame_parse (
      ctx->recv_buffer, ctx->recv_len, max_frame_payload, frame, consumed);
  if (rc == SOCKET_GRPC_WIRE_INCOMPLETE)
    return 0;
  if (rc != SOCKET_GRPC_WIRE_OK)
    {
      if (rc == SOCKET_GRPC_WIRE_LENGTH_EXCEEDED)
        {
          *error_status = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          *error_message
              = "Streaming response exceeds configured inflight limit";
        }
      return -1;
    }
  return 1;
}
static int grpc_validate_and_copy_stream_frame(SocketGRPC_Call_T call, Arena_T arena, const SocketGRPC_FrameView *frame, uint8_t **response_payload, size_t *response_payload_len, SocketGRPC_StatusCode *error_status, const char **error_message) {
  if (grpc_h3_validate_frame (frame,
                              call->channel->config.max_inbound_message_bytes,
                              error_status,
                              error_message)
      != 0)
    return -1;
  if (grpc_h3_copy_frame_payload (arena,
                                  frame,
                                  response_payload,
                                  response_payload_len,
                                  error_status,
                                  error_message)
      != 0)
    return -1;
  return 0;
}
static void grpc_shift_recv_buffer(SocketGRPC_H3CallStream *ctx, size_t consumed) {
  if (consumed < ctx->recv_len)
    {
      memmove (ctx->recv_buffer,
               ctx->recv_buffer + consumed,
               ctx->recv_len - consumed);
    }
  ctx->recv_len -= consumed;
}
static int
grpc_h3_stream_try_parse_message (SocketGRPC_Call_T call,
                                  SocketGRPC_H3CallStream *ctx,
                                  Arena_T arena,
                                  uint8_t **response_payload,
                                  size_t *response_payload_len,
                                  SocketGRPC_StatusCode *error_status,
                                  const char **error_message,
                                  int *has_message)
{
  SocketGRPC_FrameView frame;
  size_t consumed;
  int rc;
  rc = grpc_check_parse_message_inputs(call, ctx, arena, response_payload, response_payload_len, has_message, error_status, error_message);
  if (rc <= 0)
    return rc;
  rc = grpc_parse_stream_frame(call, ctx, &frame, &consumed, error_status, error_message);
  if (rc <= 0)
    return rc;
  if (grpc_validate_and_copy_stream_frame(call, arena, &frame, response_payload, response_payload_len, error_status, error_message) != 0)
    return -1;
  grpc_shift_recv_buffer(ctx, consumed);
  *has_message = 1;
  return 0;
}
static int grpc_intercept_continue(SocketGRPC_ClientStreamInterceptorEntry *entry, SocketGRPC_Call_T call, SocketGRPC_StreamInterceptEvent event, const uint8_t *payload, size_t payload_len, SocketGRPC_Status *status) {
  return entry->interceptor (
          call, event, payload, payload_len, status, entry->userdata);
}
static int grpc_handle_invalid_action(SocketGRPC_Status *status) {
  status->code = SOCKET_GRPC_STATUS_INTERNAL;
  status->message = "Interceptor returned invalid action";
  return 1;
}
static int grpc_handle_invalid_status(SocketGRPC_Status *status) {
  if (!grpc_status_code_valid (status->code)
      || status->code == SOCKET_GRPC_STATUS_OK)
    {
      status->code = SOCKET_GRPC_STATUS_INTERNAL;
      status->message = "Interceptor returned invalid status";
      return 1;
    }
  return 0;
}
static int
grpc_run_client_stream_interceptors (SocketGRPC_Call_T call,
                                     SocketGRPC_StreamInterceptEvent event,
                                     const uint8_t *payload,
                                     size_t payload_len)
{
  SocketGRPC_ClientStreamInterceptorEntry *entry;
  if (call == NULL)
    return -1;
  entry = call->stream_interceptors;
  while (entry != NULL)
    {
      SocketGRPC_Status status
          = { SOCKET_GRPC_STATUS_OK,
              SocketGRPC_status_default_message (SOCKET_GRPC_STATUS_OK) };
      int action = grpc_intercept_continue(entry, call, event, payload, payload_len, &status);
      if (action == SOCKET_GRPC_INTERCEPT_CONTINUE)
        {
          entry = entry->next;
          continue;
        }
      if (action != SOCKET_GRPC_INTERCEPT_STOP)
        grpc_handle_invalid_action(&status);
      if (grpc_handle_invalid_status(&status) != 0)
        return grpc_h3_stream_fail (call, status.code, status.message, 1);
      return grpc_h3_stream_fail (call, status.code, status.message, 1);
    }
  return 0;
}
static int grpc_intercept_unary_continue(SocketGRPC_ClientUnaryInterceptorEntry *entry, SocketGRPC_Call_T call, const uint8_t *request_payload, size_t request_payload_len, SocketGRPC_Status *status) {
  return entry->interceptor (
          call, request_payload, request_payload_len, status, entry->userdata);
}
static int grpc_handle_unary_invalid_action(SocketGRPC_Status *status) {
  status->code = SOCKET_GRPC_STATUS_INTERNAL;
  status->message = "Interceptor returned invalid action";
  return 1;
}
static int grpc_handle_unary_invalid_status(SocketGRPC_Status *status) {
  if (!grpc_status_code_valid (status->code)
      || status->code == SOCKET_GRPC_STATUS_OK)
    {
      status->code = SOCKET_GRPC_STATUS_INTERNAL;
      status->message = "Interceptor returned invalid status";
      return 1;
    }
  return 0;
}
static int grpc_set_trailers_for_intercept(SocketGRPC_Call_T call, SocketGRPC_StatusCode code, const char *message) {
  if (call->response_trailers != NULL)
    {
      SocketGRPC_Trailers_clear (call->response_trailers);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                            code);
      (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                             message);
    }
  return 0;
}
static int
grpc_run_client_unary_interceptors (SocketGRPC_Call_T call,
                                    const uint8_t *request_payload,
                                    size_t request_payload_len)
{
  SocketGRPC_ClientUnaryInterceptorEntry *entry;
  if (call == NULL)
    return -1;
  entry = call->unary_interceptors;
  while (entry != NULL)
    {
      SocketGRPC_Status status
          = { SOCKET_GRPC_STATUS_OK,
              SocketGRPC_status_default_message (SOCKET_GRPC_STATUS_OK) };
      int action = grpc_intercept_unary_continue(entry, call, request_payload, request_payload_len, &status);
      if (action == SOCKET_GRPC_INTERCEPT_CONTINUE)
        {
          entry = entry->next;
          continue;
        }
      if (action != SOCKET_GRPC_INTERCEPT_STOP)
        grpc_handle_unary_invalid_action(&status);
      if (grpc_handle_unary_invalid_status(&status) != 0) {
        grpc_set_trailers_for_intercept(call, status.code, status.message);
        grpc_call_status_set (call, status.code, status.message);
        return -1;
      }
      grpc_set_trailers_for_intercept(call, status.code, status.message);
      grpc_call_status_set (call, status.code, status.message);
      return -1;
    }
  return 0;
}
static int grpc_h3_send_validate_channel(SocketGRPC_Call_T call) {
  if (call->channel == NULL
      || call->channel->config.channel_mode != SOCKET_GRPC_CHANNEL_MODE_HTTP3)
    return -1;
  return 0;
}
static int grpc_h3_send_validate_state(SocketGRPC_Call_T call) {
  if (call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL
      || call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE
      || call->h3_stream_state == GRPC_CALL_STREAM_FAILED)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_FAILED_PRECONDITION,
                            "Send direction already closed");
      return -1;
    }
  return 0;
}
static int grpc_h3_send_validate_compression(SocketGRPC_Call_T call) {
  if (call->channel->config.enable_request_compression)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Request compression over HTTP/3 not supported");
      return -1;
    }
  return 0;
}
static int grpc_h3_send_validate_payload_size(SocketGRPC_Call_T call, size_t request_payload_len) {
  if (request_payload_len > call->channel->config.max_outbound_message_bytes
      || request_payload_len > (size_t)UINT32_MAX)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      return -1;
    }
  return 0;
}
static int
grpc_h3_send_validate_preconditions (SocketGRPC_Call_T call,
                                     const uint8_t *request_payload,
                                     size_t request_payload_len)
{
  if (call == NULL || (request_payload == NULL && request_payload_len != 0))
    return -1;
  if (grpc_h3_send_validate_channel(call) != 0)
    return -1;
  if (grpc_h3_send_validate_state(call) != 0)
    return -1;
  if (grpc_h3_send_validate_compression(call) != 0)
    return -1;
  if (grpc_h3_send_validate_payload_size(call, request_payload_len) != 0)
    return -1;
  return 0;
}
static int grpc_h3_frame_payload(const uint8_t *request_payload, size_t request_payload_len, unsigned char **framed, size_t *framed_len) {
  size_t framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + request_payload_len;
  *framed = (unsigned char *)malloc (framed_cap);
  if (*framed == NULL)
    return -1;
  if (SocketGRPC_Frame_encode (0,
                               request_payload,
                               (uint32_t)request_payload_len,
                               *framed,
                               framed_cap,
                               framed_len)
      != SOCKET_GRPC_WIRE_OK)
    return -1;
  return 0;
}
static int grpc_h3_send_framed(SocketGRPC_H3CallStream *ctx, unsigned char *framed, size_t framed_len) {
  if (SocketHTTP3_Request_send_data (ctx->request, framed, framed_len, 0) != 0
      || SocketHTTP3_Client_flush (ctx->http3_client) != 0)
    return -1;
  return 0;
}
static int
grpc_h3_frame_and_send (SocketGRPC_Call_T call,
                        SocketGRPC_H3CallStream *ctx,
                        const uint8_t *request_payload,
                        size_t request_payload_len)
{
  unsigned char *framed;
  size_t framed_len = 0;
  if (grpc_h3_frame_payload(request_payload, request_payload_len, &framed, &framed_len) != 0)
    {
      free (framed);
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                                  "Out of memory framing message",
                                  1);
    }
  if (grpc_h3_send_framed(ctx, framed, framed_len) != 0)
    {
      free (framed);
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_UNAVAILABLE,
                                  "Failed to send HTTP/3 stream frame",
                                  1);
    }
  free (framed);
  return 0;
}
int
SocketGRPC_Call_h3_send_message (SocketGRPC_Call_T call,
                                 const uint8_t *request_payload,
                                 size_t request_payload_len)
{
  SocketGRPC_H3CallStream *ctx;
  if (grpc_h3_send_validate_preconditions (
          call, request_payload, request_payload_len)
      != 0)
    return -1;
  if (grpc_run_client_stream_interceptors (call,
                                           SOCKET_GRPC_STREAM_INTERCEPT_SEND,
                                           request_payload,
                                           request_payload_len)
      != 0)
    return -1;
  ctx = grpc_h3_stream_open_if_needed (call);
  if (ctx == NULL)
    return -1;
  if (grpc_h3_frame_and_send (call, ctx, request_payload, request_payload_len)
      != 0)
    return -1;
  grpc_client_metrics_bytes_sent (call, request_payload_len);
  return 0;
}
static int grpc_h3_send_close_validate_channel(SocketGRPC_Call_T call) {
  if (call->channel == NULL
      || call->channel->config.channel_mode != SOCKET_GRPC_CHANNEL_MODE_HTTP3)
    return -1;
  return 0;
}
static int grpc_h3_send_close_validate_state(SocketGRPC_Call_T call) {
  if (call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL
      || call->h3_stream_state == GRPC_CALL_STREAM_CLOSED)
    return 0;
  if (call->h3_stream_state == GRPC_CALL_STREAM_FAILED)
    return -1;
  return 1;
}
int
SocketGRPC_Call_h3_close_send (SocketGRPC_Call_T call)
{
  SocketGRPC_H3CallStream *ctx;
  int state_rc;
  if (call == NULL)
    return -1;
  if (grpc_h3_send_close_validate_channel(call) != 0)
    return -1;
  state_rc = grpc_h3_send_close_validate_state(call);
  if (state_rc <= 0)
    return state_rc;
  ctx = grpc_h3_stream_open_if_needed (call);
  if (ctx == NULL)
    return -1;
  if (SocketHTTP3_Request_send_data (ctx->request, NULL, 0, 1) != 0
      || SocketHTTP3_Client_flush (ctx->http3_client) != 0)
    {
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_UNAVAILABLE,
                                  "Failed to close send direction",
                                  1);
    }
  call->h3_stream_state
      = (call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_REMOTE)
            ? GRPC_CALL_STREAM_CLOSED
            : GRPC_CALL_STREAM_HALF_CLOSED_LOCAL;
  return 0;
}
static int grpc_h3_recv_await_headers_poll(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, SocketHTTP_Headers_T *headers, int *status_code) {
  while (SocketHTTP3_Request_recv_headers (ctx->request, headers, status_code)
         != 0)
    {
      if (SocketTimeout_expired (ctx->deadline_ms))
        {
          return grpc_h3_stream_fail (call,
                                      SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                      "Deadline exceeded",
                                      1);
        }
      if (grpc_h3_poll_until_data (ctx->http3_client, ctx->deadline_ms) != 0)
        {
          return grpc_h3_stream_fail (call,
                                      SOCKET_GRPC_STATUS_UNAVAILABLE,
                                      "Failed to receive stream headers",
                                      1);
        }
    }
  return 0;
}
static int grpc_h3_recv_await_headers_ingest(SocketGRPC_Call_T call, SocketHTTP_Headers_T headers) {
  if (grpc_ingest_response_headers (call, headers, 0) != 0)
    {
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_INTERNAL,
                                  "Invalid streaming response headers",
                                  1);
    }
  return 0;
}
static int grpc_h3_recv_await_headers_compression(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, SocketHTTP_Headers_T headers) {
  ctx->response_compression = grpc_response_compression_from_headers (headers);
  if (ctx->response_compression == GRPC_COMPRESSION_UNSUPPORTED)
    {
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_INTERNAL,
                                  "Unsupported response compression encoding",
                                  1);
    }
  if (ctx->response_compression == GRPC_COMPRESSION_GZIP)
    {
      return grpc_h3_stream_fail (
          call,
          SOCKET_GRPC_STATUS_INTERNAL,
          "Compressed streaming responses unsupported over HTTP/3",
          1);
    }
  return 0;
}
static int
grpc_h3_recv_await_headers (SocketGRPC_Call_T call,
                            SocketGRPC_H3CallStream *ctx)
{
  SocketHTTP_Headers_T headers = NULL;
  int status_code = 0;
  if (grpc_h3_recv_await_headers_poll(call, ctx, &headers, &status_code) != 0)
    return -1;
  if (grpc_h3_recv_await_headers_ingest(call, headers) != 0)
    return -1;
  ctx->headers_received = 1;
  ctx->http_status_code = status_code;
  if (grpc_h3_recv_await_headers_compression(call, ctx, headers) != 0)
    return -1;
  return 0;
}
static int grpc_h3_recv_end_of_stream_check_incomplete(SocketGRPC_H3CallStream *ctx) {
  if (ctx->recv_len != 0)
    return -1;
  return 0;
}
static int grpc_h3_recv_end_of_stream_finalize(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx) {
  if (!ctx->status_finalized)
    {
      if (grpc_h3_stream_ingest_trailers_if_ready (call, ctx) != 0)
        {
          return grpc_h3_stream_fail (
              call, SOCKET_GRPC_STATUS_INTERNAL, "Invalid stream trailers", 1);
        }
      grpc_h3_stream_finalize_status (call, ctx->http_status_code);
      ctx->status_finalized = 1;
    }
  return 0;
}
static int
grpc_h3_recv_handle_end_of_stream (SocketGRPC_Call_T call,
                                   SocketGRPC_H3CallStream *ctx,
                                   int *done)
{
  if (grpc_h3_recv_end_of_stream_check_incomplete(ctx) != 0)
    {
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_INTERNAL,
                                  "Incomplete gRPC frame at end of stream",
                                  1);
    }
  if (grpc_h3_recv_end_of_stream_finalize(call, ctx) != 0)
    return -1;
  grpc_h3_stream_context_cleanup (call, 1, 0);
  *done = 1;
  return 0;
}
static int grpc_h3_recv_read_chunk_recv(SocketGRPC_H3CallStream *ctx, unsigned char *chunk, size_t chunk_size, int *end_stream, ssize_t *n) {
  *n = SocketHTTP3_Request_recv_data (
      ctx->request, chunk, chunk_size, end_stream);
  if (*n < 0)
    return -1;
  return 0;
}
static int grpc_h3_recv_read_chunk_append(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, const unsigned char *chunk, ssize_t n) {
  if (n > 0
      && grpc_h3_buffer_append (
             &ctx->recv_buffer,
             &ctx->recv_len,
             &ctx->recv_cap,
             chunk,
             (size_t)n,
             call->channel->config.max_cumulative_inflight_bytes)
             != 0)
    return -1;
  return 0;
}
static int grpc_h3_recv_read_chunk_end_stream(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, int end_stream) {
  if (end_stream)
    {
      call->h3_stream_state
          = (call->h3_stream_state == GRPC_CALL_STREAM_HALF_CLOSED_LOCAL)
                ? GRPC_CALL_STREAM_CLOSED
                : GRPC_CALL_STREAM_HALF_CLOSED_REMOTE;
      ctx->remote_end_stream = 1;
      if (grpc_h3_stream_ingest_trailers_if_ready (call, ctx) != 0)
        {
          return -1;
        }
    }
  return 0;
}
static int grpc_h3_recv_read_chunk_poll(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, ssize_t n, int end_stream) {
  if (n == 0 && !end_stream)
    {
      if (SocketTimeout_expired (ctx->deadline_ms))
        {
          return grpc_h3_stream_fail (call,
                                      SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED,
                                      "Deadline exceeded",
                                      1);
        }
      if (grpc_h3_poll_until_data (ctx->http3_client, ctx->deadline_ms) != 0)
        {
          return grpc_h3_stream_fail (call,
                                      SOCKET_GRPC_STATUS_UNAVAILABLE,
                                      "Failed to advance stream state",
                                      1);
        }
    }
  return 0;
}
static int
grpc_h3_recv_read_chunk (SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx)
{
  unsigned char chunk[GRPC_RESPONSE_CHUNK];
  int end_stream = 0;
  ssize_t n;
  if (grpc_h3_recv_read_chunk_recv(ctx, chunk, sizeof (chunk), &end_stream, &n) != 0)
    {
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_UNAVAILABLE,
                                  "Failed to receive stream body",
                                  1);
    }
  if (grpc_h3_recv_read_chunk_append(call, ctx, chunk, n) != 0)
    {
      return grpc_h3_stream_fail (call,
                                  SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                                  "Streaming response exceeds limit",
                                  1);
    }
  if (grpc_h3_recv_read_chunk_end_stream(call, ctx, end_stream) != 0)
    return -1;
  if (grpc_h3_recv_read_chunk_poll(call, ctx, n, ctx->remote_end_stream) != 0)
    return -1;
  return 0;
}
static int grpc_h3_recv_check_preconditions(SocketGRPC_Call_T call, SocketGRPC_H3CallStream **ctx_out, uint8_t **response_payload, size_t *response_payload_len, int *done) {
  *done = 0;
  *response_payload = NULL;
  *response_payload_len = 0;
  if (call->h3_stream_ctx == NULL)
    {
      if (call->h3_stream_state == GRPC_CALL_STREAM_CLOSED)
        {
          *done = 1;
          return 0;
        }
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_FAILED_PRECONDITION, "Stream not started");
      return -1;
    }
  if (call->h3_stream_state == GRPC_CALL_STREAM_FAILED)
    return -1;
  *ctx_out = (SocketGRPC_H3CallStream *)call->h3_stream_ctx;
  return 0;
}
static int grpc_h3_recv_await_if_needed(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx) {
  if (!ctx->headers_received && grpc_h3_recv_await_headers (call, ctx) != 0)
    return -1;
  return 0;
}
static int grpc_h3_recv_parse_message(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, Arena_T arena, uint8_t **response_payload, size_t *response_payload_len, SocketGRPC_StatusCode *parse_error_status, const char **parse_error_message, int *has_message) {
  if (grpc_h3_stream_try_parse_message (call,
                                        ctx,
                                        arena,
                                        response_payload,
                                        response_payload_len,
                                        parse_error_status,
                                        parse_error_message,
                                        has_message)
      != 0)
    {
      return grpc_h3_stream_fail (
          call, *parse_error_status, *parse_error_message, 1);
    }
  return 0;
}
static int grpc_h3_recv_handle_message(SocketGRPC_Call_T call, uint8_t *response_payload, size_t response_payload_len) {
  if (grpc_run_client_stream_interceptors (
          call,
          SOCKET_GRPC_STREAM_INTERCEPT_RECV,
          response_payload,
          response_payload_len)
      != 0)
    {
      return -1;
    }
  grpc_client_metrics_bytes_received (call, response_payload_len);
  return 0;
}
static int grpc_h3_recv_loop(SocketGRPC_Call_T call, SocketGRPC_H3CallStream *ctx, Arena_T arena, uint8_t **response_payload, size_t *response_payload_len, int *done) {
  for (;;)
    {
      int has_message = 0;
      SocketGRPC_StatusCode parse_error_status = SOCKET_GRPC_STATUS_INTERNAL;
      const char *parse_error_message = "Malformed streaming response frame";
      if (grpc_h3_recv_parse_message(call,
                                     ctx,
                                     arena,
                                     response_payload,
                                     response_payload_len,
                                     &parse_error_status,
                                     &parse_error_message,
                                     &has_message) != 0)
        return -1;
      if (has_message)
        {
          if (grpc_h3_recv_handle_message(call, *response_payload, *response_payload_len) != 0)
            {
              *response_payload = NULL;
              *response_payload_len = 0;
              return -1;
            }
          return 0;
        }
      if (ctx->remote_end_stream)
        return grpc_h3_recv_handle_end_of_stream (call, ctx, done);
      if (grpc_h3_recv_read_chunk (call, ctx) != 0)
        return -1;
    }
}
int
SocketGRPC_Call_h3_recv_message (SocketGRPC_Call_T call,
                                 Arena_T arena,
                                 uint8_t **response_payload,
                                 size_t *response_payload_len,
                                 int *done)
{
  SocketGRPC_H3CallStream *ctx;
  if (call == NULL || arena == NULL || response_payload == NULL
      || response_payload_len == NULL || done == NULL)
    return -1;
  if (grpc_h3_recv_check_preconditions(call, &ctx, response_payload, response_payload_len, done) != 0)
    return -1;
  if (*done)
    return 0;
  if (grpc_h3_recv_await_if_needed(call, ctx) != 0)
    return -1;
  return grpc_h3_recv_loop(call, ctx, arena, response_payload, response_payload_len, done);
}
static int grpc_h3_cancel_set_trailers(SocketGRPC_Call_T call) {
  if (call->response_trailers != NULL
      && !SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                            SOCKET_GRPC_STATUS_CANCELLED);
      (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                             "Call cancelled");
    }
  return 0;
}
int
SocketGRPC_Call_h3_cancel (SocketGRPC_Call_T call)
{
  if (call == NULL)
    return -1;
  grpc_h3_cancel_set_trailers(call);
  grpc_call_status_set (call, SOCKET_GRPC_STATUS_CANCELLED, "Call cancelled");
  if (call->h3_stream_ctx != NULL)
    grpc_h3_stream_context_cleanup (call, 0, 1);
  return 0;
}
static int
grpc_retry_status_is_retryable (const SocketGRPC_RetryPolicy *policy,
                                int status_code)
{
  if (policy == NULL || status_code < 0 || status_code >= 32)
    return 0;
  return (policy->retryable_status_mask & (1U << (unsigned int)status_code))
         != 0;
}
static int64_t
grpc_retry_jittered_backoff_ms (const SocketGRPC_RetryPolicy *policy,
                                int64_t base_backoff_ms)
{
  int64_t wait_ms;
  int64_t jitter;
  int64_t delta = 0;
  if (policy == NULL || base_backoff_ms <= 0)
    return 0;
  wait_ms = base_backoff_ms;
  jitter = (wait_ms * policy->jitter_percent) / 100;
  if (jitter > 0)
    {
      int span = (int)(jitter * 2 + 1);
      delta = (int64_t)(rand () % span) - jitter;
    }
  wait_ms += delta;
  return wait_ms > 0 ? wait_ms : 0;
}
static int64_t
grpc_retry_next_backoff_ms (const SocketGRPC_RetryPolicy *policy,
                            int64_t current_backoff_ms)
{
  int64_t next;
  if (policy == NULL || current_backoff_ms <= 0)
    return 0;
  next = (int64_t)((double)current_backoff_ms * policy->backoff_multiplier);
  if (policy->max_backoff_ms > 0 && next > policy->max_backoff_ms)
    next = policy->max_backoff_ms;
  return next > 0 ? next : 0;
}
static void
grpc_retry_sleep_ms (int64_t delay_ms)
{
  struct timespec req;
  struct timespec rem;
  if (delay_ms <= 0)
    return;
  if (delay_ms > INT_MAX)
    delay_ms = INT_MAX;
  req.tv_sec = (time_t)(delay_ms / 1000);
  req.tv_nsec = (long)((delay_ms % 1000) * 1000000);
  while (nanosleep (&req, &rem) == -1)
    {
      if (errno != EINTR)
        break;
      req = rem;
    }
}
static int grpc_h3_unary_validate_stream_state(SocketGRPC_Call_T call) {
  if (call->h2_stream_ctx != NULL || call->h3_stream_ctx != NULL)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_FAILED_PRECONDITION,
                            "Cannot run unary call while stream is active");
      return -1;
    }
  return 0;
}
static int grpc_h3_unary_validate_channel_mode(SocketGRPC_Call_T call) {
  if (call->channel == NULL
      || call->channel->config.channel_mode != SOCKET_GRPC_CHANNEL_MODE_HTTP3)
    return -1;
  return 0;
}
static int grpc_h3_unary_validate_compression(SocketGRPC_Call_T call) {
  if (call->channel->config.enable_request_compression)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Request compression over HTTP/3 not supported");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }
  return 0;
}
static int grpc_h3_unary_validate_payload_size(SocketGRPC_Call_T call, size_t request_payload_len) {
  if (request_payload_len > call->channel->config.max_outbound_message_bytes
      || request_payload_len > (size_t)UINT32_MAX
      || request_payload_len > (SIZE_MAX - SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE))
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
    }
  return 0;
}
static int grpc_h3_unary_validate_target(SocketGRPC_Call_T call, char *host, size_t host_cap, int *port) {
  if (grpc_h3_parse_target (call->channel->target, host, host_cap, port) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INVALID_ARGUMENT, "Invalid channel target");
      return SOCKET_GRPC_STATUS_INVALID_ARGUMENT;
    }
  return 0;
}
static int
grpc_h3_unary_validate_preconditions (SocketGRPC_Call_T call,
                                      size_t request_payload_len,
                                      char *host,
                                      size_t host_cap,
                                      int *port)
{
  if (grpc_h3_unary_validate_stream_state(call) != 0)
    return -1;
  if (grpc_h3_unary_validate_channel_mode(call) != 0)
    return -1;
  if (grpc_h3_unary_validate_compression(call) != 0)
    return grpc_h3_unary_validate_compression(call);
  if (grpc_h3_unary_validate_payload_size(call, request_payload_len) != 0)
    return grpc_h3_unary_validate_payload_size(call, request_payload_len);
  if (grpc_h3_unary_validate_target(call, host, host_cap, port) != 0)
    return grpc_h3_unary_validate_target(call, host, host_cap, port);
  return 0;
}
static int grpc_h3_unary_setup_config(SocketHTTP3_ClientConfig *cfg, SocketGRPC_Call_T call) {
  SocketHTTP3_ClientConfig_defaults (cfg);
  cfg->request_timeout_ms
      = call->config.deadline_ms > 0 ? (uint32_t)call->config.deadline_ms : 0U;
  cfg->verify_peer = call->channel->config.verify_peer;
  cfg->ca_file = call->channel->config.ca_file;
  return 0;
}
static int grpc_h3_unary_create_client(SocketHTTP3_Client_T *client_out, Arena_T transport_arena, SocketHTTP3_ClientConfig *cfg) {
  *client_out = SocketHTTP3_Client_new (transport_arena, cfg);
  if (*client_out == NULL)
    return -1;
  return 0;
}
static int grpc_h3_unary_connect_client(SocketGRPC_Call_T call, SocketHTTP3_Client_T client, const char *host, int port) {
  if (SocketHTTP3_Client_connect (client, host, port) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Connection failed");
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    }
  return 0;
}
static int grpc_h3_unary_create_request(SocketHTTP3_Request_T *req_out, SocketHTTP3_Client_T client) {
  *req_out = SocketHTTP3_Client_new_request (client);
  if (*req_out == NULL)
    return -1;
  return 0;
}
static int
grpc_h3_unary_setup_transport (SocketGRPC_Call_T call,
                               Arena_T transport_arena,
                               const char *host,
                               int port,
                               SocketHTTP3_Client_T *client_out,
                               SocketHTTP3_Request_T *req_out)
{
  SocketHTTP3_ClientConfig cfg;
  SocketHTTP3_Client_T client;
  SocketHTTP3_Request_T req;
  grpc_h3_unary_setup_config(&cfg, call);
  if (grpc_h3_unary_create_client(&client, transport_arena, &cfg) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "HTTP/3 client allocation failed");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }
  int rc = grpc_h3_unary_connect_client(call, client, host, port);
  if (rc != 0) {
    *client_out = client;
    return rc;
  }
  if (grpc_h3_unary_create_request(&req, client) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Request initialization failed");
      *client_out = client;
      return SOCKET_GRPC_STATUS_INTERNAL;
    }
  *client_out = client;
  *req_out = req;
  return 0;
}
static int grpc_h3_unary_build_and_send_headers(SocketGRPC_Call_T call, Arena_T transport_arena, const char *host, int port, SocketHTTP3_Request_T req) {
  SocketHTTP_Headers_T headers = NULL;
  if (grpc_h3_build_request_headers (
          call, transport_arena, host, port, &headers)
      != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to set request headers");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }
  if (SocketHTTP3_Request_send_headers (req, headers, 0) != 0)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_UNAVAILABLE,
                            "Failed to send request headers");
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    }
  return 0;
}
static int grpc_h3_unary_frame_payload(const uint8_t *request_payload, size_t request_payload_len, unsigned char **framed_out, size_t *framed_len_out) {
  size_t framed_cap = SOCKET_GRPC_WIRE_FRAME_PREFIX_SIZE + request_payload_len;
  unsigned char *framed = (unsigned char *)malloc (framed_cap);
  size_t framed_len = 0;
  if (framed == NULL)
    return -1;
  if (SocketGRPC_Frame_encode (0,
                               request_payload,
                               (uint32_t)request_payload_len,
                               framed,
                               framed_cap,
                               &framed_len)
      != SOCKET_GRPC_WIRE_OK)
    return -1;
  *framed_out = framed;
  *framed_len_out = framed_len;
  return 0;
}
static int grpc_h3_unary_send_framed(SocketGRPC_Call_T call, SocketHTTP3_Client_T client, SocketHTTP3_Request_T req, unsigned char *framed, size_t framed_len) {
  if (SocketHTTP3_Request_send_data (req, framed, framed_len, 1) != 0
      || SocketHTTP3_Client_flush (client) != 0)
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_UNAVAILABLE, "Failed to send request body");
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    }
  return 0;
}
static int
grpc_h3_unary_send_request (SocketGRPC_Call_T call,
                            Arena_T transport_arena,
                            SocketHTTP3_Client_T client,
                            SocketHTTP3_Request_T req,
                            const char *host,
                            int port,
                            const uint8_t *request_payload,
                            size_t request_payload_len,
                            unsigned char **framed_out)
{
  int status;
  unsigned char *framed;
  size_t framed_len;
  status = grpc_h3_unary_build_and_send_headers(call, transport_arena, host, port, req);
  if (status != 0)
    return status;
  status = grpc_h3_unary_frame_payload(request_payload, request_payload_len, &framed, &framed_len);
  if (status != 0) {
    grpc_call_status_set (call, SOCKET_GRPC_STATUS_INTERNAL, "Failed to frame request payload");
    free (framed);
    return SOCKET_GRPC_STATUS_INTERNAL;
  }
  *framed_out = framed;
  status = grpc_h3_unary_send_framed(call, client, req, framed, framed_len);
  if (status != 0)
    return status;
  return 0;
}
static int grpc_h3_unary_await_response_check_state(SocketHTTP3_Request_T req) {
  if (SocketHTTP3_Request_recv_state (req) == H3_REQ_RECV_COMPLETE)
    return 0;
  return 1;
}
static int grpc_h3_unary_await_response_check_deadline(SocketGRPC_Call_T call, int64_t deadline_ms) {
  if (call->config.deadline_ms > 0 && SocketTimeout_expired (deadline_ms))
    {
      grpc_call_status_set (
          call, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED, "Deadline exceeded");
      return SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
    }
  return 0;
}
static int grpc_h3_unary_await_response_poll(SocketHTTP3_Client_T client, int64_t deadline_ms) {
  if (grpc_h3_poll_until_data (client, deadline_ms) != 0)
    return -1;
  return 0;
}
static int
grpc_h3_unary_await_response (SocketGRPC_Call_T call,
                              SocketHTTP3_Client_T client,
                              SocketHTTP3_Request_T req,
                              int64_t deadline_ms)
{
  for (;;)
    {
      if (grpc_h3_unary_await_response_check_state(req) == 0)
        break;
      int rc = grpc_h3_unary_await_response_check_deadline(call, deadline_ms);
      if (rc != 0)
        return rc;
      if (grpc_h3_unary_await_response_poll(client, deadline_ms) != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Failed to receive response");
          return SOCKET_GRPC_STATUS_UNAVAILABLE;
        }
    }
  return 0;
}
static int grpc_h3_unary_recv_headers(SocketHTTP3_Request_T req, SocketHTTP_Headers_T *response_headers, int *status_code) {
  if (SocketHTTP3_Request_recv_headers (req, response_headers, status_code)
          != 0
      || *response_headers == NULL)
    return -1;
  return 0;
}
static int grpc_h3_unary_ingest_headers(SocketGRPC_Call_T call, SocketHTTP_Headers_T response_headers) {
  if (grpc_ingest_response_headers (call, response_headers, 1) != 0)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Invalid response header metadata");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }
  return 0;
}
static int grpc_h3_unary_check_compression(SocketGRPC_Call_T call, SocketHTTP_Headers_T response_headers) {
  SocketGRPC_Compression comp = grpc_response_compression_from_headers (response_headers);
  if (comp == GRPC_COMPRESSION_UNSUPPORTED)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Unsupported response compression encoding");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }
  if (comp == GRPC_COMPRESSION_GZIP)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_INTERNAL,
                            "Compressed responses unsupported over HTTP/3");
      return SOCKET_GRPC_STATUS_INTERNAL;
    }
  return 0;
}
static int
grpc_h3_unary_validate_response_headers (SocketGRPC_Call_T call,
                                         SocketHTTP3_Request_T req,
                                         SocketHTTP_Headers_T *headers_out,
                                         int *status_code)
{
  SocketHTTP_Headers_T response_headers = NULL;
  if (grpc_h3_unary_recv_headers(req, &response_headers, status_code) != 0)
    {
      grpc_call_status_set (call,
                            SOCKET_GRPC_STATUS_UNAVAILABLE,
                            "Failed to receive response headers");
      return SOCKET_GRPC_STATUS_UNAVAILABLE;
    }
  int rc = grpc_h3_unary_ingest_headers(call, response_headers);
  if (rc != 0)
    return rc;
  rc = grpc_h3_unary_check_compression(call, response_headers);
  if (rc != 0)
    return rc;
  *headers_out = response_headers;
  return 0;
}
static int grpc_h3_unary_recv_body_read(SocketHTTP3_Request_T req, unsigned char *chunk, size_t chunk_size, int *end_stream, ssize_t *n) {
  *n = SocketHTTP3_Request_recv_data (
      req, chunk, chunk_size, end_stream);
  if (*n < 0)
    return -1;
  return 0;
}
static int grpc_h3_unary_recv_body_append(SocketGRPC_Call_T call, unsigned char **raw_response, size_t *raw_response_len, size_t *raw_response_cap, const unsigned char *chunk, ssize_t n) {
  if (n > 0
      && grpc_h3_buffer_append (
                 raw_response,
                 raw_response_len,
                 raw_response_cap,
                 chunk,
                 (size_t)n,
                 call->channel->config.max_cumulative_inflight_bytes)
                 != 0)
    return -1;
  return 0;
}
static int grpc_h3_unary_recv_body_poll(SocketHTTP3_Client_T client, int64_t deadline_ms, ssize_t n, int end_stream) {
  if (n == 0 && !end_stream)
    {
      if (grpc_h3_poll_until_data (client, deadline_ms) != 0)
        return -1;
    }
  return 0;
}
static int
grpc_h3_unary_recv_body (SocketGRPC_Call_T call,
                         SocketHTTP3_Client_T client,
                         SocketHTTP3_Request_T req,
                         int64_t deadline_ms,
                         unsigned char **raw_response,
                         size_t *raw_response_len,
                         size_t *raw_response_cap)
{
  for (;;)
    {
      unsigned char chunk[GRPC_RESPONSE_CHUNK];
      int end_stream = 0;
      ssize_t n;
      if (grpc_h3_unary_recv_body_read(req, chunk, sizeof (chunk), &end_stream, &n) != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Failed to receive response body");
          return SOCKET_GRPC_STATUS_UNAVAILABLE;
        }
      if (grpc_h3_unary_recv_body_append(call, raw_response, raw_response_len, raw_response_cap, chunk, n) != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED,
                                "Response exceeds configured inflight limit");
          return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
        }
      if (end_stream)
        break;
      if (grpc_h3_unary_recv_body_poll(client, deadline_ms, n, end_stream) != 0)
        {
          grpc_call_status_set (call,
                                SOCKET_GRPC_STATUS_UNAVAILABLE,
                                "Failed to advance response stream");
          return SOCKET_GRPC_STATUS_UNAVAILABLE;
        }
    }
  return 0;
}
static int grpc_h3_unary_ingest_trailers(SocketGRPC_Call_T call, SocketHTTP3_Request_T req) {
  SocketHTTP_Headers_T response_trailers = NULL;
  if (SocketHTTP3_Request_recv_trailers (req, &response_trailers) == 0
      && response_trailers != NULL)
    {
      if (grpc_ingest_response_headers (call, response_trailers, 1) != 0)
        {
          grpc_call_status_set (
              call, SOCKET_GRPC_STATUS_INTERNAL, "Invalid response trailers");
          return SOCKET_GRPC_STATUS_INTERNAL;
        }
    }
  return 0;
}
static int grpc_h3_unary_finalize_status(SocketGRPC_Call_T call, int status_code) {
  if (!SocketGRPC_Trailers_has_status (call->response_trailers))
    {
      SocketGRPC_StatusCode mapped
          = SocketGRPC_http_status_to_grpc (status_code);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers, mapped);
    }
  status_code = SocketGRPC_Trailers_status (call->response_trailers);
  grpc_call_status_set (call,
                        (SocketGRPC_StatusCode)status_code,
                        SocketGRPC_Trailers_message (call->response_trailers));
  return status_code;
}
static int
grpc_h3_unary_process_trailers (SocketGRPC_Call_T call,
                                SocketHTTP3_Request_T req,
                                int status_code)
{
  int rc = grpc_h3_unary_ingest_trailers(call, req);
  if (rc != 0)
    return rc;
  return grpc_h3_unary_finalize_status(call, status_code);
}
static int grpc_h3_unary_parse_frame(SocketGRPC_Call_T call, const unsigned char *raw_response, size_t raw_response_len, SocketGRPC_FrameView *frame, size_t *consumed, size_t max_frame_payload) {
  SocketGRPC_WireResult parse_rc = SocketGRPC_Frame_parse (
      raw_response, raw_response_len, max_frame_payload, frame, consumed);
  if (parse_rc != SOCKET_GRPC_WIRE_OK || *consumed != raw_response_len)
    return -1;
  return 0;
}
static int grpc_h3_unary_handle_parse_error(SocketGRPC_Call_T call, SocketGRPC_WireResult parse_rc, const char **decode_message, int *status_code) {
  *decode_message = parse_rc == SOCKET_GRPC_WIRE_LENGTH_EXCEEDED
                       ? "Response exceeds configured inflight limit"
                       : "Malformed gRPC response frame";
  *status_code = parse_rc == SOCKET_GRPC_WIRE_LENGTH_EXCEEDED
                    ? SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED
                    : SOCKET_GRPC_STATUS_INTERNAL;
  grpc_call_status_set (call, *status_code, *decode_message);
  (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                        *status_code);
  (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                         *decode_message);
  return *status_code;
}
static int grpc_h3_unary_check_compressed(SocketGRPC_Call_T call, const SocketGRPC_FrameView *frame, const char **decode_message, int *status_code) {
  if (frame->compressed != 0)
    {
      *status_code = SOCKET_GRPC_STATUS_INTERNAL;
      *decode_message = "Compressed responses unsupported over HTTP/3";
      grpc_call_status_set (call, *status_code, *decode_message);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                            *status_code);
      (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                             *decode_message);
      return *status_code;
    }
  return 0;
}
static int grpc_h3_unary_check_payload_size(SocketGRPC_Call_T call, const SocketGRPC_FrameView *frame, const char **decode_message, int *status_code) {
  if (frame->payload_len > call->channel->config.max_inbound_message_bytes)
    {
      *status_code = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
      *decode_message = "Response message exceeds configured limit";
      grpc_call_status_set (call, *status_code, *decode_message);
      (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                            *status_code);
      (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                             *decode_message);
      return *status_code;
    }
  return 0;
}
static int grpc_h3_unary_copy_payload(Arena_T arena, const SocketGRPC_FrameView *frame, uint8_t **response_payload, size_t *response_payload_len, int *status_code) {
  if (frame->payload_len > 0)
    {
      uint8_t *copy = (uint8_t *)ALLOC (arena, frame->payload_len);
      if (copy == NULL)
        {
          *status_code = SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
          return *status_code;
        }
      memcpy (copy, frame->payload, frame->payload_len);
      *response_payload = copy;
      *response_payload_len = frame->payload_len;
    }
  return 0;
}
static int
grpc_h3_unary_decode_response_frame (SocketGRPC_Call_T call,
                                     Arena_T arena,
                                     const unsigned char *raw_response,
                                     size_t raw_response_len,
                                     uint8_t **response_payload,
                                     size_t *response_payload_len)
{
  SocketGRPC_FrameView frame;
  size_t consumed = 0;
  size_t max_frame_payload = call->channel->config.max_cumulative_inflight_bytes;
  const char *decode_message = NULL;
  int status_code;
  if (max_frame_payload == 0)
    max_frame_payload = call->channel->config.max_inbound_message_bytes;
  if (grpc_h3_unary_parse_frame(call, raw_response, raw_response_len, &frame, &consumed, max_frame_payload) != 0)
    return grpc_h3_unary_handle_parse_error(call, SOCKET_GRPC_WIRE_INCOMPLETE, &decode_message, &status_code);
  if (grpc_h3_unary_check_compressed(call, &frame, &decode_message, &status_code) != 0)
    return status_code;
  if (grpc_h3_unary_check_payload_size(call, &frame, &decode_message, &status_code) != 0)
    return status_code;
  if (grpc_h3_unary_copy_payload(arena, &frame, response_payload, response_payload_len, &status_code) != 0) {
    grpc_call_status_set (call, status_code, NULL);
    (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                          status_code);
    return status_code;
  }
  return SOCKET_GRPC_STATUS_OK;
}
static int grpc_init_transport_for_unary(SocketGRPC_Call_T call, char *host, int port, Arena_T *transport_arena, SocketHTTP3_Client_T *client, SocketHTTP3_Request_T *req) {
  *transport_arena = Arena_new ();
  if (*transport_arena == NULL)
    {
      grpc_call_status_set (call, SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED, NULL);
      return SOCKET_GRPC_STATUS_RESOURCE_EXHAUSTED;
    }
  return grpc_h3_unary_setup_transport (
      call, *transport_arena, host, port, client, req);
}
static int grpc_send_unary_request(SocketGRPC_Call_T call, Arena_T transport_arena, SocketHTTP3_Client_T client, SocketHTTP3_Request_T req, const char *host, int port, const uint8_t *request_payload, size_t request_payload_len, unsigned char **framed) {
  return grpc_h3_unary_send_request (call,
                                     transport_arena,
                                     client,
                                     req,
                                     host,
                                     port,
                                     request_payload,
                                     request_payload_len,
                                     framed);
}
static int grpc_receive_unary_response(SocketGRPC_Call_T call, SocketHTTP3_Client_T client, SocketHTTP3_Request_T req, int64_t deadline_ms, unsigned char **raw_response, size_t *raw_response_len, size_t *raw_response_cap, int *http_status) {
  int status_code = grpc_h3_unary_await_response (call, client, req, deadline_ms);
  if (status_code != 0)
    return status_code;
  SocketHTTP_Headers_T headers_out;
  status_code = grpc_h3_unary_validate_response_headers (
      call, req, &headers_out, http_status);
  if (status_code != 0)
    return status_code;
  status_code = grpc_h3_unary_recv_body (call,
                                         client,
                                         req,
                                         deadline_ms,
                                         raw_response,
                                         raw_response_len,
                                         raw_response_cap);
  if (status_code != 0)
    return status_code;
  return 0;
}
static int grpc_process_unary_trailers(SocketGRPC_Call_T call, SocketHTTP3_Request_T req, int http_status) {
  return grpc_h3_unary_process_trailers (call, req, http_status);
}
static int grpc_decode_unary_response(SocketGRPC_Call_T call, Arena_T arena, unsigned char *raw_response, size_t raw_response_len, uint8_t **response_payload, size_t *response_payload_len) {
  return grpc_h3_unary_decode_response_frame (call,
                                              arena,
                                              raw_response,
                                              raw_response_len,
                                              response_payload,
                                              response_payload_len);
}
static int
grpc_call_unary_h3_single_attempt (SocketGRPC_Call_T call,
                                   const uint8_t *request_payload,
                                   size_t request_payload_len,
                                   Arena_T arena,
                                   uint8_t **response_payload,
                                   size_t *response_payload_len)
{
  Arena_T transport_arena = NULL;
  SocketHTTP3_Client_T client = NULL;
  SocketHTTP3_Request_T req = NULL;
  unsigned char *framed = NULL;
  unsigned char *raw_response = NULL;
  size_t raw_response_len = 0;
  size_t raw_response_cap = 0;
  char host[GRPC_MAX_HOST_LEN];
  int port;
  int status_code;
  int http_status = 0;
  int rc;
  int64_t deadline_ms = SocketTimeout_deadline_ms (call->config.deadline_ms);
  if (call == NULL || request_payload == NULL || arena == NULL
      || response_payload == NULL || response_payload_len == NULL)
    return -1;
  rc = grpc_h3_unary_validate_preconditions (
      call, request_payload_len, host, sizeof (host), &port);
  if (rc != 0)
    return rc;
  *response_payload = NULL;
  *response_payload_len = 0;
  SocketGRPC_Trailers_clear (call->response_trailers);
  status_code = grpc_init_transport_for_unary(call, host, port, &transport_arena, &client, &req);
  if (status_code != 0)
    goto cleanup;
  status_code = grpc_send_unary_request(call, transport_arena, client, req, host, port, request_payload, request_payload_len, &framed);
  if (status_code != 0)
    goto cleanup;
  status_code = grpc_receive_unary_response(call, client, req, deadline_ms, &raw_response, &raw_response_len, &raw_response_cap, &http_status);
  if (status_code != 0)
    goto cleanup;
  status_code = grpc_process_unary_trailers(call, req, http_status);
  if (status_code != SOCKET_GRPC_STATUS_OK)
    goto cleanup;
  if (raw_response != NULL && raw_response_len > 0)
    {
      status_code = grpc_decode_unary_response(call, arena, raw_response, raw_response_len, response_payload, response_payload_len);
    }
  else
    {
      *response_payload = NULL;
      *response_payload_len = 0;
    }
cleanup:
  free (raw_response);
  free (framed);
  if (client != NULL)
    (void)SocketHTTP3_Client_close (client);
  if (transport_arena != NULL)
    Arena_dispose (&transport_arena);
  return status_code;
}
static void
grpc_h3_set_deadline_exceeded (SocketGRPC_Call_T call)
{
  grpc_call_status_set (
      call, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED, "Deadline exceeded");
  (void)SocketGRPC_Trailers_set_status (call->response_trailers,
                                        SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED);
  (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                         "Deadline exceeded");
}
static int
grpc_h3_retry_update_deadline (SocketGRPC_Call_T call,
                               int64_t call_deadline_ms,
                               int original_deadline_ms)
{
  if (call_deadline_ms > 0)
    {
      int64_t remaining = SocketTimeout_remaining_ms (call_deadline_ms);
      if (remaining <= 0)
        return -1;
      call->config.deadline_ms
          = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
    }
  else
    {
      call->config.deadline_ms = original_deadline_ms;
    }
  return 0;
}
static int grpc_h3_retry_wait_check_deadline(int64_t call_deadline_ms, int64_t *wait_ms) {
  if (call_deadline_ms > 0)
    {
      int64_t remaining = SocketTimeout_remaining_ms (call_deadline_ms);
      if (remaining <= 0)
        return -1;
      if (*wait_ms > remaining)
        *wait_ms = remaining;
    }
  return 0;
}
static int
grpc_h3_retry_wait_and_backoff (SocketGRPC_Call_T call,
                                const SocketGRPC_RetryPolicy *policy,
                                int64_t call_deadline_ms,
                                int64_t *backoff_ms,
                                int attempt)
{
  int64_t wait_ms = grpc_retry_jittered_backoff_ms (policy, *backoff_ms);
  if (grpc_h3_retry_wait_check_deadline(call_deadline_ms, &wait_ms) != 0)
    return -1;
  grpc_client_observability_call_retry (call, (uint32_t)(attempt + 1));
  if (wait_ms > 0)
    grpc_retry_sleep_ms (wait_ms);
  *backoff_ms = grpc_retry_next_backoff_ms (policy, *backoff_ms);
  return 0;
}
static int grpc_h3_retry_loop_init(SocketGRPC_Call_T call, int original_deadline_ms, int64_t *call_deadline_ms, int64_t *backoff_ms, const SocketGRPC_RetryPolicy *policy) {
  *call_deadline_ms = SocketTimeout_deadline_ms (original_deadline_ms);
  *backoff_ms = policy->initial_backoff_ms;
  call->retry_in_progress = 1;
  call->retry_attempt = 0;
  return 0;
}
static int grpc_h3_retry_loop_check_timeout(int64_t call_deadline_ms) {
  if (SocketTimeout_expired (call_deadline_ms))
    return -1;
  return 0;
}
static int grpc_h3_retry_loop_attempt(SocketGRPC_Call_T call, const uint8_t *request_payload, size_t request_payload_len, Arena_T arena, uint8_t **response_payload, size_t *response_payload_len, int *status_code) {
  int rc = grpc_call_unary_h3_single_attempt (call,
                                              request_payload,
                                              request_payload_len,
                                              arena,
                                              response_payload,
                                              response_payload_len);
  *status_code = (rc >= 0) ? rc : (int)SocketGRPC_Call_status (call).code;
  return rc;
}
static int grpc_h3_retry_loop_should_break(int attempt, int max_attempts, int status_code) {
  if (attempt >= max_attempts)
    return 1;
  if (status_code == SOCKET_GRPC_STATUS_CANCELLED
      || status_code == SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED)
    return 1;
  return 0;
}
static int grpc_h3_retry_loop_backoff(SocketGRPC_Call_T call, const SocketGRPC_RetryPolicy *policy, int64_t call_deadline_ms, int64_t *backoff_ms, int attempt) {
  if (grpc_h3_retry_wait_and_backoff (
          call, policy, call_deadline_ms, backoff_ms, attempt)
      != 0)
    return -1;
  return 0;
}
static int
grpc_h3_retry_loop (SocketGRPC_Call_T call,
                    const SocketGRPC_RetryPolicy *policy,
                    int max_attempts,
                    const uint8_t *request_payload,
                    size_t request_payload_len,
                    Arena_T arena,
                    uint8_t **response_payload,
                    size_t *response_payload_len,
                    uint32_t *finish_attempt)
{
  int original_deadline_ms = call->config.deadline_ms;
  int64_t call_deadline_ms;
  int64_t backoff_ms;
  int rc = -1;
  int attempt;
  grpc_h3_retry_loop_init(call, original_deadline_ms, &call_deadline_ms, &backoff_ms, policy);
  for (attempt = 1; attempt <= max_attempts; attempt++)
    {
      int status_code;
      *finish_attempt = (uint32_t)attempt;
      if (grpc_h3_retry_loop_check_timeout(call_deadline_ms) != 0
          || grpc_h3_retry_update_deadline (call, call_deadline_ms, original_deadline_ms) != 0)
        {
          rc = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
          grpc_h3_set_deadline_exceeded (call);
          break;
        }
      call->retry_attempt = (uint32_t)(attempt - 1);
      rc = grpc_h3_retry_loop_attempt(call, request_payload, request_payload_len, arena, response_payload, response_payload_len, &status_code);
      if (grpc_h3_retry_loop_should_break(attempt, max_attempts, status_code) != 0)
        break;
      if (!grpc_retry_status_is_retryable (policy, status_code))
        break;
      if (grpc_h3_retry_loop_backoff(call, policy, call_deadline_ms, &backoff_ms, attempt) != 0)
        {
          rc = SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED;
          break;
        }
    }
  if (rc == SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED)
    {
      (void)SocketGRPC_Trailers_set_status (
          call->response_trailers, SOCKET_GRPC_STATUS_DEADLINE_EXCEEDED);
      (void)SocketGRPC_Trailers_set_message (call->response_trailers,
                                             "Deadline exceeded");
    }
  call->config.deadline_ms = original_deadline_ms;
  call->retry_attempt = 0;
  call->retry_in_progress = 0;
  return rc;
}
static int grpc_setup_retry_policy(SocketGRPC_Call_T call, SocketGRPC_RetryPolicy *policy, int *max_attempts) {
  *policy = call->config.retry_policy;
  if (SocketGRPC_RetryPolicy_validate (policy) != 0)
    SocketGRPC_RetryPolicy_defaults (policy);
  *max_attempts = 1;
  if (call->channel != NULL && call->channel->client != NULL
      && call->channel->client->config.enable_retry && !call->retry_in_progress)
    *max_attempts = policy->max_attempts;
  return 0;
}
static int grpc_unary_h3_start_observability(SocketGRPC_Call_T call, size_t request_payload_len, int *observability_started, int64_t *call_started_ms) {
  *call_started_ms = SocketTimeout_now_ms ();
  *observability_started = grpc_client_observability_enabled (call);
  grpc_client_observability_call_started (call, request_payload_len, 1U);
  return 0;
}
static int grpc_unary_h3_run_interceptors(SocketGRPC_Call_T call, const uint8_t *request_payload, size_t request_payload_len) {
  if (grpc_run_client_unary_interceptors (
          call, request_payload, request_payload_len)
      != 0)
    return (int)SocketGRPC_Call_status (call).code;
  return 0;
}
static int grpc_unary_h3_single_attempt(SocketGRPC_Call_T call, const uint8_t *request_payload, size_t request_payload_len, Arena_T arena, uint8_t **response_payload, size_t *response_payload_len) {
  return grpc_call_unary_h3_single_attempt (call,
                                            request_payload,
                                            request_payload_len,
                                            arena,
                                            response_payload,
                                            response_payload_len);
}
static int grpc_unary_h3_retry_attempt(SocketGRPC_Call_T call, const uint8_t *request_payload, size_t request_payload_len, Arena_T arena, uint8_t **response_payload, size_t *response_payload_len, const SocketGRPC_RetryPolicy *policy, int max_attempts, uint32_t *finish_attempt) {
  return grpc_h3_retry_loop (call,
                             policy,
                             max_attempts,
                             request_payload,
                             request_payload_len,
                             arena,
                             response_payload,
                             response_payload_len,
                             finish_attempt);
}
static void grpc_unary_h3_finish_metrics(SocketGRPC_Call_T call, int rc, size_t response_payload_len, int observability_started, int64_t call_started_ms, uint32_t finish_attempt) {
  if (rc == SOCKET_GRPC_STATUS_OK && response_payload_len > 0)
    grpc_client_metrics_bytes_received (call, response_payload_len);
  if (observability_started)
    {
      grpc_client_observability_call_finished (
          call, call_started_ms, response_payload_len, finish_attempt);
    }
}
int
SocketGRPC_Call_unary_h3 (SocketGRPC_Call_T call,
                          const uint8_t *request_payload,
                          size_t request_payload_len,
                          Arena_T arena,
                          uint8_t **response_payload,
                          size_t *response_payload_len)
{
  SocketGRPC_RetryPolicy policy;
  int max_attempts;
  int rc = -1;
  int64_t call_started_ms;
  uint32_t finish_attempt = 1U;
  int observability_started = 0;
  if (call == NULL || request_payload == NULL || arena == NULL
      || response_payload == NULL || response_payload_len == NULL)
    return -1;
  *response_payload = NULL;
  *response_payload_len = 0;
  grpc_unary_h3_start_observability(call, request_payload_len, &observability_started, &call_started_ms);
  rc = grpc_unary_h3_run_interceptors(call, request_payload, request_payload_len);
  if (rc != 0)
    goto finish;
  grpc_client_metrics_bytes_sent (call, request_payload_len);
  grpc_setup_retry_policy(call, &policy, &max_attempts);
  if (max_attempts <= 1)
    {
      rc = grpc_unary_h3_single_attempt(call, request_payload, request_payload_len, arena, response_payload, response_payload_len);
      goto finish;
    }
  rc = grpc_unary_h3_retry_attempt(call, request_payload, request_payload_len, arena, response_payload, response_payload_len, &policy, max_attempts, &finish_attempt);
finish:
  grpc_unary_h3_finish_metrics(call, rc, *response_payload_len, observability_started, call_started_ms, finish_attempt);
  return rc;
}
#endif /* SOCKET_HAS_TLS */