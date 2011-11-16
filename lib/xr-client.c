/*
 * Libxr.
 *
 * Copyright (C) 2008-2010 Zonio s.r.o <developers@zonio.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#ifndef HAVE_GLIB_REGEXP
#include <regex.h>
#endif

#ifdef WIN32
  #include <winsock2.h>
#else
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <arpa/inet.h>
  #include <netinet/tcp.h>
  #include <signal.h>
#endif

#include "xr-client.h"
#include "xr-http.h"
#include "xr-utils.h"

/* OpenSSL 1.0.0 supports IPv6 in BIO.  If we are using OpenSSL with
 * version lower than 1.0.0, we must setup IPv6 socket ourself.
 *
 * The approach is to create an IPv6 socket and bind it to a BIO.
 */

#if !defined WIN32 && OPENSSL_VERSION_NUMBER < 0x10000000L
#  define XR_CHECK_IPV6
#endif

/*
 * OpenSSL 1.0.0 should handle client IPv6 cnnections in BIO, but it still
 * doesn't work. Because of that there is hard switch which turns on
 * extern IPv6 socket creation.
 */
#define XR_CHECK_IPV6

struct _xr_client_conn
{
  SSL_CTX* ctx;
  BIO* bio;
  xr_http* http;

  char* resource;
  char* host;
  char* session_id;
  int secure;

  int is_open;
  GHashTable* headers;
  xr_call_transport transport;
};

xr_client_conn* xr_client_new(GError** err)
{
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  xr_trace(XR_DEBUG_CLIENT_TRACE, "(err=%p)", err);

  xr_init();

  xr_client_conn* conn = g_new0(xr_client_conn, 1);
  conn->ctx = SSL_CTX_new(TLSv1_client_method());
  if (conn->ctx == NULL)
  {
    g_free(conn);
    g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_FAILED, "ssl context creation failed: %s", ERR_reason_error_string(ERR_get_error()));
    return NULL;
  }

  conn->headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  conn->transport = XR_CALL_XML_RPC;

  return conn;
}

SSL_CTX* xr_client_get_ssl_context(xr_client_conn* conn)
{
  g_return_val_if_fail(conn != NULL, NULL);
  g_return_val_if_fail(!conn->is_open, NULL);

  return conn->ctx;
}

#ifndef HAVE_GLIB_REGEXP

static gboolean _parse_uri(const char* uri, int* secure, char** host, char** resource)
{
  regex_t r;
  regmatch_t m[7];
  gint rs;

  g_return_val_if_fail(uri != NULL, FALSE);
  g_return_val_if_fail(secure != NULL, FALSE);
  g_return_val_if_fail(host != NULL, FALSE);
  g_return_val_if_fail(resource != NULL, FALSE);

  if ((rs = regcomp(&r, "^([a-z]+)://([a-z0-9.:-]+(:(:)?([0-9]+))?)(/.+)?$", REG_EXTENDED | REG_ICASE)))
    return FALSE;
  rs = regexec(&r, uri, 7, m, 0);
  regfree(&r);
  if (rs != 0)
    return FALSE;
  
  char* schema = g_strndup(uri + m[1].rm_so, m[1].rm_eo - m[1].rm_so);
  if (!g_ascii_strcasecmp("http", schema))
    *secure = 0;
  else if (!g_ascii_strcasecmp("https", schema))
    *secure = 1;
  else
  {
    g_free(schema);
    return FALSE;
  }
  g_free(schema);
  
  *host = g_strndup(uri + m[2].rm_so, m[2].rm_eo - m[2].rm_so);
  if (m[5].rm_eo - m[5].rm_so == 0)
    *resource = g_strdup("/RPC2");
  else
    *resource = g_strndup(uri + m[5].rm_so, m[5].rm_eo - m[5].rm_so);
  
  return TRUE;
}

#else

G_LOCK_DEFINE_STATIC(regex);

static gboolean _parse_uri(const char* uri, int* secure, char** host, char** resource)
{
  static GRegex* regex = NULL;
  GMatchInfo *match_info = NULL;

  g_return_val_if_fail(uri != NULL, FALSE);
  g_return_val_if_fail(secure != NULL, FALSE);
  g_return_val_if_fail(host != NULL, FALSE);
  g_return_val_if_fail(resource != NULL, FALSE);

  // precompile regexp
  G_LOCK(regex);
  if (regex == NULL)
    regex = g_regex_new("^([a-z]+)://([a-z0-9.:-]+(:([0-9]+))?)(/.+)?$", G_REGEX_CASELESS, 0, NULL);
  G_UNLOCK(regex);

  if (!g_regex_match(regex, uri, 0, &match_info))
    return FALSE;
  
  // check schema
  char* schema = g_match_info_fetch(match_info, 1);
  if (!g_ascii_strcasecmp("http", schema))
    *secure = 0;
  else if (!g_ascii_strcasecmp("https", schema))
    *secure = 1;
  else
  {
    g_free(schema);
    g_match_info_free(match_info);
    return FALSE;
  }
  g_free(schema);
  
  *host = g_match_info_fetch(match_info, 2);
  *resource = g_match_info_fetch(match_info, 5);
  if (*resource == NULL)
    *resource = g_strdup("/RPC2");

  g_match_info_free(match_info);
  return TRUE;
}

#endif

#ifdef XR_CHECK_IPV6
static gboolean xr_client_try_ipv6_resolve(GError** err, const char* host, const char* port)
{
  int n;
  struct addrinfo hints, *res=NULL;
  
  memset(&hints, '\0', sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  
  if (getaddrinfo(host, port, &hints, &res) != 0) {
    freeaddrinfo(res);
    return FALSE;
  }
  
  freeaddrinfo(res);
  return TRUE;
}

static int xr_client_new_sock_ipv6(GError** err, const char* host, const char* serv)
{
  int n, sockfd;
  const int optval=1;
  struct addrinfo hints, *res=NULL;

  xr_trace(XR_DEBUG_CLIENT_TRACE, "(host=%p, serv=%s, err=%p)", host, serv, err);
  g_return_val_if_fail(err == NULL || *err == NULL, -1);

  memset(&hints, '\0', sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;

  if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
    g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_FAILED,
        "getaddrinfo failed: %s", gai_strerror(n));
    return -1;
  }

  if ((sockfd = socket(AF_INET6, res->ai_socktype, res->ai_protocol)) < 0) {
    g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_FAILED,
        "create socket failed (errno=%d)", errno);
    goto err;
  }

  setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  if (connect(sockfd, (struct sockaddr*)res->ai_addr, res->ai_addrlen) < 0) {
    g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_FAILED,
        "connect socket failed (errno=%d)", errno);
    close(sockfd);
    sockfd = -1;
    goto err;
  }

err:
  freeaddrinfo(res);
  return sockfd;
}
#endif

gboolean xr_client_open(xr_client_conn* conn, const char* uri, GError** err)
{
  g_return_val_if_fail(conn != NULL, FALSE);
  g_return_val_if_fail(uri != NULL, FALSE);
  g_return_val_if_fail(!conn->is_open, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  xr_trace(XR_DEBUG_CLIENT_TRACE, "(conn=%p, uri=%s)", conn, uri);

  // parse URI format: http://host:8080/RES
  g_free(conn->host);
  g_free(conn->resource);
  conn->host = NULL;
  conn->resource = NULL;
  if (!_parse_uri(uri, &conn->secure, &conn->host, &conn->resource))
  {
    g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_FAILED, "invalid URI format: %s", uri);
    return FALSE;
  }

  SSL* ssl;
  gboolean ipv6 = FALSE;

  if (conn->secure)
  {
    conn->bio = BIO_new_buffer_ssl_connect(conn->ctx);
    BIO_get_ssl(conn->bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(conn->bio, conn->host);
    BIO_set_buffer_size(conn->bio, 2048);
  }
  else
  {
    conn->bio = BIO_new(BIO_f_buffer());
    BIO_push(conn->bio, BIO_new_connect(conn->host));
    BIO_set_buffer_size(conn->bio, 2048);
  }

#ifdef XR_CHECK_IPV6
  do {
    char* h = g_strdup(conn->host);
    char* t, *p = NULL;
    int sock;

    for (t = h; *t; ++t)
      if (*t == ':') p = t;

    if (p == NULL) {      /* no ':' found */
      g_free(h);
      break;
    }

    *p++ = '\0';          /* `p' points to port number */
    
    if (!xr_client_try_ipv6_resolve(err, h, p))
    {
      g_free(h);
      break;
    }
    /* IPv6 address */
    if (h[1] != ':') sock = xr_client_new_sock_ipv6(err, h, p);
    else sock = xr_client_new_sock_ipv6(err, NULL, p);

    g_free(h);
    if (sock < 0) break;

    BIO_set_fd(conn->bio, sock, BIO_CLOSE);
    
    if (conn->secure) {
      SSL_set_fd(ssl,sock);
      
      int err_code = SSL_connect(ssl);    /* SSL handshake here */
      if (err_code <= 0) { 
        g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_FAILED, "SSL handshake error: %d", SSL_get_error(ssl, err_code));
        BIO_free_all(conn->bio);
        close(sock);
        return FALSE;
      }
    }
    ipv6 = TRUE;
  }while(0);
#endif

  if (!ipv6)
  {
    if (BIO_do_connect(conn->bio) <= 0)
    {
      g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_FAILED, "BIO_do_connect failed: %s", xr_get_bio_error_string());
      BIO_free_all(conn->bio);
      return FALSE;
    }
  }

  xr_set_nodelay(conn->bio);

  if (conn->secure && !ipv6)
  {
    if (BIO_do_handshake(conn->bio) <= 0)
    {
      g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_FAILED, "BIO_do_handshake failed: %s", xr_get_bio_error_string());
      BIO_free_all(conn->bio);
      return FALSE;
    }
  }

  conn->http = xr_http_new(conn->bio);
  g_free(conn->session_id);
  conn->session_id = g_strdup_printf("%08x%08x%08x%08x", g_random_int(), g_random_int(), g_random_int(), g_random_int());
  conn->is_open = 1;

  xr_client_set_http_header(conn, "X-SESSION-ID", conn->session_id);

  return TRUE;
}

void xr_client_set_http_header(xr_client_conn* conn, const char* name, const char* value)
{
  g_return_if_fail(conn != NULL);
  g_return_if_fail(name != NULL);

  if (value == NULL)
    g_hash_table_remove(conn->headers, name);
  else
    g_hash_table_replace(conn->headers, g_strdup(name), g_strdup(value));
}

void xr_client_reset_http_headers(xr_client_conn* conn)
{
  g_return_if_fail(conn != NULL);

  g_hash_table_remove_all(conn->headers);
}

void xr_client_basic_auth(xr_client_conn* conn, const char* username, const char* password)
{
  g_return_if_fail(conn != NULL);
  g_return_if_fail(username != NULL);
  g_return_if_fail(password != NULL);

  char* auth_str = g_strdup_printf("%s:%s", username, password);
  char* enc_auth_str = g_base64_encode(auth_str, strlen(auth_str));
  char* auth_value = g_strdup_printf("Basic %s", enc_auth_str);
  xr_client_set_http_header(conn, "Authorization", auth_value);
  g_free(auth_str);
  g_free(enc_auth_str);
  g_free(auth_value);
}

xr_http* xr_client_get_http(xr_client_conn* conn)
{
  g_return_val_if_fail(conn != NULL, NULL);

  return conn->http;
}

void xr_client_close(xr_client_conn* conn)
{
  xr_trace(XR_DEBUG_CLIENT_TRACE, "(conn=%p)", conn);

  g_return_if_fail(conn != NULL);

  if (!conn->is_open)
    return;

  if (conn->secure)
    BIO_ssl_shutdown(conn->bio);

  xr_http_free(conn->http);
  conn->http = NULL;
  BIO_free_all(conn->bio);
  conn->bio = NULL;
  conn->is_open = FALSE;
}

static void _add_http_header(const char* name, const char* value, xr_http* http)
{
  xr_http_set_header(http, name, value);
}

gboolean xr_client_set_transport(xr_client_conn* conn, xr_call_transport transport)
{
  g_return_val_if_fail(conn != NULL, FALSE);
  g_return_val_if_fail(transport < XR_CALL_TRANSPORT_COUNT, FALSE);

  conn->transport = transport;

  return TRUE;
}

gboolean xr_client_call(xr_client_conn* conn, xr_call* call, GError** err)
{
  char* buffer;
  int length;
  gboolean rs;
  gboolean write_success;
  GString* response;

  xr_trace(XR_DEBUG_CLIENT_TRACE, "(conn=%p, call=%p)", conn, call);

  g_return_val_if_fail(conn != NULL, FALSE);
  g_return_val_if_fail(call != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  if (!conn->is_open)
  {
    g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_CLOSED, "Can't perform RPC on closed connection.");
    return FALSE;
  }

  /* serialize nad send XML-RPC request */
  xr_call_set_transport(call, conn->transport);
  xr_call_serialize_request(call, &buffer, &length);
  xr_http_setup_request(conn->http, "POST", conn->resource, conn->host);
  g_hash_table_foreach(conn->headers, (GHFunc)_add_http_header, conn->http);
  if (conn->transport == XR_CALL_XML_RPC)
    xr_http_set_header(conn->http, "Content-Type", "text/xml");
#ifdef XR_JSON_ENABLED
  else if (conn->transport == XR_CALL_JSON_RPC)
    xr_http_set_header(conn->http, "Content-Type", "text/json");
#endif
  xr_http_set_message_length(conn->http, length);
  write_success = xr_http_write_all(conn->http, buffer, length, err);
  xr_call_free_buffer(call, buffer);
  if (!write_success)
  {
    xr_client_close(conn);
    return FALSE;
  }

  /* receive HTTP response header */
  if (!xr_http_read_header(conn->http, err))
    return FALSE;

  /* check if some dumb bunny sent us wrong message type */
  if (xr_http_get_message_type(conn->http) != XR_HTTP_RESPONSE)
    return FALSE;

  response = xr_http_read_all(conn->http, err);
  if (response == NULL)
  {
    g_clear_error(err);
    g_set_error(err, XR_CLIENT_ERROR, XR_CLIENT_ERROR_IO, "HTTP receive failed.");
    xr_client_close(conn);
    return FALSE;
  }

  rs = xr_call_unserialize_response(call, response->str, response->len);
  g_string_free(response, TRUE);
  if (!rs)
  {
    g_set_error(err, XR_REMOTE_SERVER_ERROR, xr_call_get_error_code(call), "%s", xr_call_get_error_message(call));

    if (xr_debug_enabled & XR_DEBUG_CALL)
      xr_call_dump(call, 0);

    return FALSE;
  }

  if (xr_debug_enabled & XR_DEBUG_CALL)
    xr_call_dump(call, 0);

  return TRUE;
}

void xr_client_free(xr_client_conn* conn)
{
  xr_trace(XR_DEBUG_CLIENT_TRACE, "(conn=%p)", conn);

  if (conn == NULL)
    return;

  xr_client_close(conn);
  g_free(conn->host);
  g_free(conn->resource);
  g_free(conn->session_id);
  SSL_CTX_free(conn->ctx);
  g_hash_table_destroy(conn->headers);
  g_free(conn);
}

GQuark xr_client_error_quark()
{
  static GQuark quark;
  return quark ? quark : (quark = g_quark_from_static_string("xr_client_error"));
}

GQuark xr_remote_server_error_quark()
{
  static GQuark quark;
  return quark ? quark : (quark = g_quark_from_static_string("Remote server error"));
}
