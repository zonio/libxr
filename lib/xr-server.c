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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "xr-server.h"
#include "xr-http.h"
#include "xr-utils.h"

#define XR_ENABLE_IPv6

/* OpenSSL 1.0.0 supports IPv6 in BIO.  If we are using OpenSSL with
 * version lower than 1.0.0, we must setup IPv6 socket ourself.
 *
 * The approach is to create an IPv6 socket and bind it to a BIO.
 */
#if defined XR_ENABLE_IPv6
#  if !defined WIN32 && OPENSSL_VERSION_NUMBER < 0x10000000L
#    define XR_CHECK_IPV6
#  endif
#endif

/* server */

struct _xr_server
{
  SSL_CTX* ctx;
  BIO* bio_accept;
  int sock;
  GThreadPool* pool;
  gboolean secure;
  gboolean running;
#ifdef XR_CHECK_IPV6
  gboolean ipv6;
#endif
  GSList* servlet_types;
  GHashTable* sessions;
  GStaticRWLock sessions_lock;
  GThread* sessions_cleaner;
  time_t current_time;
};

/* servlet API */

typedef struct _xr_server_conn xr_server_conn;
struct _xr_server_conn
{
  BIO* bio;
  xr_http* http;
  GPtrArray* servlets;
  gboolean running;
};

struct _xr_servlet
{
  void* priv;
  xr_servlet_def* def;
  xr_call* call;
  xr_server_conn* conn;
  time_t last_used;
  GMutex* call_mutex; /* held during call */
};

static void xr_servlet_free(xr_servlet* servlet, gboolean fini)
{
  if (servlet == NULL)
    return;
  if (fini && servlet->def && servlet->def->fini)
    servlet->def->fini(servlet);
  g_free(servlet->priv);
  g_mutex_free(servlet->call_mutex);
  memset(servlet, 0, sizeof(*servlet));
  g_free(servlet);
}

static xr_servlet* xr_servlet_new(xr_servlet_def* def, xr_server_conn* conn)
{
  xr_servlet* s = g_new0(xr_servlet, 1);
  if (def->size > 0)
    s->priv = g_malloc0(def->size);
  s->def = def;
  s->conn = conn;
  s->call_mutex = g_mutex_new();

  if (s->def->init && !s->def->init(s))
  {
    xr_servlet_free(s, FALSE);
    return NULL;
  }

  return s;
}

static xr_server_conn* xr_server_conn_new(BIO* bio)
{
  xr_server_conn* c = g_new0(xr_server_conn, 1);
  c->servlets = g_ptr_array_sized_new(3);
  c->http = xr_http_new(bio);
  c->bio = bio;
  c->running = TRUE;
  return c;
}

static void xr_server_conn_free(xr_server_conn* conn)
{
  if (conn == NULL)
    return;
  xr_http_free(conn->http);
  BIO_reset(conn->bio);
  BIO_free_all(conn->bio);
  g_ptr_array_foreach(conn->servlets, (GFunc)xr_servlet_free, (gpointer)TRUE);
  g_ptr_array_free(conn->servlets, TRUE);
  memset(conn, 0, sizeof(*conn));
  g_free(conn);
}

static xr_servlet* xr_server_conn_find_servlet(xr_server_conn* conn, const char* name)
{
  int i;

  for (i = 0; i < conn->servlets->len; i++)
  {
    xr_servlet* servlet = conn->servlets->pdata[i];
    if (!strcmp(servlet->def->name, name))
      return servlet;
  }

  return NULL;
}

void* xr_servlet_get_priv(xr_servlet* servlet)
{
  g_return_val_if_fail(servlet != NULL, NULL);

  return servlet->priv;
}

xr_http* xr_servlet_get_http(xr_servlet* servlet)
{
  g_return_val_if_fail(servlet != NULL, NULL);
  g_return_val_if_fail(servlet->conn != NULL, NULL);
  g_return_val_if_fail(servlet->conn->http != NULL, NULL);

  return servlet->conn->http;
}

char* xr_servlet_get_client_ip(xr_servlet* servlet)
{
#ifdef WIN32
  /* I don't have time for this crap, right now :D */
  return NULL;
#else
  char buf[INET_ADDRSTRLEN];
  int socket = -1;

  g_return_val_if_fail(servlet != NULL, NULL);
  g_return_val_if_fail(servlet->conn != NULL, NULL);

  BIO_get_fd(servlet->conn->bio, &socket);
  if (socket > 0)
  {
    socklen_t clnt_length;
    struct sockaddr_in clnt_addr;

    memset(&clnt_addr, 0, sizeof(clnt_addr));
    clnt_length = sizeof(clnt_addr);

    if (getpeername(socket, (struct sockaddr*)&clnt_addr, &clnt_length) == 0)
    {
      if (inet_ntop(AF_INET, &clnt_addr.sin_addr, buf, sizeof(buf)) == NULL)
        return NULL;
      else
        return g_strdup(buf);
    }
  }

  return NULL;
#endif
}

static xr_servlet_def* _find_servlet_def(xr_server* server, char* name)
{
  GSList* i;

  for (i = server->servlet_types; i; i = i->next)
  {
    xr_servlet_def* def = i->data;
    if (!g_ascii_strcasecmp(def->name, name))
      return def;
  }

  return NULL;
}

static xr_servlet_method_def* _find_servlet_method_def(xr_servlet* servlet, const char* name)
{
  int i;

  g_return_val_if_fail(servlet != NULL, NULL);
  g_return_val_if_fail(servlet->def != NULL, NULL);

  for (i = 0; i < servlet->def->methods_count; i++)
    if (!strcmp(servlet->def->methods[i].name, name))
      return servlet->def->methods + i;

  return NULL;
}

static gboolean _xr_servlet_do_call(xr_servlet* servlet, xr_call* call)
{
  xr_servlet_method_def* method;
  gboolean retval = FALSE;

  servlet->call = call;

  /* find method and perform a call */
  method = _find_servlet_method_def(servlet, xr_call_get_method(call));
  if (method)
  {
    if (servlet->def->pre_call)
    {
      if (!servlet->def->pre_call(servlet, call))
      {
        // FALSE returned
        if (xr_call_get_retval(call) == NULL && !xr_call_error_set(call))
          xr_call_set_error(call, -1, "Pre-call did not returned value or set error.");
        goto out;
      }
    }

    retval = method->cb(servlet, call);

    if (servlet->def->post_call)
      servlet->def->post_call(servlet, call);
  }
  else if (servlet->def->fallback)
  {
    if (servlet->def->fallback(servlet, call))
    {
      // call should be handled
      if (xr_call_get_retval(call) == NULL && !xr_call_error_set(call))
        xr_call_set_error(call, -1, "Fallback did not returned value or set error.");
    }
    else
      xr_call_set_error(call, -1, "Method %s not found in %s servlet.", xr_call_get_method(call), servlet->def->name);
  }
  else
    xr_call_set_error(call, -1, "Method %s not found in %s servlet.", xr_call_get_method(call), servlet->def->name);

out:
  servlet->call = NULL;
  return retval;
}

static gboolean maybe_remove_servlet(gpointer key, gpointer value, gpointer user_data)
{
  xr_servlet* servlet = value;
  xr_server* server = user_data;

  if (g_mutex_trylock(servlet->call_mutex))
  {
    g_mutex_unlock(servlet->call_mutex); /* this is ok, as nobody else is going to take this lock during remove */
    return (servlet->last_used + 60 < server->current_time || servlet->last_used > server->current_time);
  }

  /* servlet is locked, can't remove */
  return FALSE;
}

static gpointer sessions_cleaner_func(xr_server* server)
{
  while (server->running)
  {
    g_usleep(1000000);

    server->current_time = time(NULL);
    g_static_rw_lock_writer_lock(&server->sessions_lock);
    g_hash_table_foreach_remove(server->sessions, maybe_remove_servlet, server);
    g_static_rw_lock_writer_unlock(&server->sessions_lock);
  }

  return NULL;
}

static gboolean _xr_server_servlet_method_call(xr_server* server, xr_server_conn* conn, xr_call* call)
{
  xr_servlet* servlet = NULL;
  xr_servlet* cur_servlet;
  char *servlet_name;

  g_return_val_if_fail(server != NULL, FALSE);
  g_return_val_if_fail(conn != NULL, FALSE);
  g_return_val_if_fail(call != NULL, FALSE);

  /* session mode */
  const char* session_id = xr_http_get_header(conn->http, "X-SESSION-ID");
  if (session_id && xr_http_get_header(conn->http, "X-SESSION-USE"))
  {
    /* lookup servlet in session and try to lock it for call, if call is in
       progress try again later (1ms) */
again:
    g_static_rw_lock_reader_lock(&server->sessions_lock);
    servlet = g_hash_table_lookup(server->sessions, session_id);
    if (servlet)
      if (!g_mutex_trylock(servlet->call_mutex))
      {
        g_static_rw_lock_reader_unlock(&server->sessions_lock);
        g_usleep(1000);
        goto again;
      }
    g_static_rw_lock_reader_unlock(&server->sessions_lock);

    /* if servlet does not exist */
    if (servlet == NULL)
    {
      xr_servlet_def* def;
      servlet_name = xr_call_get_servlet_name(call, xr_http_get_resource(conn->http) + 1);
      if (servlet_name == NULL)
      {
        xr_call_set_error(call, -1, "Undefined servlet name.");
        return FALSE;
      }

      def = _find_servlet_def(server, servlet_name);
      if (def == NULL)
      {
        xr_call_set_error(call, -1, "Unknown servlet %s.", servlet_name);
        g_free(servlet_name);
        return FALSE;
      }
      g_free(servlet_name);

      servlet = xr_servlet_new(def, conn);
      if (servlet == NULL)
      {
        xr_call_set_error(call, -1, "Servlet initialization failed.");
        return FALSE;
      }

      g_static_rw_lock_writer_lock(&server->sessions_lock);

      /* user might have used same session ID to create servlet in other thread, check for
         this situation */
      cur_servlet = g_hash_table_lookup(server->sessions, session_id); 
      if (cur_servlet)
      {
        xr_servlet_free(servlet, TRUE);
        servlet = cur_servlet;
      }
      else
        g_hash_table_replace(server->sessions, g_strdup(session_id), servlet);

      /* this will block sessions ht access until servlet call completes, if
         servlet was found in other thread, which should be rare occurrance */
      g_mutex_lock(servlet->call_mutex);
      g_static_rw_lock_writer_unlock(&server->sessions_lock);
    }

    servlet->conn = conn;
    servlet->last_used = time(NULL);
    gboolean rs = _xr_servlet_do_call(servlet, call);
    g_mutex_unlock(servlet->call_mutex);
    return rs;
  }

  /* persistent mode */

  /* get xr_servlet object for current connection and given servlet name */
  servlet_name = xr_call_get_servlet_name(call, xr_http_get_resource(conn->http) + 1);
  if (servlet_name == NULL)
  {
    xr_call_set_error(call, -1, "Undefined servlet name.");
    return FALSE;
  }

  servlet = xr_server_conn_find_servlet(conn, servlet_name);
  if (servlet == NULL)
  {
    xr_servlet_def* def = _find_servlet_def(server, servlet_name);
    if (def == NULL)
    {
      xr_call_set_error(call, -1, "Unknown servlet %s.", servlet_name);
      g_free(servlet_name);
      return FALSE;
    }
    g_free(servlet_name);

    servlet = xr_servlet_new(def, conn);
    if (servlet == NULL)
    {
      xr_call_set_error(call, -1, "Servlet initialization failed.");
      return FALSE;
    }

    g_ptr_array_add(conn->servlets, servlet);
  }else
    g_free(servlet_name);
  
  return _xr_servlet_do_call(servlet, call);
}

static gboolean _xr_server_serve_download(xr_server* server, xr_server_conn* conn)
{
  guint i;
  GSList* iter;

  /* for each available servlet type, check if it has download hook */
  for (iter = server->servlet_types; iter; iter = iter->next)
  {
    xr_servlet_def* def = iter->data;

    if (def->download)
    {
      xr_servlet* servlet = NULL;

      /* check if servlet is instantiated */
      for (i = 0; i < conn->servlets->len; i++)
      {
        xr_servlet* existing_servlet = g_ptr_array_index(conn->servlets, i);
        if (existing_servlet->def == def)
          servlet = existing_servlet;
      }

      /* it's not, instantiate it now */
      if (servlet == NULL)
      {
        servlet = xr_servlet_new(def, conn);
        g_ptr_array_add(conn->servlets, servlet);
      }

      if (def->download(servlet))
        return xr_http_is_ready(conn->http);
    }
  }

  xr_http_setup_response(conn->http, 501);
  xr_http_set_header(conn->http, "Content-Type", "text/plain");
  if (!xr_http_write_all(conn->http, "Download hook is not implemented.", -1, NULL))
    return FALSE;

  return TRUE;
}

static gboolean _xr_server_serve_upload(xr_server* server, xr_server_conn* conn)
{
  guint i;
  GSList* iter;

  /* for each available servlet type, check if it has upload hook */
  for (iter = server->servlet_types; iter; iter = iter->next)
  {
    xr_servlet_def* def = iter->data;

    if (def->upload)
    {
      xr_servlet* servlet = NULL;

      /* check if servlet is instantiated */
      for (i = 0; i < conn->servlets->len; i++)
      {
        xr_servlet* existing_servlet = g_ptr_array_index(conn->servlets, i);
        if (existing_servlet->def == def)
          servlet = existing_servlet;
      }

      /* it's not, instantiate it now */
      if (servlet == NULL)
      {
        servlet = xr_servlet_new(def, conn);
        g_ptr_array_add(conn->servlets, servlet);
      }

      if (def->upload(servlet))
        return xr_http_is_ready(conn->http);
    }
  }

  char buf[4096];
  while (xr_http_read(conn->http, buf, sizeof(buf), NULL) > 0);
  xr_http_setup_response(conn->http, 501);
  xr_http_set_header(conn->http, "Content-Type", "text/plain");
  if (!xr_http_write_all(conn->http, "Upload hook is not implemented.", -1, NULL))
    return FALSE;

  return TRUE;
}

static int _ctype_to_transport(const char* ctype)
{
  if (ctype == NULL)
    return -1;
  if (!g_ascii_strncasecmp(ctype, "text/xml", 8))
    return XR_CALL_XML_RPC;
#ifdef XR_JSON_ENABLED
  if (!g_ascii_strncasecmp(ctype, "text/json", 9))
    return XR_CALL_JSON_RPC;
#endif
  return -1;
}

static gboolean _xr_server_serve_request(xr_server* server, xr_server_conn* conn)
{
  const char* method;
  int version;

  xr_trace(XR_DEBUG_SERVER_TRACE, "(server=%p, conn=%p)", server, conn);

  g_return_val_if_fail(server != NULL, FALSE);
  g_return_val_if_fail(conn != NULL, FALSE);

  /* check whether incoming HTTP request is available in one minute */
  if (!xr_http_has_pending_request(conn->http, 60))
    return FALSE;

  /* receive HTTP request */
  if (!xr_http_read_header(conn->http, NULL))
    return FALSE;

  /* check if some dumb bunny sent us wrong message type */
  if (xr_http_get_message_type(conn->http) != XR_HTTP_REQUEST)
    return FALSE;

  method = xr_http_get_method(conn->http);
  if (method == NULL)
    return FALSE;

  version = xr_http_get_version(conn->http);

  if (!strcmp(method, "GET"))
    return _xr_server_serve_download(server, conn) && (version == 1);
  else if (!strcmp(method, "POST"))
  {
    int transport = _ctype_to_transport(xr_http_get_header(conn->http, "Content-Type"));

    if (transport >= 0)
    {
      xr_call* call;
      GString* request;
      char* buffer;
      int length;
      gboolean rs;

      request = xr_http_read_all(conn->http, NULL);
      if (request == NULL)
        return FALSE;

      /* parse request data into xr_call */
      call = xr_call_new(NULL);
      xr_call_set_transport(call, transport);

      rs = xr_call_unserialize_request(call, request->str, request->len);
      g_string_free(request, TRUE);

      /* run call */
      if (!rs)
        xr_call_set_error(call, -1, "Unserialize request failure.");
      else
        _xr_server_servlet_method_call(server, conn, call);

      /* generate response data from xr_call */
      xr_call_serialize_response(call, &buffer, &length);
      if (xr_debug_enabled & XR_DEBUG_CALL)
        xr_call_dump(call, 0);

      /* send HTTP response */
      xr_http_setup_response(conn->http, 200);
      xr_http_set_message_length(conn->http, length);
      rs = xr_http_write_all(conn->http, buffer, length, NULL);
      xr_call_free_buffer(call, buffer);
      xr_call_free(call);

      return rs && (version == 1);
    }
    else
      return _xr_server_serve_upload(server, conn) && (version == 1);
  }
  else
    return FALSE;

  return TRUE;
}

static void _xr_server_connection_thread(xr_server_conn* conn, xr_server* server)
{
  xr_trace(XR_DEBUG_SERVER_TRACE, "(conn=%p, server=%p)", conn, server);

  g_return_if_fail(conn != NULL);
  g_return_if_fail(server != NULL);

  if (server->secure
#ifdef XR_CHECK_IPV6
		  && (!server->ipv6)
#endif
     )
    if (BIO_do_handshake(conn->bio) <= 0)
      goto done;

  while (conn->running)
    if (!_xr_server_serve_request(server, conn))
      break;

 done:
  xr_server_conn_free(conn);
}

void xr_server_stop(xr_server* server)
{
  xr_trace(XR_DEBUG_SERVER_TRACE, "(server=%p)", server);
  g_return_if_fail(server != NULL);
  server->running = FALSE;
}

/* wait for a connection and accept it, return FALSE on fatal error, TRUE on
   temprary error or success */
static gboolean _xr_server_accept_connection(xr_server* server, GError** err)
{
  GError* local_err = NULL;
  xr_server_conn* conn = NULL;

  xr_trace(XR_DEBUG_SERVER_TRACE, "(server=%p, err=%p)", server, err);

  g_return_val_if_fail(server != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

#ifdef XR_CHECK_IPV6
  if (server->ipv6) {
    BIO* bbio = NULL;
    BIO* acpt = NULL;
    int  connfd = -1;

    connfd = accept(server->sock, (struct sockaddr*)NULL, NULL);
    if (connfd < 0) {
      g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "accept failed: %s", xr_get_bio_error_string());
      return FALSE;
    }

    acpt = BIO_new_socket(connfd, BIO_CLOSE);
    bbio = BIO_new(BIO_f_buffer());
    BIO_set_buffer_size(bbio, 2048);

    if (server->secure) {
      BIO* sbio = BIO_new_ssl(server->ctx, 0);
      SSL* ssl = NULL;

      BIO_get_ssl(sbio, &ssl);
      SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

      /* The null BIO is used to avoid to crash from BIO_copy_next_retry() */
      sbio = BIO_push(sbio, BIO_new(BIO_f_null()));

      /* Need to chain these BIO before SSL_accept() */
      sbio = BIO_push(bbio, sbio);

      SSL_set_bio(ssl, acpt, acpt);
      if (SSL_accept(ssl) <= 0) { /* SSL handshake here */
        g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "SSL handshake error");
        BIO_free_all(sbio);
        return FALSE;
      }
      conn = xr_server_conn_new(sbio);
    } else {
      conn = xr_server_conn_new(BIO_push(bbio, acpt));
    }
  } else {
#endif	/* XR_CHECK_IPV6 */
    if (BIO_do_accept(server->bio_accept) <= 0)
    {
      g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "accept failed: %s", xr_get_bio_error_string());
      return FALSE;
    }

    // new connection accepted
    conn = xr_server_conn_new(BIO_pop(server->bio_accept));

#ifdef XR_CHECK_IPV6
  }
#endif

  // if we have too many clients in the queue, pause accepting new ones
  // and leave some time to process existing ones, this ensures that
  // server does not get overloaded and improves latency for clients that are in
  // the queue or being processed right now
  if (g_thread_pool_unprocessed(server->pool) > 50)
    g_usleep(500000);

  // push client into the queue
  g_thread_pool_push(server->pool, conn, &local_err);
  if (local_err)
  {
    xr_server_conn_free(conn);

    // check if this is only temporary error
    if (!g_error_matches(local_err, G_THREAD_ERROR, G_THREAD_ERROR_AGAIN))
    {
      g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "thread push failed: %s", local_err->message);
      g_clear_error(&local_err);
      return FALSE;
    }

    g_clear_error(&local_err);
  }

  return TRUE;
}

gboolean xr_server_run(xr_server* server, GError** err)
{
  GError* local_err = NULL;
  fd_set set, setcopy;
  struct timeval tv, tvcopy;
  int maxfd;

  xr_trace(XR_DEBUG_SERVER_TRACE, "(server=%p, err=%p)", server, err);

  g_return_val_if_fail(server != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  FD_ZERO(&setcopy);
  FD_SET(server->sock, &setcopy);
  maxfd = server->sock + 1;
  tvcopy.tv_sec = 0;
  tvcopy.tv_usec = 500000;
  
  server->running = TRUE;
  while (server->running)
  {
    set = setcopy;
    tv = tvcopy;

    int rs = select(maxfd, &set, NULL, NULL, &tv);
    if (rs < 0)
    {
#ifdef WIN32
      if (WSAGetLastError() == WSAEINTR)
        continue;
#else
      if (errno == EINTR)
        return TRUE;
#endif
      g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "select failed: %s", g_strerror(errno));
      return FALSE;
    }
    else if (rs == 0)
      continue;

    if (!_xr_server_accept_connection(server, &local_err))
    {
      g_propagate_error(err, local_err);
      return FALSE;
    }
  }

  return TRUE;
}

gboolean xr_server_register_servlet(xr_server* server, xr_servlet_def* servlet)
{
  xr_trace(XR_DEBUG_SERVER_TRACE, "(server=%p, servlet=%p)", server, servlet);

  g_return_val_if_fail(server != NULL, FALSE);
  g_return_val_if_fail(servlet != NULL, FALSE);

  if (_find_servlet_def(server, servlet->name))
    return FALSE;

  server->servlet_types = g_slist_append(server->servlet_types, servlet);
  return TRUE;
}

xr_server* xr_server_new(const char* cert, int threads, GError** err)
{
  xr_trace(XR_DEBUG_SERVER_TRACE, "(cert=%s, threads=%d, err=%p)", cert, threads, err);
  GError* local_err = NULL;

  g_return_val_if_fail(threads > 0 && threads < 1000, NULL);
  g_return_val_if_fail (err == NULL || *err == NULL, NULL);

  xr_init();

  xr_server* server = g_new0(xr_server, 1);
  server->secure = !!cert;

  server->ctx = SSL_CTX_new(SSLv23_server_method());
  if (server->ctx == NULL)
  {
    g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "ssl context creation failed: %s", ERR_reason_error_string(ERR_get_error()));
    goto err1;
  }

  if (server->secure)
  {
    if (!SSL_CTX_use_certificate_file(server->ctx, cert, SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(server->ctx, cert, SSL_FILETYPE_PEM) ||
        !SSL_CTX_check_private_key(server->ctx))
    {
      g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "ssl cert load failed: %s", ERR_reason_error_string(ERR_get_error()));
      goto err2;
    }
  }

  server->pool = g_thread_pool_new((GFunc)_xr_server_connection_thread, server, threads, TRUE, &local_err);
  if (local_err)
  {
    g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "thread pool creation failed: %s", local_err->message);
    g_clear_error(&local_err);
    goto err2;
  }

  server->running = TRUE;

  server->sessions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify)xr_servlet_free);
  g_static_rw_lock_init(&server->sessions_lock);
  server->sessions_cleaner = g_thread_create((GThreadFunc)sessions_cleaner_func, server, TRUE, NULL);
  if (server->sessions_cleaner == NULL)
    goto err3;

  return server;

err3:
  g_hash_table_destroy(server->sessions);
  g_static_rw_lock_free(&server->sessions_lock);
err2:
  SSL_CTX_free(server->ctx);
  server->ctx = NULL;
err1:
  g_free(server);
  return NULL;
}

SSL_CTX* xr_server_get_ssl_context(xr_server* server)
{
  g_return_val_if_fail(server != NULL, FALSE);

  if (server->secure)
    return server->ctx;
  return NULL;
}

#ifdef XR_CHECK_IPV6
static gboolean xr_server_try_ipv6_resolve(GError** err, const char* host, const char* port)
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

static int xr_server_new_sock_ipv6(GError** err, const char* host, const char* serv)
{
  int n, sockfd;
  const int optval=1;
  struct addrinfo hints, *res=NULL;

  xr_trace(XR_DEBUG_SERVER_TRACE, "(host=%p, serv=%s, err=%p)", host, serv, err);
  g_return_val_if_fail(err == NULL || *err == NULL, -1);

  memset(&hints, '\0', sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;

  if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
    g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED,
        "getaddrinfo failed: %s", gai_strerror(n));
    return -1;
  }

  if ((sockfd = socket(AF_INET6, res->ai_socktype, res->ai_protocol)) < 0) {
    g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED,
        "create socket failed (errno=%d)", errno);
    goto err;
  }

  setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  if (bind(sockfd, (struct sockaddr*)res->ai_addr, res->ai_addrlen) < 0) {
    g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED,
        "bind socket failed (errno=%d)", errno);
    close(sockfd);
    sockfd = -1;
    goto err;
  }

  if (listen(sockfd, 32) < 0) {
    g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED,
        "listen failed (errno=%d)", errno);
    close(sockfd);
    sockfd = -1;
  }

err:
  freeaddrinfo(res);
  return sockfd;
}
#endif

gboolean xr_server_bind(xr_server* server, const char* port, GError** err)
{
  BIO* bio_buffer;

  xr_trace(XR_DEBUG_SERVER_TRACE, "(server=%p, port=%s, err=%p)", server, port, err);

  g_return_val_if_fail(server != NULL, FALSE);
  g_return_val_if_fail(port != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

#ifdef XR_CHECK_IPV6
  do {
    char* h = g_strdup(port);
    char* t, *p = NULL;
    int sock;

    for (t = h; *t; ++t)
      if (*t == ':') p = t;

    if (p == NULL) {      /* no ':' found */
      g_free(h);
      break;
    }

    *p++ = '\0';          /* `p' points to port number */

    if (!xr_server_try_ipv6_resolve(err, h, p))
      break;
    
    /* IPv6 address */
    if (h[1] != ':') sock = xr_server_new_sock_ipv6(err, h, p);
    else sock = xr_server_new_sock_ipv6(err, NULL, p);

    g_free(h);
    if (sock < 0) return FALSE;

    server->ipv6 = TRUE;
    server->sock = sock;
    
    return TRUE;
  }while(0);
#endif

  server->bio_accept = BIO_new_accept((char*)port);
  if (server->bio_accept == NULL)
  {
    g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "accept bio creation failed: %s", xr_get_bio_error_string());
    return FALSE;
  }

  BIO_set_bind_mode(server->bio_accept, BIO_BIND_REUSEADDR);

  bio_buffer = BIO_new(BIO_f_buffer());
  BIO_set_buffer_size(bio_buffer, 2048);

  if (server->secure)
  {
    BIO* bio_ssl;
    SSL* ssl;

    bio_ssl = BIO_new_ssl(server->ctx, 0);
    BIO_get_ssl(bio_ssl, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_push(bio_buffer, bio_ssl);
  }

  BIO_set_accept_bios(server->bio_accept, bio_buffer);

  if (BIO_do_accept(server->bio_accept) <= 0)
  {
    g_set_error(err, XR_SERVER_ERROR, XR_SERVER_ERROR_FAILED, "%s", xr_get_bio_error_string());
    BIO_free_all(server->bio_accept);
    server->bio_accept = NULL;
    return FALSE;
  }

  server->sock = -1;
  BIO_get_fd(server->bio_accept, &server->sock);
  xr_set_nodelay(server->bio_accept);

  return TRUE;
}

void xr_server_free(xr_server* server)
{
  xr_trace(XR_DEBUG_SERVER_TRACE, "(server=%p)", server);

  if (server == NULL)
    return;

  g_thread_pool_free(server->pool, TRUE, TRUE);
  BIO_free_all(server->bio_accept);
  SSL_CTX_free(server->ctx);
  g_slist_free(server->servlet_types);
  g_thread_join(server->sessions_cleaner);
  g_hash_table_destroy(server->sessions);
  g_static_rw_lock_free(&server->sessions_lock);
  g_free(server);
}

GQuark xr_server_error_quark()
{
  static GQuark quark;
  return quark ? quark : (quark = g_quark_from_static_string("xr_server_error"));
}

/* simple server setup function */

static xr_server* server = NULL;
static xr_server* server2 = NULL;
static void _sh(int signum)
{
  xr_server_stop(server);
  xr_server_stop(server2);
}

gboolean xr_server_simple(const char* cert, int threads, const char* bind, xr_servlet_def** servlets, GError** err)
{
  if (!g_thread_supported())
    g_thread_init(NULL);

//  g_return_val_if_fail(server == NULL, FALSE);
  g_return_val_if_fail(threads > 0, FALSE);
  g_return_val_if_fail(bind != NULL, FALSE);
  g_return_val_if_fail(servlets != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

#ifndef WIN32
  struct sigaction act;
  act.sa_handler = _sh;
  act.sa_flags = SA_RESTART;
  sigemptyset(&act.sa_mask);
  if (sigaction(SIGINT, &act, NULL) < 0
   || sigaction(SIGHUP, &act, NULL) < 0
   || sigaction(SIGTERM, &act, NULL) < 0)
    return FALSE;
#endif

  xr_server *used_server;

  if (server == NULL) used_server = server;
  else used_server = server2;

  used_server = xr_server_new(cert, threads, err);
  if (used_server == NULL)
    return FALSE;

  if (!xr_server_bind(used_server, bind, err))
  {
    xr_server_stop(used_server);
    xr_server_free(used_server);
    return FALSE;
  }

  if (servlets)
  {
    while (*servlets)
    {
      xr_server_register_servlet(used_server, *servlets);
      servlets++;
    }
  }

  if (!xr_server_run(used_server, err))
  {
    xr_server_free(used_server);
    return FALSE;
  }

  xr_server_free(used_server);
  return TRUE;
}
