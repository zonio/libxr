/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright © 2010 Red Hat, Inc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gio.h"
#include "gtlsbackend-gnutls.h"

/**
 * SECTION:gtls
 * @title: TLS Overview
 * @short_description: TLS (aka SSL) support for GSocketConnection
 * @include: gio/gio.h
 *
 * #GTlsConnection and related classes provide TLS (Transport Layer
 * Security, previously known as SSL, Secure Sockets Layer) support for
 * gio-based network streams.
 *
 * In the simplest case, for a client connection, you can just set the
 * #GSocketClient:tls flag on a #GSocketClient, and then any
 * connections created by that client will have TLS negotiated
 * automatically, using appropriate default settings, and rejecting
 * any invalid or self-signed certificates (unless you change that
 * default by setting the #GSocketClient:tls-validation-flags
 * property). The returned object will be a #GTcpWrapperConnection,
 * which wraps the underlying #GTlsClientConnection.
 *
 * For greater control, you can create your own #GTlsClientConnection,
 * wrapping a #GSocketConnection (or an arbitrary #GIOStream with
 * pollable input and output streams) and then connect to its signals,
 * such as #GTlsConnection::accept-certificate, before starting the
 * handshake.
 *
 * Server-side TLS is similar, using #GTlsServerConnection. At the
 * moment, there is no support for automatically wrapping server-side
 * connections in the way #GSocketClient does for client-side
 * connections.
 */

/**
 * SECTION:gtlsbackend
 * @title: GTlsBackend
 * @short_description: TLS backend implementation
 * @include: gio/gio.h
 */

/**
 * GTlsBackend:
 *
 * Type implemented by TLS #GIOModules to provide access to additional
 * TLS-related types.
 *
 * Since: 2.28
 */

G_DEFINE_INTERFACE (GTlsBackend, g_tls_backend, G_TYPE_OBJECT);

static void
g_tls_backend_default_init (GTlsBackendInterface *iface)
{
}

static gboolean
g_socket_input_stream_pollable_is_readable (GPollableInputStream *pollable)
{
  GSocketInputStream *input_stream = G_SOCKET_INPUT_STREAM (pollable);

  return g_socket_condition_check ((GSocket *) input_stream->priv, G_IO_IN);
}

static GSource *
g_socket_input_stream_pollable_create_source (GPollableInputStream *pollable,
      GCancellable         *cancellable)
{
  GSocketInputStream *input_stream = G_SOCKET_INPUT_STREAM (pollable);
  GSource *socket_source, *pollable_source;

  pollable_source = g_pollable_source_new (G_OBJECT (input_stream));
  socket_source = g_socket_create_source ((GSocket *) input_stream->priv,
  G_IO_IN, cancellable);
  g_source_set_dummy_callback (socket_source);
  g_source_add_child_source (pollable_source, socket_source);
  g_source_unref (socket_source);

  return pollable_source;
}

/*static gssize
g_socket_input_stream_pollable_read_nonblocking (GPollableInputStream  *pollable,
			 void                  *buffer,
			 gsize                  size,
			 GError               **error)
{
  GSocketInputStream *input_stream = G_SOCKET_INPUT_STREAM (pollable);

  return g_socket_receive_with_blocking ((GSocket *) input_stream->priv,
		     buffer, size, FALSE,
		     NULL, error);
}*/

static void
g_socket_input_stream_pollable_iface_init (GPollableInputStreamInterface *iface)
{
  iface->is_readable = g_socket_input_stream_pollable_is_readable;
  iface->create_source = g_socket_input_stream_pollable_create_source;
/*  iface->read_nonblocking = g_socket_input_stream_pollable_read_nonblocking;*/
}

static gboolean
g_socket_output_stream_pollable_is_writable (GPollableOutputStream *pollable)
{
  GSocketOutputStream *output_stream = G_SOCKET_OUTPUT_STREAM (pollable);

  return g_socket_condition_check ((GSocket *) output_stream->priv, G_IO_OUT);
}

static GSource *
g_socket_output_stream_pollable_create_source (GPollableOutputStream *pollable,
       GCancellable          *cancellable)
{
  GSocketOutputStream *output_stream = G_SOCKET_OUTPUT_STREAM (pollable);
  GSource *socket_source, *pollable_source;

  pollable_source = g_pollable_source_new (G_OBJECT (output_stream));
  socket_source = g_socket_create_source ((GSocket *) output_stream->priv,
		      G_IO_OUT, cancellable);
  g_source_set_dummy_callback (socket_source);
  g_source_add_child_source (pollable_source, socket_source);
  g_source_unref (socket_source);

  return pollable_source;
}

/*static gssize
g_socket_output_stream_pollable_write_nonblocking (GPollableOutputStream  *pollable,
			   const void             *buffer,
			   gsize                   size,
			   GError                **error)
{
  GSocketOutputStream *output_stream = G_SOCKET_OUTPUT_STREAM (pollable);

  return g_socket_send_with_blocking ((GSocket *) output_stream->priv,
		      buffer, size, FALSE,
		      NULL, error);
}*/

static void
g_socket_output_stream_pollable_iface_init (GPollableOutputStreamInterface *iface)
{
  iface->is_writable = g_socket_output_stream_pollable_is_writable;
  iface->create_source = g_socket_output_stream_pollable_create_source;
/*  iface->write_nonblocking = g_socket_output_stream_pollable_write_nonblocking;*/
}

#include <sys/types.h>
#include <sys/socket.h>

static GType gsis_t = 0, gsos_t = 0;

static void
discover_gsios_t ()
{
  /* Somehow in CentOS glib cannot link G_TYPE_SOCKET_INPUT/OUTPUT_STREAM,
     so we will get those types this way.  */

  GSocket *s;
  GIOStream *c;
  int sv[2];

  socketpair (AF_UNIX, SOCK_STREAM, 0, sv);

  s = G_SOCKET (g_object_new (G_TYPE_SOCKET, "fd", sv[0], "family", G_SOCKET_FAMILY_IPV4, "type", G_SOCKET_TYPE_STREAM, NULL));
  c = G_IO_STREAM (g_object_new (G_TYPE_SOCKET_CONNECTION, "socket", s, NULL));

  gsis_t = G_OBJECT_TYPE (g_io_stream_get_input_stream (c));
  gsos_t = G_OBJECT_TYPE (g_io_stream_get_output_stream (c));

  g_object_unref (c);

  g_socket_close (s, NULL);
  g_object_unref (s);

  close (sv[1]);
}

GType
xr_g_socket_input_stream_get_type ()
{
  if (!gsis_t)
    discover_gsios_t ();

  return gsis_t;
}

GType
xr_g_socket_output_stream_get_type ()
{
  if (!gsos_t)
    discover_gsios_t ();

  return gsos_t;
}

void
xr_g_tls_init ()
{
  static gint loaded = 0;

  if (!loaded)
    {
      GType g_define_type_id;

      g_define_type_id = G_TYPE_SOCKET_INPUT_STREAM;
      G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM, g_socket_input_stream_pollable_iface_init);

      g_define_type_id = G_TYPE_SOCKET_OUTPUT_STREAM;
      G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM, g_socket_output_stream_pollable_iface_init);

      loaded = 1;
    }
}

static gpointer
get_default_tls_backend (gpointer arg)
{
  return g_object_new (G_TYPE_TLS_BACKEND_GNUTLS, NULL);
}

/**
 * g_tls_backend_get_default:
 *
 * Gets the default #GTlsBackend for the system.
 *
 * Returns: (transfer none): a #GTlsBackend
 *
 * Since: 2.28
 */
GTlsBackend *
g_tls_backend_get_default (void)
{
  static GOnce once_init = G_ONCE_INIT;

  return g_once (&once_init, get_default_tls_backend, NULL);
}

/**
 * g_tls_backend_supports_tls:
 * @backend: the #GTlsBackend
 *
 * Checks if TLS is supported; if this returns %FALSE for the default
 * #GTlsBackend, it means no "real" TLS backend is available.
 *
 * Return value: whether or not TLS is supported
 *
 * Since: 2.28
 */
gboolean
g_tls_backend_supports_tls (GTlsBackend *backend)
{
  if (G_TLS_BACKEND_GET_INTERFACE (backend)->supports_tls)
    return G_TLS_BACKEND_GET_INTERFACE (backend)->supports_tls (backend);
  else
    return TRUE;
}

/**
 * g_tls_backend_get_default_database:
 * @backend: the #GTlsBackend
 *
 * Gets the default #GTlsDatabase used to verify TLS connections.
 *
 * Return value: (transfer full): the default database, which should be
 *               unreffed when done.
 *
 * Since: 2.30
 */
GTlsDatabase *
g_tls_backend_get_default_database (GTlsBackend *backend)
{
  g_return_val_if_fail (G_IS_TLS_BACKEND (backend), NULL);

  /* This method was added later, so accept the (remote) possibility it can be NULL */
  if (!G_TLS_BACKEND_GET_INTERFACE (backend)->get_default_database)
    return NULL;

  return G_TLS_BACKEND_GET_INTERFACE (backend)->get_default_database (backend);
}

/**
 * g_tls_backend_get_certificate_type:
 * @backend: the #GTlsBackend
 *
 * Gets the #GType of @backend's #GTlsCertificate implementation.
 *
 * Return value: the #GType of @backend's #GTlsCertificate
 *   implementation.
 *
 * Since: 2.28
 */
GType
g_tls_backend_get_certificate_type (GTlsBackend *backend)
{
  return G_TLS_BACKEND_GET_INTERFACE (backend)->get_certificate_type ();
}

/**
 * g_tls_backend_get_client_connection_type:
 * @backend: the #GTlsBackend
 *
 * Gets the #GType of @backend's #GTlsClientConnection implementation.
 *
 * Return value: the #GType of @backend's #GTlsClientConnection
 *   implementation.
 *
 * Since: 2.28
 */
GType
g_tls_backend_get_client_connection_type (GTlsBackend *backend)
{
  return G_TLS_BACKEND_GET_INTERFACE (backend)->get_client_connection_type ();
}

/**
 * g_tls_backend_get_server_connection_type:
 * @backend: the #GTlsBackend
 *
 * Gets the #GType of @backend's #GTlsServerConnection implementation.
 *
 * Return value: the #GType of @backend's #GTlsServerConnection
 *   implementation.
 *
 * Since: 2.28
 */
GType
g_tls_backend_get_server_connection_type (GTlsBackend *backend)
{
  return G_TLS_BACKEND_GET_INTERFACE (backend)->get_server_connection_type ();
}

/**
 * g_tls_backend_get_file_database_type:
 * @backend: the #GTlsBackend
 *
 * Gets the #GTyep of @backend's #GTlsFileDatabase implementation.
 *
 * Return value: the #GType of backend's #GTlsFileDatabase implementation.
 *
 * Since: 2.30
 */
GType
g_tls_backend_get_file_database_type (GTlsBackend *backend)
{
  g_return_val_if_fail (G_IS_TLS_BACKEND (backend), 0);

  /* This method was added later, so accept the (remote) possibility it can be NULL */
  if (!G_TLS_BACKEND_GET_INTERFACE (backend)->get_file_database_type)
    return 0;

  return G_TLS_BACKEND_GET_INTERFACE (backend)->get_file_database_type ();
}
