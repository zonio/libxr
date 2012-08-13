#ifndef __LIBXR_GIO_H__
#define __LIBXR_GIO_H__

/**
 * G_DEFINE_INTERFACE:
 * @TN: The name of the new type, in Camel case.
 * @t_n: The name of the new type, in lowercase, with words separated by '_'.
 * @T_P: The #GType of the prerequisite type for the interface, or 0
 * (%G_TYPE_INVALID) for no prerequisite type.
 *
 * A convenience macro for #GTypeInterface definitions, which declares
 * a default vtable initialization function and defines a *_get_type()
 * function.
 *
 * The macro expects the interface initialization function to have the
 * name <literal>t_n ## _default_init</literal>, and the interface
 * structure to have the name <literal>TN ## Interface</literal>.
 *
 * Since: 2.24
 */
#define G_DEFINE_INTERFACE(TN, t_n, T_P)		    G_DEFINE_INTERFACE_WITH_CODE(TN, t_n, T_P, ;)

/**
 * G_DEFINE_INTERFACE_WITH_CODE:
 * @TN: The name of the new type, in Camel case.
 * @t_n: The name of the new type, in lowercase, with words separated by '_'.
 * @T_P: The #GType of the prerequisite type for the interface, or 0
 * (%G_TYPE_INVALID) for no prerequisite type.
 * @_C_: Custom code that gets inserted in the *_get_type() function.
 *
 * A convenience macro for #GTypeInterface definitions. Similar to
 * G_DEFINE_INTERFACE(), but allows you to insert custom code into the
 * *_get_type() function, e.g. additional interface implementations
 * via G_IMPLEMENT_INTERFACE(), or additional prerequisite types. See
 * G_DEFINE_TYPE_EXTENDED() for a similar example using
 * G_DEFINE_TYPE_WITH_CODE().
 *
 * Since: 2.24
 */
#define G_DEFINE_INTERFACE_WITH_CODE(TN, t_n, T_P, _C_)     _G_DEFINE_INTERFACE_EXTENDED_BEGIN(TN, t_n, T_P) {_C_;} _G_DEFINE_INTERFACE_EXTENDED_END()

/**
 * G_IMPLEMENT_INTERFACE:
 * @TYPE_IFACE: The #GType of the interface to add
 * @iface_init: The interface init function
 *
 * A convenience macro to ease interface addition in the @_C_ section
 * of G_DEFINE_TYPE_WITH_CODE() or G_DEFINE_ABSTRACT_TYPE_WITH_CODE().
 * See G_DEFINE_TYPE_EXTENDED() for an example.
 *
 * Note that this macro can only be used together with the G_DEFINE_TYPE_*
 * macros, since it depends on variable names from those macros.
 *
 * Since: 2.4
 */
#define G_IMPLEMENT_INTERFACE(TYPE_IFACE, iface_init)       { \
  const GInterfaceInfo g_implement_interface_info = { \
    (GInterfaceInitFunc) iface_init, NULL, NULL \
  }; \
  g_type_add_interface_static (g_define_type_id, TYPE_IFACE, &g_implement_interface_info); \
}

#define _G_DEFINE_TYPE_EXTENDED_BEGIN(TypeName, type_name, TYPE_PARENT, flags) \
\
static void     type_name##_init              (TypeName        *self); \
static void     type_name##_class_init        (TypeName##Class *klass); \
static gpointer type_name##_parent_class = NULL; \
static void     type_name##_class_intern_init (gpointer klass) \
{ \
  type_name##_parent_class = g_type_class_peek_parent (klass); \
  type_name##_class_init ((TypeName##Class*) klass); \
} \
\
GType \
type_name##_get_type (void) \
{ \
  static volatile gsize g_define_type_id__volatile = 0; \
  if (g_once_init_enter (&g_define_type_id__volatile))  \
    { \
      GType g_define_type_id = \
        g_type_register_static_simple (TYPE_PARENT, \
                                       g_intern_static_string (#TypeName), \
                                       sizeof (TypeName##Class), \
                                       (GClassInitFunc) type_name##_class_intern_init, \
                                       sizeof (TypeName), \
                                       (GInstanceInitFunc) type_name##_init, \
                                       (GTypeFlags) flags); \
      { /* custom code follows */
#define _G_DEFINE_TYPE_EXTENDED_END()	\
        /* following custom code */	\
      }					\
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id); \
    }					\
  return g_define_type_id__volatile;	\
} /* closes type_name##_get_type() */

#define _G_DEFINE_INTERFACE_EXTENDED_BEGIN(TypeName, type_name, TYPE_PREREQ) \
\
static void     type_name##_default_init        (TypeName##Interface *klass); \
\
GType \
type_name##_get_type (void) \
{ \
  static volatile gsize g_define_type_id__volatile = 0; \
  if (g_once_init_enter (&g_define_type_id__volatile))  \
    { \
      GType g_define_type_id = \
        g_type_register_static_simple (G_TYPE_INTERFACE, \
                                       g_intern_static_string (#TypeName), \
                                       sizeof (TypeName##Interface), \
                                       (GClassInitFunc)type_name##_default_init, \
                                       0, \
                                       (GInstanceInitFunc)NULL, \
                                       (GTypeFlags) 0); \
      if (TYPE_PREREQ) \
        g_type_interface_add_prerequisite (g_define_type_id, TYPE_PREREQ); \
      { /* custom code follows */
#define _G_DEFINE_INTERFACE_EXTENDED_END()	\
        /* following custom code */		\
      }						\
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id); \
    }						\
  return g_define_type_id__volatile;			\
} /* closes type_name##_get_type() */


#include <errno.h>
#include <glib.h>
#include <gio/gio.h>
#include <gio/gunixinputstream.h>
#include <gio/gunixoutputstream.h>

typedef struct _GTlsCertificate               GTlsCertificate;
typedef struct _GTlsClientConnection          GTlsClientConnection; /* Dummy typedef */
typedef struct _GTlsConnection                GTlsConnection;
typedef struct _GTlsDatabase                  GTlsDatabase;
typedef struct _GTlsFileDatabase              GTlsFileDatabase;
typedef struct _GTlsInteraction               GTlsInteraction;
typedef struct _GTlsPassword                  GTlsPassword;
typedef struct _GTlsServerConnection          GTlsServerConnection; /* Dummy typedef */
typedef struct _GPollableInputStream          GPollableInputStream; /* Dummy typedef */
typedef struct _GPollableOutputStream         GPollableOutputStream; /* Dummy typedef */

typedef gboolean (*GPollableSourceFunc) (GObject  *pollable_stream, gpointer  user_data);


GType g_tls_error_get_type (void) G_GNUC_CONST;
#define G_TYPE_TLS_ERROR (g_tls_error_get_type ())
GType g_tls_certificate_flags_get_type (void) G_GNUC_CONST;
#define G_TYPE_TLS_CERTIFICATE_FLAGS (g_tls_certificate_flags_get_type ())
GType g_tls_authentication_mode_get_type (void) G_GNUC_CONST;
#define G_TYPE_TLS_AUTHENTICATION_MODE (g_tls_authentication_mode_get_type ())
GType g_tls_rehandshake_mode_get_type (void) G_GNUC_CONST;
#define G_TYPE_TLS_REHANDSHAKE_MODE (g_tls_rehandshake_mode_get_type ())
GType g_tls_password_flags_get_type (void) G_GNUC_CONST;
#define G_TYPE_TLS_PASSWORD_FLAGS (g_tls_password_flags_get_type ())
GType g_tls_interaction_result_get_type (void) G_GNUC_CONST;
#define G_TYPE_TLS_INTERACTION_RESULT (g_tls_interaction_result_get_type ())
GType g_tls_database_verify_flags_get_type (void) G_GNUC_CONST;
#define G_TYPE_TLS_DATABASE_VERIFY_FLAGS (g_tls_database_verify_flags_get_type ())
GType g_tls_database_lookup_flags_get_type (void) G_GNUC_CONST;
#define G_TYPE_TLS_DATABASE_LOOKUP_FLAGS (g_tls_database_lookup_flags_get_type ())

/**
 * GTlsError:
 * @G_TLS_ERROR_UNAVAILABLE: No TLS provider is available
 * @G_TLS_ERROR_MISC: Miscellaneous TLS error
 * @G_TLS_ERROR_BAD_CERTIFICATE: A certificate could not be parsed
 * @G_TLS_ERROR_NOT_TLS: The TLS handshake failed because the
 *   peer does not seem to be a TLS server.
 * @G_TLS_ERROR_HANDSHAKE: The TLS handshake failed because the
 *   peer's certificate was not acceptable.
 * @G_TLS_ERROR_CERTIFICATE_REQUIRED: The TLS handshake failed because
 *   the server requested a client-side certificate, but none was
 *   provided. See g_tls_connection_set_certificate().
 * @G_TLS_ERROR_EOF: The TLS connection was closed without proper
 *   notice, which may indicate an attack. See
 *   g_tls_connection_set_require_close_notify().
 *
 * An error code used with %G_TLS_ERROR in a #GError returned from a
 * TLS-related routine.
 *
 * Since: 2.28
 */
typedef enum {
  G_TLS_ERROR_UNAVAILABLE,
  G_TLS_ERROR_MISC,
  G_TLS_ERROR_BAD_CERTIFICATE,
  G_TLS_ERROR_NOT_TLS,
  G_TLS_ERROR_HANDSHAKE,
  G_TLS_ERROR_CERTIFICATE_REQUIRED,
  G_TLS_ERROR_EOF
} GTlsError;

/**
 * GTlsCertificateFlags:
 * @G_TLS_CERTIFICATE_UNKNOWN_CA: The signing certificate authority is
 *   not known.
 * @G_TLS_CERTIFICATE_BAD_IDENTITY: The certificate does not match the
 *   expected identity of the site that it was retrieved from.
 * @G_TLS_CERTIFICATE_NOT_ACTIVATED: The certificate's activation time
 *   is still in the future
 * @G_TLS_CERTIFICATE_EXPIRED: The certificate has expired
 * @G_TLS_CERTIFICATE_REVOKED: The certificate has been revoked
 *   according to the #GTlsConnection's certificate revocation list.
 * @G_TLS_CERTIFICATE_INSECURE: The certificate's algorithm is
 *   considered insecure.
 * @G_TLS_CERTIFICATE_GENERIC_ERROR: Some other error occurred validating
 *   the certificate
 * @G_TLS_CERTIFICATE_VALIDATE_ALL: the combination of all of the above
 *   flags
 *
 * A set of flags describing TLS certification validation. This can be
 * used to set which validation steps to perform (eg, with
 * g_tls_client_connection_set_validation_flags()), or to describe why
 * a particular certificate was rejected (eg, in
 * #GTlsConnection::accept-certificate).
 *
 * Since: 2.28
 */
typedef enum {
  G_TLS_CERTIFICATE_UNKNOWN_CA    = (1 << 0),
  G_TLS_CERTIFICATE_BAD_IDENTITY  = (1 << 1),
  G_TLS_CERTIFICATE_NOT_ACTIVATED = (1 << 2),
  G_TLS_CERTIFICATE_EXPIRED       = (1 << 3),
  G_TLS_CERTIFICATE_REVOKED       = (1 << 4),
  G_TLS_CERTIFICATE_INSECURE      = (1 << 5),
  G_TLS_CERTIFICATE_GENERIC_ERROR = (1 << 6),

  G_TLS_CERTIFICATE_VALIDATE_ALL  = 0x007f
} GTlsCertificateFlags;

/**
 * GTlsAuthenticationMode:
 * @G_TLS_AUTHENTICATION_NONE: client authentication not required
 * @G_TLS_AUTHENTICATION_REQUESTED: client authentication is requested
 * @G_TLS_AUTHENTICATION_REQUIRED: client authentication is required
 *
 * The client authentication mode for a #GTlsServerConnection.
 *
 * Since: 2.28
 */
typedef enum {
  G_TLS_AUTHENTICATION_NONE,
  G_TLS_AUTHENTICATION_REQUESTED,
  G_TLS_AUTHENTICATION_REQUIRED
} GTlsAuthenticationMode;

/**
 * GTlsRehandshakeMode:
 * @G_TLS_REHANDSHAKE_NEVER: Never allow rehandshaking
 * @G_TLS_REHANDSHAKE_SAFELY: Allow safe rehandshaking only
 * @G_TLS_REHANDSHAKE_UNSAFELY: Allow unsafe rehandshaking
 *
 * When to allow rehandshaking. See
 * g_tls_connection_set_rehandshake_mode().
 *
 * Since: 2.28
 */
typedef enum {
  G_TLS_REHANDSHAKE_NEVER,
  G_TLS_REHANDSHAKE_SAFELY,
  G_TLS_REHANDSHAKE_UNSAFELY
} GTlsRehandshakeMode;

/**
 * GTlsPasswordFlags:
 * @G_TLS_PASSWORD_NONE: No flags
 * @G_TLS_PASSWORD_RETRY: The password was wrong, and the user should retry.
 * @G_TLS_PASSWORD_MANY_TRIES: Hint to the user that the password has been
 *    wrong many times, and the user may not have many chances left.
 * @G_TLS_PASSWORD_FINAL_TRY: Hint to the user that this is the last try to get
 *    this password right.
 *
 * Various flags for the password.
 *
 * Since: 2.30
 */

typedef enum _GTlsPasswordFlags
{
  G_TLS_PASSWORD_NONE = 0,
  G_TLS_PASSWORD_RETRY = 1 << 1,
  G_TLS_PASSWORD_MANY_TRIES = 1 << 2,
  G_TLS_PASSWORD_FINAL_TRY = 1 << 3
} GTlsPasswordFlags;

/**
 * GTlsInteractionResult:
 * @G_TLS_INTERACTION_UNHANDLED: The interaction was unhandled (i.e. not
 *     implemented).
 * @G_TLS_INTERACTION_HANDLED: The interaction completed, and resulting data
 *     is available.
 * @G_TLS_INTERACTION_FAILED: The interaction has failed, or was cancelled.
 *     and the operation should be aborted.
 *
 * #GTlsInteractionResult is returned by various functions in #GTlsInteraction
 * when finishing an interaction request.
 *
 * Since: 2.30
 */
typedef enum {
  G_TLS_INTERACTION_UNHANDLED,
  G_TLS_INTERACTION_HANDLED,
  G_TLS_INTERACTION_FAILED
} GTlsInteractionResult;

/**
 * GTlsDatabaseVerifyFlags:
 * @G_TLS_DATABASE_VERIFY_NONE: No verification flags
 *
 * Flags for g_tls_database_verify_chain().
 *
 * Since: 2.30
 */
typedef enum {
  G_TLS_DATABASE_VERIFY_NONE = 0
} GTlsDatabaseVerifyFlags;

/**
 * GTlsDatabaseLookupFlags:
 * @G_TLS_DATABASE_LOOKUP_NONE: No lookup flags
 * @G_TLS_DATABASE_LOOKUP_KEYPAIR: Restrict lookup to certificates that have
 *     a private key.
 *
 * Flags for g_tls_database_lookup_handle(), g_tls_database_lookup_issuer(),
 * and g_tls_database_lookup_issued().
 *
 * Since: 2.30
 */
typedef enum {
  G_TLS_DATABASE_LOOKUP_NONE = 0,
  G_TLS_DATABASE_LOOKUP_KEYPAIR = 1
} GTlsDatabaseLookupFlags;

#include "gasynchelper.h"
#include "gpollableinputstream.h"
#include "gpollableoutputstream.h"
#include "gsocketinputstream.h"
#include "gsocketoutputstream.h"
#include "gsourceclosure.h"
#include "gtlsbackend.h"
#include "gtlscertificate.h"
#include "gtlsclientconnection.h"
#include "gtlsconnection.h"
#include "gtlsdatabase.h"
#include "gtlsfiledatabase.h"
#include "gtlsinteraction.h"
#include "gtlsserverconnection.h"
#include "gtlspassword.h"

static inline void
g_clear_object (volatile GObject **object_ptr)
{
  gpointer *ptr = (gpointer) object_ptr;
  gpointer old;                         

  /* This is a little frustrating.
   * Would be nice to have an atomic exchange (with no compare).
   */
  do
    old = g_atomic_pointer_get (ptr);
  while G_UNLIKELY (!g_atomic_pointer_compare_and_exchange (ptr, old, NULL));

  if (old)
    g_object_unref (old);
}

static inline void
g_source_set_name (GSource    *source,
                   const char *name)
{
}

#include <ffi.h>
static ffi_type *
value_to_ffi_type (const GValue *gvalue, gpointer *value)
{
  ffi_type *rettype = NULL;
  GType type = g_type_fundamental (G_VALUE_TYPE (gvalue));
  g_assert (type != G_TYPE_INVALID);

  switch (type)
    {
    case G_TYPE_BOOLEAN:
    case G_TYPE_CHAR:
    case G_TYPE_INT:
    case G_TYPE_ENUM:
      rettype = &ffi_type_sint;
      *value = (gpointer)&(gvalue->data[0].v_int);
      break;
    case G_TYPE_UCHAR:
    case G_TYPE_UINT:
    case G_TYPE_FLAGS:
      rettype = &ffi_type_uint;
      *value = (gpointer)&(gvalue->data[0].v_uint);
      break;
    case G_TYPE_STRING:
    case G_TYPE_OBJECT:
    case G_TYPE_BOXED:
    case G_TYPE_PARAM:
    case G_TYPE_POINTER:
    case G_TYPE_INTERFACE:
/*    case G_TYPE_VARIANT:*/
      rettype = &ffi_type_pointer;
      *value = (gpointer)&(gvalue->data[0].v_pointer);
      break;
    case G_TYPE_FLOAT:
      rettype = &ffi_type_float;
      *value = (gpointer)&(gvalue->data[0].v_float);
      break;
    case G_TYPE_DOUBLE:
      rettype = &ffi_type_double;
      *value = (gpointer)&(gvalue->data[0].v_double);
      break;
    case G_TYPE_LONG:
      rettype = &ffi_type_slong;
      *value = (gpointer)&(gvalue->data[0].v_long);
      break;
    case G_TYPE_ULONG:
      rettype = &ffi_type_ulong;
      *value = (gpointer)&(gvalue->data[0].v_ulong);
      break;
    case G_TYPE_INT64:
      rettype = &ffi_type_sint64;
      *value = (gpointer)&(gvalue->data[0].v_int64);
      break;
    case G_TYPE_UINT64:
      rettype = &ffi_type_uint64;
      *value = (gpointer)&(gvalue->data[0].v_uint64);
      break;
    default:
      rettype = &ffi_type_pointer;
      *value = NULL;
      g_warning ("value_to_ffi_type: Unsupported fundamental type: %s", g_type_name (type));
      break;
    }
  return rettype;
}

static void
value_from_ffi_type (GValue *gvalue, gpointer *value)
{
  switch (g_type_fundamental (G_VALUE_TYPE (gvalue)))
    {
    case G_TYPE_INT:
      g_value_set_int (gvalue, *(gint*)value);
      break;
    case G_TYPE_FLOAT:
      g_value_set_float (gvalue, *(gfloat*)value);
      break;
    case G_TYPE_DOUBLE:
      g_value_set_double (gvalue, *(gdouble*)value);
      break;
    case G_TYPE_BOOLEAN:
      g_value_set_boolean (gvalue, *(gboolean*)value);
      break;
    case G_TYPE_STRING:
      g_value_set_string (gvalue, *(gchar**)value);
      break;
    case G_TYPE_CHAR:
      g_value_set_char (gvalue, *(gchar*)value);
      break;
    case G_TYPE_UCHAR:
      g_value_set_uchar (gvalue, *(guchar*)value);
      break;
    case G_TYPE_UINT:
      g_value_set_uint (gvalue, *(guint*)value);
      break;
    case G_TYPE_POINTER:
      g_value_set_pointer (gvalue, *(gpointer*)value);
      break;
    case G_TYPE_LONG:
      g_value_set_long (gvalue, *(glong*)value);
      break;
    case G_TYPE_ULONG:
      g_value_set_ulong (gvalue, *(gulong*)value);
      break;
    case G_TYPE_INT64:
      g_value_set_int64 (gvalue, *(gint64*)value);
      break;
    case G_TYPE_UINT64:
      g_value_set_uint64 (gvalue, *(guint64*)value);
      break;
    case G_TYPE_BOXED:
      g_value_set_boxed (gvalue, *(gpointer*)value);
      break;
    case G_TYPE_ENUM:
      g_value_set_enum (gvalue, *(gint*)value);
      break;
    case G_TYPE_FLAGS:
      g_value_set_flags (gvalue, *(guint*)value);
      break;
    case G_TYPE_PARAM:
      g_value_set_param (gvalue, *(gpointer*)value);
      break;
    case G_TYPE_OBJECT:
      g_value_set_object (gvalue, *(gpointer*)value);
      break;
    default:
      g_warning ("value_from_ffi_type: Unsupported fundamental type: %s",
                g_type_name (g_type_fundamental (G_VALUE_TYPE (gvalue))));
    }
}

/**
 * g_cclosure_marshal_generic:
 * @closure: A #GClosure.
 * @return_gvalue: A #GValue to store the return value. May be %NULL
 *   if the callback of closure doesn't return a value.
 * @n_param_values: The length of the @param_values array.
 * @param_values: An array of #GValue<!-- -->s holding the arguments
 *   on which to invoke the callback of closure.
 * @invocation_hint: The invocation hint given as the last argument to
 *   g_closure_invoke().
 * @marshal_data: Additional data specified when registering the
 *   marshaller, see g_closure_set_marshal() and
 *   g_closure_set_meta_marshal()
 *
 * A generic marshaller function implemented via <ulink
 * url="http://sourceware.org/libffi/">libffi</ulink>.
 *
 * Since: 2.30
 */
static void
g_cclosure_marshal_generic (GClosure     *closure,
                            GValue       *return_gvalue,
                            guint         n_param_values,
                            const GValue *param_values,
                            gpointer      invocation_hint,
                            gpointer      marshal_data)
{
  ffi_type *rtype;
  void *rvalue;
  int n_args;
  ffi_type **atypes;
  void **args;
  int i;
  ffi_cif cif;
  GCClosure *cc = (GCClosure*) closure;

  if (return_gvalue && G_VALUE_TYPE (return_gvalue))
    {
      rtype = value_to_ffi_type (return_gvalue, &rvalue);
    }
  else
    {
      rtype = &ffi_type_void;
    }

  rvalue = g_alloca (MAX (rtype->size, sizeof (ffi_arg)));

  n_args = n_param_values + 1;
  atypes = g_alloca (sizeof (ffi_type *) * n_args);
  args =  g_alloca (sizeof (gpointer) * n_args);

  if (G_CCLOSURE_SWAP_DATA (closure))
    {
      atypes[n_args-1] = value_to_ffi_type (param_values + 0,
                                            &args[n_args-1]);
      atypes[0] = &ffi_type_pointer;
      args[0] = &closure->data;
    }
  else
    {
      atypes[0] = value_to_ffi_type (param_values + 0, &args[0]);
      atypes[n_args-1] = &ffi_type_pointer;
      args[n_args-1] = &closure->data;
    }

  for (i = 1; i < n_args - 1; i++)
    atypes[i] = value_to_ffi_type (param_values + i, &args[i]);

  if (ffi_prep_cif (&cif, FFI_DEFAULT_ABI, n_args, rtype, atypes) != FFI_OK)
    return;

  ffi_call (&cif, marshal_data ? marshal_data : cc->callback, rvalue, args);

  if (return_gvalue && G_VALUE_TYPE (return_gvalue))
    value_from_ffi_type (return_gvalue, rvalue);
}

static void
g_source_add_child_source (GSource *source, GSource *child_source)
{
/*  GMainContext *context;

  g_return_if_fail (source != NULL);
  g_return_if_fail (child_source != NULL);
  g_return_if_fail (!SOURCE_DESTROYED (source));
  g_return_if_fail (!SOURCE_DESTROYED (child_source));
  g_return_if_fail (child_source->context == NULL);
  g_return_if_fail (child_source->priv == NULL || child_source->priv->parent_source == NULL);

  context = source->context;

  if (context)
    LOCK_CONTEXT (context);

  if (!source->priv)
    source->priv = g_slice_new0 (GSourcePrivate);
  if (!child_source->priv)
    child_source->priv = g_slice_new0 (GSourcePrivate);

  source->priv->child_sources = g_slist_prepend (source->priv->child_sources, g_source_ref (child_source));
  child_source->priv->parent_source = source;
  g_source_set_priority_unlocked (child_source, context, source->priority);

  if (context)
    {
      UNLOCK_CONTEXT (context);
      g_source_attach (child_source, context);
    }*/
}

static void
g_source_remove_child_source (GSource *source, GSource *child_source)
{
}


#endif /* __LIBXR_GIO_H__ */

