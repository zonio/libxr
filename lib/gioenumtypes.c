#include "gio.h"

GType
g_tls_error_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      static const GEnumValue values[] = {
        { G_TLS_ERROR_UNAVAILABLE, "G_TLS_ERROR_UNAVAILABLE", "unavailable" },
        { G_TLS_ERROR_MISC, "G_TLS_ERROR_MISC", "misc" },
        { G_TLS_ERROR_BAD_CERTIFICATE, "G_TLS_ERROR_BAD_CERTIFICATE", "bad-certificate" },
        { G_TLS_ERROR_NOT_TLS, "G_TLS_ERROR_NOT_TLS", "not-tls" },
        { G_TLS_ERROR_HANDSHAKE, "G_TLS_ERROR_HANDSHAKE", "handshake" },
        { G_TLS_ERROR_CERTIFICATE_REQUIRED, "G_TLS_ERROR_CERTIFICATE_REQUIRED", "certificate-required" },
        { G_TLS_ERROR_EOF, "G_TLS_ERROR_EOF", "eof" },
        { 0, NULL, NULL }
      };
      GType g_define_type_id =
        g_enum_register_static (g_intern_static_string ("GTlsError"), values);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }

  return g_define_type_id__volatile;
}

GType
g_tls_certificate_flags_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      static const GFlagsValue values[] = {
        { G_TLS_CERTIFICATE_UNKNOWN_CA, "G_TLS_CERTIFICATE_UNKNOWN_CA", "unknown-ca" },
        { G_TLS_CERTIFICATE_BAD_IDENTITY, "G_TLS_CERTIFICATE_BAD_IDENTITY", "bad-identity" },
        { G_TLS_CERTIFICATE_NOT_ACTIVATED, "G_TLS_CERTIFICATE_NOT_ACTIVATED", "not-activated" },
        { G_TLS_CERTIFICATE_EXPIRED, "G_TLS_CERTIFICATE_EXPIRED", "expired" },
        { G_TLS_CERTIFICATE_REVOKED, "G_TLS_CERTIFICATE_REVOKED", "revoked" },
        { G_TLS_CERTIFICATE_INSECURE, "G_TLS_CERTIFICATE_INSECURE", "insecure" },
        { G_TLS_CERTIFICATE_GENERIC_ERROR, "G_TLS_CERTIFICATE_GENERIC_ERROR", "generic-error" },
        { G_TLS_CERTIFICATE_VALIDATE_ALL, "G_TLS_CERTIFICATE_VALIDATE_ALL", "validate-all" },
        { 0, NULL, NULL }
      };
      GType g_define_type_id =
        g_flags_register_static (g_intern_static_string ("GTlsCertificateFlags"), values);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }

  return g_define_type_id__volatile;
}

GType
g_tls_authentication_mode_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      static const GEnumValue values[] = {
        { G_TLS_AUTHENTICATION_NONE, "G_TLS_AUTHENTICATION_NONE", "none" },
        { G_TLS_AUTHENTICATION_REQUESTED, "G_TLS_AUTHENTICATION_REQUESTED", "requested" },
        { G_TLS_AUTHENTICATION_REQUIRED, "G_TLS_AUTHENTICATION_REQUIRED", "required" },
        { 0, NULL, NULL }
      };
      GType g_define_type_id =
        g_enum_register_static (g_intern_static_string ("GTlsAuthenticationMode"), values);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }

  return g_define_type_id__volatile;
}

GType
g_tls_rehandshake_mode_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      static const GEnumValue values[] = {
        { G_TLS_REHANDSHAKE_NEVER, "G_TLS_REHANDSHAKE_NEVER", "never" },
        { G_TLS_REHANDSHAKE_SAFELY, "G_TLS_REHANDSHAKE_SAFELY", "safely" },
        { G_TLS_REHANDSHAKE_UNSAFELY, "G_TLS_REHANDSHAKE_UNSAFELY", "unsafely" },
        { 0, NULL, NULL }
      };
      GType g_define_type_id =
        g_enum_register_static (g_intern_static_string ("GTlsRehandshakeMode"), values);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }

  return g_define_type_id__volatile;
}

GType
g_tls_password_flags_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      static const GFlagsValue values[] = {
        { G_TLS_PASSWORD_NONE, "G_TLS_PASSWORD_NONE", "none" },
        { G_TLS_PASSWORD_RETRY, "G_TLS_PASSWORD_RETRY", "retry" },
        { G_TLS_PASSWORD_MANY_TRIES, "G_TLS_PASSWORD_MANY_TRIES", "many-tries" },
        { G_TLS_PASSWORD_FINAL_TRY, "G_TLS_PASSWORD_FINAL_TRY", "final-try" },
        { 0, NULL, NULL }
      };
      GType g_define_type_id =
        g_flags_register_static (g_intern_static_string ("GTlsPasswordFlags"), values);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }

  return g_define_type_id__volatile;
}

GType
g_tls_interaction_result_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      static const GEnumValue values[] = {
        { G_TLS_INTERACTION_UNHANDLED, "G_TLS_INTERACTION_UNHANDLED", "unhandled" },
        { G_TLS_INTERACTION_HANDLED, "G_TLS_INTERACTION_HANDLED", "handled" },
        { G_TLS_INTERACTION_FAILED, "G_TLS_INTERACTION_FAILED", "failed" },
        { 0, NULL, NULL }
      };
      GType g_define_type_id =
        g_enum_register_static (g_intern_static_string ("GTlsInteractionResult"), values);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }

  return g_define_type_id__volatile;
}

GType
g_tls_database_verify_flags_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      static const GEnumValue values[] = {
        { G_TLS_DATABASE_VERIFY_NONE, "G_TLS_DATABASE_VERIFY_NONE", "none" },
        { 0, NULL, NULL }
      };
      GType g_define_type_id =
        g_enum_register_static (g_intern_static_string ("GTlsDatabaseVerifyFlags"), values);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }

  return g_define_type_id__volatile;
}

GType
g_tls_database_lookup_flags_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      static const GEnumValue values[] = {
        { G_TLS_DATABASE_LOOKUP_NONE, "G_TLS_DATABASE_LOOKUP_NONE", "none" },
        { G_TLS_DATABASE_LOOKUP_KEYPAIR, "G_TLS_DATABASE_LOOKUP_KEYPAIR", "keypair" },
        { 0, NULL, NULL }
      };
      GType g_define_type_id =
        g_enum_register_static (g_intern_static_string ("GTlsDatabaseLookupFlags"), values);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }

  return g_define_type_id__volatile;
}
