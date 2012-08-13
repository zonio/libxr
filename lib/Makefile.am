EXTRA_DIST = \
  xml-priv.h \
  xr-utils.h \
  xr-call-xml-rpc.c \
  xr-call-json-rpc.c

AM_CFLAGS= \
  $(GLIB_CFLAGS) \
  $(GNUTLS_CFLAGS) \
  $(GCRYPT_CFLAGS) \
  $(XML_CFLAGS) \
  $(JSON_CFLAGS) \
  $(LIBFFI_CFLAGS) \
  -I$(top_srcdir) \
  -I$(top_srcdir)/include \
  -D_REENTRANT \
  -D_GNU_SOURCE \
  -DGIO_COMPILATION

lib_LTLIBRARIES = \
  libxr.la

libxr_la_LIBADD = \
  $(GLIB_LIBS) \
  $(GNUTLS_LIBS) \
  $(GCRYPT_LIBS) \
  $(XML_LIBS) \
  $(JSON_LIBS) \
  $(WIN32LIBS) \
  $(LIBFFI_LIBS)

libxr_la_LDFLAGS = -version-info $(LIB_XR_VERSION) -no-undefined

libxr_la_SOURCES = \
  gasynchelper.c \
  gioenumtypes.c \
  gnutls-marshal.c \
  gpollableinputstream.c \
  gpollableoutputstream.c \
  gsourceclosure.c \
  gtlsbackend.c \
  gtlsbackend-gnutls.c \
  gtlscertificate.c \
  gtlscertificate-gnutls.c \
  gtlsclientconnection.c \
  gtlsclientconnection-gnutls.c \
  gtlsconnection.c \
  gtlsconnection-gnutls.c \
  gtlsdatabase.c \
  gtlsdatabase-gnutls.c \
  gtlsfiledatabase.c \
  gtlsfiledatabase-gnutls.c \
  gtlsinputstream-gnutls.c \
  gtlsinteraction.c \
  gtlsoutputstream-gnutls.c \
  gtlspassword.c \
  gtlsserverconnection.c \
  gtlsserverconnection-gnutls.c \
  xr-lib.c \
  xr-value.c \
  xr-call.c \
  xr-client.c \
  xr-server.c \
  xr-http.c \
  xr-utils.c \
  xr-value-utils.c
