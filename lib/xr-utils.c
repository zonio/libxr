#ifdef WIN32
  #include <winsock2.h>
#else
  #include <signal.h>
  #include <arpa/inet.h>
  #include <netinet/tcp.h>
#endif

#include "xr-utils.h"

void xr_set_nodelay(BIO* bio)
{
  int flag = 1;
  int sock = -1;
  BIO_get_fd(bio, &sock);
  if (sock >= 0)
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
  else
    fprintf(stderr, "Error disabling Nagle.\n");
}

static GMutex** _ssl_mutexes = NULL;
static int _ssl_initialized = 0;

static void _ssl_locking_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    g_mutex_lock(_ssl_mutexes[type]);
  else
    g_mutex_unlock(_ssl_mutexes[type]);
}

static unsigned long _ssl_thread_id_callback()
{
  unsigned long ret;
  ret = (unsigned long)g_thread_self();
  return ret;
}

void xr_ssl_init()
{
  int i;

  if (_ssl_initialized)
    return;

  signal(SIGPIPE, SIG_IGN);

  if (!g_thread_supported())
    g_thread_init(NULL);

  SSL_library_init();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  ERR_load_SSL_strings();

  _ssl_mutexes = g_new(GMutex*, CRYPTO_num_locks());
  for (i=0; i<CRYPTO_num_locks(); i++)
    _ssl_mutexes[i] = g_mutex_new();
  CRYPTO_set_id_callback(_ssl_thread_id_callback);
  CRYPTO_set_locking_callback(_ssl_locking_callback);
  
  _ssl_initialized = 1;
}

void xr_ssl_fini()
{
  if (!_ssl_initialized)
    return;

  signal(SIGPIPE, SIG_DFL);

  if (_ssl_mutexes)
  {
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    int i;
    for (i=0; i<CRYPTO_num_locks(); i++)
      g_mutex_free(_ssl_mutexes[i]);
    g_free(_ssl_mutexes);
    _ssl_mutexes = NULL;
  }

  _ssl_initialized = 0;
}