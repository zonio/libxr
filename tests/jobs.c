#include "jobs.h"
#include "TTest2.xrc.h"

typedef struct _job job;
struct _job
{
  gint id;
  gboolean complete;
  gboolean working;

  gchar* url;
  gchar* result;
  gint refs;
};

static gint jobs_next_id;
static GPtrArray* jobs;

G_LOCK_DEFINE_STATIC(jobs);

// worker function
gchar* do_query(const gchar* url)
{
  GError* local_err = NULL;
  gchar* result = NULL;

  g_printerr("Remote Server Call %p\n", url);
  xr_client_conn* conn = xr_client_new(&local_err);
  if (conn)
  {
    if (xr_client_open(conn, "https://localhost:4444/RPC2", &local_err))
      result = TTest2_serverCall(conn, url, &local_err);

    xr_client_free(conn);
  }

  if (local_err)
  {
    g_printerr("QUERY ERROR: %s\n", local_err->message);
    g_clear_error(&local_err);
  }

  g_printerr("Remote Server Call Done %p\n", url);

  return result;
}

// functions
static void job_unref(job* j)
{
  if (j && g_atomic_int_dec_and_test(&j->refs))
  {
    g_free(j->result);
    g_free(j->url);
    g_free(j);
  }
}

static job* get_pending_job(void)
{
  gint i;

  G_LOCK(jobs);

  for (i = 0; i < jobs->len; i++)
  {
    job* j = g_ptr_array_index(jobs, i);

    if (!g_atomic_int_get(&j->complete) && !g_atomic_int_get(&j->working))
    {
      g_atomic_int_inc(&j->refs);

      G_UNLOCK(jobs);
      return j;
    }
  }

  G_UNLOCK(jobs);
  return NULL;
}

static job* get_job(gint job_id)
{
  gint i;

  G_LOCK(jobs);

  for (i = 0; i < jobs->len; i++)
  {
    job* j = g_ptr_array_index(jobs, i);

    if (j->id == job_id)
    {
      g_atomic_int_inc(&j->refs);

      G_UNLOCK(jobs);
      return j;
    }
  }

  G_UNLOCK(jobs);
  return NULL;
}

gint jobs_start_job(const gchar* url)
{
  job* j = g_new0(job, 1);
  j->id = g_atomic_int_add(&jobs_next_id, 1);
  j->refs = 1;
  j->url = g_strdup(url);

  G_LOCK(jobs);
  g_ptr_array_add(jobs, j);
  gint job_id = j->id;
  G_UNLOCK(jobs);

  return job_id;
}

gboolean jobs_job_exists(gint job_id)
{
  job* j = get_job(job_id);
  if (j)
  {
    job_unref(j);
    return TRUE;
  }

  return FALSE;
}

gboolean jobs_is_job_done(gint job_id)
{
  job* j = get_job(job_id);
  if (j)
  {
    gboolean complete = g_atomic_int_get(&j->complete);
    job_unref(j);
    return complete;
  }

  return FALSE;
}

gboolean jobs_job_failed(gint job_id)
{
  job* j = get_job(job_id);
  if (j)
  {
    gboolean failed = g_atomic_int_get(&j->complete) && j->result == NULL;
    job_unref(j);
    return failed;
  }

  return FALSE;
}

gchar* jobs_get_job_result(gint job_id)
{
  gchar* result = NULL;
  job* j = get_job(job_id);
  if (j)
  {
    if (g_atomic_int_get(&j->complete))
       result = g_strdup(j->result);
    job_unref(j);
    return result;
  }

  return NULL;
}

void jobs_job_close(gint job_id)
{
  gint i;

  G_LOCK(jobs);
  for (i = 0; i < jobs->len; i++)
  {
    job* j = g_ptr_array_index(jobs, i);

    if (j->id == job_id)
    {
      g_ptr_array_remove_index(jobs, i);

      G_UNLOCK(jobs);
      return;
    }
  }

  G_UNLOCK(jobs);
  return;
}

static gpointer job_worker_thread(gpointer data)
{
  job* j = data;

  j->result = do_query(j->url);
  g_atomic_int_set(&j->working, FALSE);
  g_atomic_int_set(&j->complete, TRUE);
  job_unref(j);

  return NULL;
}

static gpointer jobs_manager_thread(gpointer data)
{
  while (TRUE)
  {
    job* j = get_pending_job();
    if (!j)
    {
      g_usleep(100 * 1000);
      continue;
    }

    // mark job as in progress
    g_atomic_int_set(&j->working, TRUE);

    // create thread for it
    g_thread_new("jobs-worker", job_worker_thread, j);
  }

  return NULL;
}

void jobs_init(void)
{
  if (g_once_init_enter(&jobs))
  {
    GPtrArray* a = g_ptr_array_new_full(100, (GDestroyNotify)job_unref);

    g_thread_new("jobs-manager", jobs_manager_thread, NULL);

    g_once_init_leave(&jobs, a);
  }
}
