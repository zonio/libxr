#ifndef __JOBS_H
#define __JOBS_H

#include <glib.h>

gchar*    do_query             (const gchar* url);

gint      jobs_start_job       (const gchar* url);

gboolean  jobs_job_exists      (gint job_id);
gboolean  jobs_is_job_done     (gint job_id);
gboolean  jobs_job_failed      (gint job_id);
gchar*    jobs_get_job_result  (gint job_id);

void      jobs_job_close       (gint job_id);

void      jobs_init(void);

#endif
