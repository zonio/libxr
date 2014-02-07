/*
 * Copyright 2006-2008 Ondrej Jirman <ondrej.jirman@zonio.net>
 *
 * This file is part of libxr.
 *
 * Libxr is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 2 of the License, or (at your option) any
 * later version.
 *
 * Libxr is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libxr.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "TTest1.xrs.h"
#include "TTest2.xrs.h"
#include <pthread.h>
#include <stdio.h>

void dbg(const gchar *string)
{
  GDateTime* ts = g_date_time_new_now_local();
  gchar* tmp = g_date_time_format(ts, "%T");
  g_date_time_unref(ts);

  printf("%x %s - %s", (gint)pthread_self(), tmp, string);

  g_free(tmp);
}

int main(int ac, char* av[])
{
  GError* err = NULL;
  xr_servlet_def* servlets[3] = {
    __TTest1Servlet_def(),
    __TTest2Servlet_def(),
    NULL
  };

  g_set_print_handler(dbg);
  g_set_printerr_handler(dbg);

  //xr_debug_enabled = XR_DEBUG_CALL;

  xr_server_simple("server.pem", NULL, 100, "*:4444", servlets, &err);
  if (err)
    g_print("error: %s\n", err->message);

  xr_fini();

  return !!err;
}
