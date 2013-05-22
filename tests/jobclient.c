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

#include <stdio.h>
#include <string.h>

#include "TTest2.xrc.h"

/* this function prints client error if any and resets error so that futher calls to client funcs work */

static int _check_err(GError** err)
{
  if (*err)
  {
    g_print("** ERROR **: %s\n", (*err)->message);
    g_clear_error(err);
    return 1;
  }
  return 0;
}

int main(int ac, char* av[])
{
  GError* err = NULL;
  char* uri = ac == 2 ? av[1] : "https://localhost:4444/RPC2";

  xr_debug_enabled = XR_DEBUG_CALL;

  xr_client_conn* conn = xr_client_new(&err);
  if (_check_err(&err))
    goto err;

  xr_client_open(conn, uri, &err);
  if (_check_err(&err))
    goto err;

  // start job

  gint job_id = TTest2_startQuery(conn, "http://localhost/slow.php", &err);
  if (_check_err(&err))
    goto err;

  // poll job result

  while (TRUE)
  {
    TQueryResult* result =  TTest2_completeQuery(conn, job_id, &err);
    if (err && err->code != T_XMLRPC_ERROR_TEST2_AGAIN)
    {
      _check_err(&err);
      goto err;
    }

    if (result)
    {
      g_print("Job done, result:\n%s\n", result->response);
      TQueryResult_free(result);
      break;
    }
    else
      g_usleep(1000 * 1000);

    g_clear_error(&err);
  }

  xr_client_free(conn);
  xr_fini();
  return 0;

err:
  xr_client_free(conn);
  xr_fini();
  return 1;
}
