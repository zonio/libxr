/* GObject - GLib Type, Object, Parameter and Signal Library
 * Copyright (C) 2001 Red Hat, Inc.
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

static void
dummy_closure_marshal (GClosure     *closure,
		       GValue       *return_value,
		       guint         n_param_values,
		       const GValue *param_values,
		       gpointer      invocation_hint,
		       gpointer      marshal_data)
{
  if (G_VALUE_HOLDS_BOOLEAN (return_value))
    g_value_set_boolean (return_value, TRUE);
}

/**
 * g_source_set_dummy_callback:
 * @source: the source
 *
 * Sets a dummy callback for @source. The callback will do nothing, and
 * if the source expects a #gboolean return value, it will return %TRUE.
 * (If the source expects any other type of return value, it will return
 * a 0/%NULL value; whatever g_value_init() initializes a #GValue to for
 * that type.)
 *
 * If the source is not one of the standard GLib types, the
 * @closure_callback and @closure_marshal fields of the #GSourceFuncs
 * structure must have been filled in with pointers to appropriate
 * functions.
 */
void
g_source_set_dummy_callback (GSource *source)
{
  GClosure *closure;

  closure = g_closure_new_simple (sizeof (GClosure), NULL);
  g_closure_set_meta_marshal (closure, NULL, dummy_closure_marshal);
  g_source_set_closure (source, closure);
}
