#include <string.h>

#include "xml-priv.h"
#include "xr-call.h"

struct _xr_call
{
  char* method;
  GSList* params;
  xr_value* retval;

  int errcode;    /* this must be > 0 for errors */
  char* errmsg;   /* Non-NULL on error. */
};

/* construct/destruct */

xr_call* xr_call_new(char* method)
{
  xr_call* c = g_new0(xr_call, 1);
  c->method = g_strdup(method);
  return c;
}

void xr_call_free(xr_call* call)
{
  GSList* i;
  g_free(call->method);
  for (i = call->params; i; i = i->next)
    xr_value_free(i->data);
  xr_value_free(call->retval);
  g_free(call->errmsg);
  g_free(call);
}

/* param manipulation */

void xr_call_add_param(xr_call* call, xr_value* val)
{
  g_assert(call != NULL);
  g_assert(val != NULL);
  call->params = g_slist_append(call->params, val);
}

xr_value* xr_call_get_param(xr_call* call, unsigned int pos)
{
  g_assert(call != NULL);
  xr_value* v = g_slist_nth_data(call->params, pos);
  return v;
}

/* retval manipulation */

void xr_call_set_retval(xr_call* call, xr_value* val)
{
  g_assert(call != NULL);
  g_assert(val != NULL);
  call->retval = val;
}

xr_value* xr_call_get_retval(xr_call* call)
{
  g_assert(call != NULL);
  return call->retval;
}

/* error manipulation */

void xr_call_set_error(xr_call* call, int code, char* msg)
{
  g_assert(call != NULL);
  g_assert(call->errcode == 0);
  g_assert(call->errmsg == NULL);
  call->errcode = code;
  call->errmsg = g_strdup(msg);
}

int xr_call_get_error_code(xr_call* call)
{
  g_assert(call != NULL);
  return call->errcode;
}

char* xr_call_get_error_message(xr_call* call)
{
  g_assert(call != NULL);
  return call->errmsg;
}

static void _xr_value_serialize(xmlNode* node, xr_value* val)
{
  xmlNode* value;
  char* data;
  char buf[50];
  GSList* i;
  if (xr_value_get_type(val) != XRV_MEMBER)
    node = xmlNewChild(node, NULL, BAD_CAST "value", NULL);
  switch (xr_value_get_type(val))
  {
    case XRV_ARRAY:
      value = xmlNewChild(node, NULL, BAD_CAST "array", NULL);
      for (i = xr_value_get_items(val); i; i = i->next)
        _xr_value_serialize(value, i->data);
      break;
    case XRV_STRUCT:
      value = xmlNewChild(node, NULL, BAD_CAST "struct", NULL);
      for (i = xr_value_get_members(val); i; i = i->next)
        _xr_value_serialize(value, i->data);
      break;
    case XRV_MEMBER:
      value = xmlNewChild(node, NULL, BAD_CAST "member", NULL);
      xmlNewChild(value, NULL, BAD_CAST "name", BAD_CAST xr_value_get_member_name(val));
      _xr_value_serialize(value, xr_value_get_member_value(val));
      break;
    case XRV_INT:
    {
      int int_val = -1;
      xr_value_to_int(val, &int_val);
      snprintf(buf, sizeof(buf), "%d", int_val);
      value = xmlNewChild(node, NULL, BAD_CAST "int", BAD_CAST buf);
      break;
    }
    case XRV_STRING:
    {
      char* str_val = NULL;
      xr_value_to_string(val, &str_val);
      value = xmlNewChild(node, NULL, BAD_CAST "string", BAD_CAST str_val);
      break;
    }
    case XRV_BOOLEAN:
    {
      int bool_val = -1;
      xr_value_to_bool(val, &bool_val);
      value = xmlNewChild(node, NULL, BAD_CAST "boolean", BAD_CAST (bool_val ? "true" : "false"));
      break;
    }
    case XRV_DOUBLE:
    {
      double dbl_val = -1;
      xr_value_to_double(val, &dbl_val);
      snprintf(buf, sizeof(buf), "%g", dbl_val);
      value = xmlNewChild(node, NULL, BAD_CAST "double", NULL);
      break;
    }
    case XRV_TIME:
    {
      char* str_val = NULL;
      xr_value_to_time(val, &str_val);
      value = xmlNewChild(node, NULL, BAD_CAST "time", BAD_CAST str_val);
      break;
    }
    case XRV_BLOB:
    {
      xr_blob* b = NULL;
      xr_value_to_blob(val, &b);
      data = g_base64_encode(b->buf, b->len); //XXX: not exactly efficient
      value = xmlNewChild(node, NULL, BAD_CAST "base64", BAD_CAST data);
      g_free(data);
      break;
    }
  }
}

void xr_call_serialize_request(xr_call* call, char** buf, int* len)
{
  g_assert(call != NULL);
  g_assert(call->method != NULL);
  g_assert(buf != NULL);
  g_assert(len != NULL);

  xmlDoc* doc = xmlNewDoc(BAD_CAST "1.0");
  xmlNode* root = xmlNewNode(NULL, BAD_CAST "methodCall");
  xmlDocSetRootElement(doc, root);
  xmlNewChild(root, NULL, BAD_CAST "methodName", call->method);
  xmlNode* params = xmlNewChild(root, NULL, BAD_CAST "params", NULL);
  GSList* i;
  for (i = call->params; i; i = i->next)
  {
    xmlNode* param = xmlNewChild(params, NULL, BAD_CAST "param", NULL);
    _xr_value_serialize(param, i->data);
  }

  xmlDocDumpFormatMemoryEnc(doc, (xmlChar**)buf, len, "UTF-8", 1);
}

void xr_call_free_buffer(char* buf)
{
  xmlFree(buf);
}

void xr_call_serialize_response(xr_call* call, char** buf, int* len)
{
  g_assert(call != NULL);
  g_assert(call->errcode > 0 || call->retval != NULL);
  g_assert(buf != NULL);
  g_assert(len != NULL);

  xmlDoc* doc = xmlNewDoc(BAD_CAST "1.0");
  xmlNode* root = xmlNewNode(NULL, BAD_CAST "methodResponse");
  xmlDocSetRootElement(doc, root);
  xmlNode* params = xmlNewChild(root, NULL, BAD_CAST "params", NULL);
  xmlNode* param = xmlNewChild(params, NULL, BAD_CAST "param", NULL);
  if (call->errcode > 0)
  {
    xr_value* v = xr_value_struct_new();
    xr_value_struct_set_member(v, "faultCode", xr_value_int_new(call->errcode));
    xr_value_struct_set_member(v, "faultString", xr_value_string_new(call->errmsg));
    _xr_value_serialize(param, v);
    xr_value_free(v);
  }
  else if (call->retval)
  {
    _xr_value_serialize(param, call->retval);
  }

  xmlDocDumpFormatMemoryEnc(doc, (xmlChar**)buf, len, "UTF-8", 1);
}

// return NULL if some unrecognized XML elements are found

static xr_value* _xr_value_unserialize(xmlNode* node)
{
  for_each_node(node, tn)
  {
    if (match_node(tn, "int"))
      return xr_value_int_new(xml_get_cont_int(tn));
    else if (match_node(tn, "string"))
      return xr_value_string_new(xml_get_cont_str(tn));
    else if (match_node(tn, "boolean"))
      return xr_value_bool_new(xml_get_cont_bool(tn));
    else if (match_node(tn, "double"))
      return xr_value_double_new(xml_get_cont_double(tn));
    else if (match_node(tn, "time"))
      return xr_value_time_new(xml_get_cont_str(tn));
    else if (match_node(tn, "base64"))
    {
      char* base64 = xml_get_cont_str(tn);
      gsize len = 0;
      char* buf = g_base64_decode(base64, &len);
      g_free(base64);
      return xr_value_blob_new(xr_blob_new(buf, len));
    }
    else if (match_node(tn, "array"))
    {
      xr_value* arr = xr_value_array_new();
      for_each_node(tn, v)
      {
        if (match_node(v, "value"))
        {
          xr_value* elem = _xr_value_unserialize(v);
          if (elem == NULL)
          {
            xr_value_free(arr);
            return NULL;
          }
          xr_value_array_append(arr, elem);
        }
      }
      return arr;
    }
    else if (match_node(tn, "struct"))
    {
      xr_value* str = xr_value_struct_new();
      for_each_node(tn, m)
      {
        if (match_node(m, "member"))
        {
          char* name = NULL;
          xr_value* val = NULL;
          int names = 0, values = 0;

          for_each_node(m, me)
          {
            if (match_node(me, "name"))
            {
              if (names++ == 0)
                name = xml_get_cont_str(me);
            }
            else if (match_node(me, "value"))
            {
              if (values++ == 0)
                val = _xr_value_unserialize(me);
            }
          }

          if (values != 1 || names != 1)
          {
            g_free(name);
            xr_value_free(val);
            xr_value_free(str);
            return NULL;
          }
          xr_value_struct_set_member(str, name, val);
        }
      }
      return str;
    }
    else
      return NULL;
  }
  return NULL;
}

int xr_call_unserialize_request(xr_call* call, char* buf, int len)
{
  g_assert(call != NULL);
  g_assert(buf != NULL);
  g_assert(len > 0);

  xmlDoc* doc = xmlReadMemory(buf, len, 0, 0, XML_PARSE_NOWARNING|XML_PARSE_NOERROR|XML_PARSE_NONET);
  if (doc == NULL)
  {
    xr_call_set_error(call, 100, "Can't parse XML-RPC XML request. Invalid XML document.");
    goto err_0;
  }

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL)
  {
    xr_call_set_error(call, 100, "Can't parse XML-RPC XML request. Root element is missing.");
    goto err_1;
  }

  xmlXPathContext* ctx = xmlXPathNewContext(doc);

  call->method = xp_eval_cont_str(ctx, "/methodCall/methodName");
  if (call->method == NULL)
  {
    xr_call_set_error(call, 100, "Can't parse XML-RPC XML request. Missing methodName.");
    goto err_2;
  }

  struct nodeset* ns = xp_eval_nodes(ctx, "/methodCall/params/param/value[0]");
  for (int i = 0; i < ns->count; i++)
  {
    xr_value* v = _xr_value_unserialize(ns->nodes[i]);
    if (v == NULL)
    {
      char* msg = g_strdup_printf("Can't parse XML-RPC XML request. Failed to unserialize parameter %d.", i);
      xr_call_set_error(call, 100, msg);
      g_free(msg);
      goto err_3;
    }
    xr_call_add_param(call, v);
  }
  xp_free_nodes(ns);
  xmlXPathFreeContext(ctx);
  xmlFreeDoc(doc);
  return 0;

 err_3:
  xp_free_nodes(ns);
 err_2:
  xmlXPathFreeContext(ctx);
 err_1:
  xmlFreeDoc(doc);
 err_0:
  return -1;
}

int xr_call_unserialize_response(xr_call* call, char* buf, int len)
{
  g_assert(call != NULL);
  g_assert(buf != NULL);
  g_assert(len > 0);

  xmlDoc* doc = xmlReadMemory(buf, len, 0, 0, XML_PARSE_NOWARNING|XML_PARSE_NOERROR|XML_PARSE_NONET);
  if (doc == NULL)
  {
    xr_call_set_error(call, 100, "Can't parse XML-RPC XML response. Invalid XML document.");
    goto err_0;
  }

  xmlNode* root = xmlDocGetRootElement(doc);
  if (root == NULL)
  {
    xr_call_set_error(call, 100, "Can't parse XML-RPC XML response. Root element is missing.");
    goto err_1;
  }

  xmlXPathContext* ctx = xmlXPathNewContext(doc);

  struct nodeset* ns = xp_eval_nodes(ctx, "/methodResponse/params/param/value");
  if (ns->count != 1)
  {
    if (ns->count == 0)
      xr_call_set_error(call, 100, "Can't parse XML-RPC XML response. No return value.");
    else
      xr_call_set_error(call, 100, "Can't parse XML-RPC XML response. Too many return values.");
    goto err_2;
  }
  call->retval = _xr_value_unserialize(ns->nodes[0]);
  if (call->retval == NULL)
  {
    xr_call_set_error(call, 100, "Can't parse XML-RPC XML response. Failed to unserialize retval.");
    goto err_2;
  }
  xp_free_nodes(ns);

  int errcode = 0;
  char* errmsg = NULL;
  if (xr_value_is_error_retval(call->retval, &errcode, &errmsg))
  {
    xr_call_set_error(call, errcode, errmsg);
    xr_value_free(call->retval);
    call->retval = NULL;
  }

  xmlXPathFreeContext(ctx);
  xmlFreeDoc(doc);
  return xr_call_get_error_code(call) != 0 ? -1 : 0;

 err_2:
  xp_free_nodes(ns);
  xmlXPathFreeContext(ctx);
 err_1:
  xmlFreeDoc(doc);
 err_0:
  return -1;
}