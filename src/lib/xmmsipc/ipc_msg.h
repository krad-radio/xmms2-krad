#ifndef __XMMS_IPC_MSG_H__
#define __XMMS_IPC_MSG_H__

#include <glib.h>

#define XMMS_MSG_DATA_SIZE 32768

typedef struct xmms_msg_St {
	guint32 cmd;
	guint16 get_pos, data_length;
	guint8 data[XMMS_MSG_DATA_SIZE];
} xmms_msg_t;

xmms_msg_t *xmms_msg_new (guint32 cmd);
void xmms_msg_destroy (xmms_msg_t *msg);

gboolean xmms_msg_can_read (xmms_ringbuf_t *ringbuf);
xmms_msg_t *xmms_msg_read (xmms_ringbuf_t *ringbuf);
gboolean xmms_msg_write (xmms_ringbuf_t *ringbuf, const xmms_msg_t *msg);

gpointer xmms_msg_put_data (xmms_msg_t *msg, gconstpointer data, guint len);
gpointer xmms_msg_put_uint32 (xmms_msg_t *msg, guint32 v);
gpointer xmms_msg_put_int32 (xmms_msg_t *msg, gint32 v);
gpointer xmms_msg_put_float (xmms_msg_t *msg, gint64 v);
gpointer xmms_msg_put_string (xmms_msg_t *msg, const char *str);
gpointer xmms_msg_append (xmms_msg_t *dmsg, xmms_msg_t *smsg);

typedef enum {
	XMMS_MSG_ARG_TYPE_END,
	XMMS_MSG_ARG_TYPE_UINT32,
	XMMS_MSG_ARG_TYPE_INT32,
	XMMS_MSG_ARG_TYPE_FLOAT,
	XMMS_MSG_ARG_TYPE_STRING,
} xmms_msg_arg_type_t;

#define __XMMS_MSG_DO_IDENTITY_FUNC(type) static inline type *__xmms_msg_arg_##type (type *arg) {return arg;}
__XMMS_MSG_DO_IDENTITY_FUNC(gint32)
__XMMS_MSG_DO_IDENTITY_FUNC(guint32)
__XMMS_MSG_DO_IDENTITY_FUNC(gfloat)
__XMMS_MSG_DO_IDENTITY_FUNC(char)
#undef __XMMS_MSG_DO_IDENTITY_FUNC

#define XMMS_MSG_UINT32(a) XMMS_MSG_ARG_TYPE_UINT32, __xmms_msg_arg_guint32 (a)
#define XMMS_MSG_INT32(a) XMMS_MSG_ARG_TYPE_INT32, __xmms_msg_arg_gint32 (a)
#define XMMS_MSG_INT64(a) XMMS_MSG_ARG_TYPE_FLOAT, __xmms_msg_arg_gint64 (a)
#define XMMS_MSG_STRING(a,len) XMMS_MSG_ARG_TYPE_STRING, ((gint)len), __xmms_msg_arg_char (a)

#define XMMS_MSG_END XMMS_MSG_ARG_TYPE_END

void xmms_msg_get_reset (xmms_msg_t *msg);
#define xmms_msg_get_cmd(msg) (msg)->cmd
gboolean xmms_msg_get_uint32 (xmms_msg_t *msg, guint32 *v);
gboolean xmms_msg_get_int32 (xmms_msg_t *msg, gint32 *v);
gboolean xmms_msg_get_float (xmms_msg_t *msg, gfloat *v);
gboolean xmms_msg_get_string (xmms_msg_t *msg, char *str, guint maxlen);
gboolean xmms_msg_get (xmms_msg_t *msg, ...);
gboolean xmms_msg_get_data (xmms_msg_t *msg, gpointer buf, guint len);

#endif 
