/*  XMMS2 - X Music Multiplexer System
 *  Copyright (C) 2003-2007 XMMS2 Team
 *
 *  PLUGINS ARE NOT CONSIDERED TO BE DERIVED WORK !!!
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#ifndef __RB_XMMSCLIENT_H
#define __RB_XMMSCLIENT_H

#define CHECK_DELETED(xmms) \
	if (xmms->deleted) \
		rb_raise (eDisconnectedError, "client deleted");

typedef struct {
	xmmsc_connection_t *real;
	bool deleted;
	VALUE results;
	VALUE disconnect_cb;
	VALUE io_need_out_cb;

	void *ecore_handle;
	void *gmain_handle;
} RbXmmsClient;

#endif
