/*  XMMS2 - X Music Multiplexer System
 *  Copyright (C) 2003-2012 XMMS2 Team
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





#include "xmms/xmms_outputplugin.h"
#include "xmms/xmms_log.h"

#include <glib.h>

#include "krad_ipc_client.h"

/*
 *  Defines
 */

/* this isn't really what we want... */
#define CHANNELS 2


/*
 * Type definitions
 */

typedef struct xmms_krad_data_St {
	kr_client_t *krad;
	kr_audioport_t *kr_audioport;

	gboolean error;
	gboolean running;
	guint underruns;
	guint volume[CHANNELS];
	gfloat volume_actual[CHANNELS];
	gfloat new_volume_actual[CHANNELS];
	gint last_sign[CHANNELS];
	GMutex *volume_change; /* This should not be needed once the server doesn't allow multiple clients to set the volume at the same time */
} xmms_krad_data_t;


/*
 * Function prototypes
 */

static gboolean xmms_krad_plugin_setup (xmms_output_plugin_t *plugin);
static gboolean xmms_krad_new (xmms_output_t *output);
static void xmms_krad_destroy (xmms_output_t *output);
static gboolean xmms_krad_status (xmms_output_t *output, xmms_playback_status_t status);
static void xmms_krad_flush (xmms_output_t *output);
static gboolean xmms_krad_volume_set (xmms_output_t *output, const gchar *channel, guint volume);
static gboolean xmms_krad_volume_get (xmms_output_t *output, const gchar **names, guint *values, guint *num_channels);
static int xmms_krad_process (uint32_t nframes, void *arg);
//static void xmms_krad_shutdown (void *arg);
//static void xmms_krad_error (const gchar *desc);
//static gboolean xmms_krad_ports_connected (xmms_output_t *output);
//static gboolean xmms_krad_connect_ports (xmms_output_t *output);
static gboolean xmms_krad_connect (xmms_output_t *output);

/*
 * Plugin header
 */

XMMS_OUTPUT_PLUGIN ("krad", "krad Output", XMMS_VERSION,
                    "krad audio server output plugin",
                    xmms_krad_plugin_setup);

static gboolean
xmms_krad_plugin_setup (xmms_output_plugin_t *plugin)
{
	xmms_output_methods_t methods;

	XMMS_OUTPUT_METHODS_INIT (methods);

	methods.new = xmms_krad_new;
	methods.destroy = xmms_krad_destroy;
	methods.status = xmms_krad_status;
	methods.flush = xmms_krad_flush;
	methods.volume_get = xmms_krad_volume_get;
	methods.volume_set = xmms_krad_volume_set;

	xmms_output_plugin_methods_set (plugin, &methods);

	xmms_output_plugin_config_property_register (plugin, "stationname", "radio1",
	                                             NULL, NULL);

	xmms_output_plugin_config_property_register (plugin, "clientname", "XMMS2",
	                                             NULL, NULL);
	                                             
	xmms_output_plugin_config_property_register (plugin, "volume.left", "100",
	                                             NULL, NULL);

	xmms_output_plugin_config_property_register (plugin, "volume.right", "100",
	                                             NULL, NULL);

	return TRUE;
}


/*
 * Member functions
 */


static gboolean
xmms_krad_connect (xmms_output_t *output)
{
	int i;
	const xmms_config_property_t *cv;
	const gchar *stationname;
	xmms_krad_data_t *data;

	g_return_val_if_fail (output, FALSE);
	data = xmms_output_private_data_get (output);
	g_return_val_if_fail (data, FALSE);

	cv = xmms_output_config_lookup (output, "stationname");
	stationname = xmms_config_property_get_string (cv);

	data->krad = kr_connect(stationname);
	if (data->krad == NULL) {
		return FALSE;
	}
	
	data->kr_audioport = kr_audioport_create (data->krad, INPUT);

	kr_audioport_set_callback (data->kr_audioport, xmms_krad_process, output);
	kr_audioport_activate (data->kr_audioport);


	return TRUE;
}


static gboolean
xmms_krad_new (xmms_output_t *output)
{
	xmms_krad_data_t *data;
	xmms_config_property_t *cv;
	int connect;

	g_return_val_if_fail (output, FALSE);

	data = g_new0 (xmms_krad_data_t, 1);

	data->underruns = 0;

	cv = xmms_output_config_lookup (output, "volume.left");
	data->volume[0] = xmms_config_property_get_int (cv);

	cv = xmms_output_config_lookup (output, "volume.right");
	data->volume[1] = xmms_config_property_get_int (cv);

	data->volume_actual[0] = (gfloat)(data->volume[0] / 100.0);
	data->volume_actual[0] *= data->volume_actual[0];
	data->new_volume_actual[0] = data->volume_actual[0];
	data->volume_actual[1] = (gfloat)(data->volume[1] / 100.0);
	data->volume_actual[1] *= data->volume_actual[1];
	data->new_volume_actual[1] = data->volume_actual[1];

	data->volume_change = g_mutex_new ();

	xmms_output_private_data_set (output, data);

	if (!xmms_krad_connect (output)) {
		g_mutex_free (data->volume_change);
		g_free (data);
		return FALSE;
	}

	xmms_output_format_add (output, XMMS_SAMPLE_FORMAT_FLOAT, CHANNELS,
	                        48000);

	return TRUE;
}


static void
xmms_krad_destroy (xmms_output_t *output)
{
	xmms_krad_data_t *data;

	g_return_if_fail (output);
	data = xmms_output_private_data_get (output);
	g_return_if_fail (data);

	g_mutex_free (data->volume_change);

	if (data->krad) {
		kr_audioport_deactivate (data->kr_audioport);
		kr_audioport_destroy (data->kr_audioport);
		kr_disconnect (data->krad);
	}

	g_free (data);
}


static gboolean
xmms_krad_status (xmms_output_t *output, xmms_playback_status_t status)
{
	xmms_krad_data_t *data;

	g_return_val_if_fail (output, FALSE);
	data = xmms_output_private_data_get (output);
	g_return_val_if_fail (data, FALSE);

	if (status == XMMS_PLAYBACK_STATUS_PLAY) {
		data->running = TRUE;
	} else {
		data->running = FALSE;
	}

	return TRUE;
}


static void
xmms_krad_flush (xmms_output_t *output)
{
	/* do nothing... */
}


static int
xmms_krad_process (uint32_t frames, void *arg)
{
	xmms_output_t *output = (xmms_output_t*) arg;
	xmms_krad_data_t *data;
	xmms_samplefloat_t *buf[CHANNELS];
	xmms_samplefloat_t tbuf[CHANNELS*4096];
	gint i, j, res, toread, sign;

	g_return_val_if_fail (output, -1);
	data = xmms_output_private_data_get (output);
	g_return_val_if_fail (data, -1);

	for (i = 0; i < CHANNELS; i++) {
		buf[i] = kr_audioport_get_buffer (data->kr_audioport, i);
	}

	toread = frames;

	if (data->running) {
		while (toread) {
			gint t, avail;

			t = MIN (toread * CHANNELS * sizeof (xmms_samplefloat_t),
			         sizeof (tbuf));

			avail = xmms_output_bytes_available (output);

			if (avail < t) {
				data->underruns++;
				XMMS_DBG ("krad output underun number %d! Not enough bytes available. Wanted: %d Available: %d", data->underruns, t, avail);
				break;
			}

			res = xmms_output_read (output, (gchar *)tbuf, t);

			if (res <= 0) {
				XMMS_DBG ("Output read returned %d unexpectedly", res);
				break;
			}

			if (res < t) {
				XMMS_DBG ("Less bytes read than expected. (Probably a ringbuffer hotspot)");
			}

			res /= CHANNELS * sizeof (xmms_samplefloat_t);

			for (j = 0; j < CHANNELS; j++) {
				if (data->new_volume_actual[j] == data->volume_actual[j]) {
					for (i = 0; i < res; i++) {
						buf[j][i] = (tbuf[i * CHANNELS + j] * data->volume_actual[j]);
					}
				} else {
				
					/* The way the volume change is set up here, the volume can only change once per callback, but thats 
					   allways plenty of times per second */
				
					/* last_sign: 0 = unset, -1 neg, +1 pos */
					
					if (data->last_sign[j] == 0) {
						if (tbuf[j] > 0.0f) {
							data->last_sign[j] = 1;
						} else {
							/* Zero counts as negative here, but its moot */
							data->last_sign[j] = -1;
						}
					}
				
					for (i = 0; i < res; i++) {
					
						if (data->last_sign[j] != 0) {
							if (tbuf[i*CHANNELS + j] > 0.0f) {
								sign = 1;
							} else {
								sign = -1;
							}
					
							if ((sign != data->last_sign[j]) || (tbuf[i * CHANNELS + j] == 0.0f)) {						
						
								data->volume_actual[j] = data->new_volume_actual[j];
								data->last_sign[j] = 0;
							}
						}
						
						buf[j][i] = (tbuf[i * CHANNELS + j] * data->volume_actual[j]);
						
					}

					if (data->last_sign[j] != 0) {
						data->last_sign[j] = sign;
					}
				}
			}
			
			toread -= res;
		}
	}

	if ((!data->running) || ((frames - toread) != frames)) {
		/* fill rest of buffer with silence */
		if (data->running) {
			XMMS_DBG ("Silence for %d frames", toread);
		}
		for (j = 0; j < CHANNELS; j++) {
			if (data->new_volume_actual[j] != data->volume_actual[j]) {
				data->volume_actual[j] = data->new_volume_actual[j];
			}
			for (i = frames - toread; i < frames; i++) {
				buf[j][i] = 0.0f;
			}
		}
	}

	return 0;
}

static gboolean
xmms_krad_volume_set (xmms_output_t *output,
                      const gchar *channel_name, guint volume)
{
	xmms_krad_data_t *data;
	xmms_config_property_t *cv;
	gchar *volume_strp;
	gchar volume_str[4];
	gfloat new_volume; /* For atomicness with zero crossing respect */

	g_return_val_if_fail (output, FALSE);
	g_return_val_if_fail (channel_name, FALSE);
	g_return_val_if_fail (volume <= 100, FALSE);

	volume_strp = volume_str;

	data = xmms_output_private_data_get (output);

	g_mutex_lock (data->volume_change);

	g_return_val_if_fail (data, FALSE);

	if (g_ascii_strcasecmp (channel_name, "Left") == 0) {
		data->volume[0] = volume;
		new_volume = (gfloat)(volume / 100.0);
		new_volume *= new_volume;
		data->new_volume_actual[0] = new_volume;
		cv = xmms_output_config_lookup (output, "volume.left");
		sprintf (volume_str, "%d", data->volume[0]);
		xmms_config_property_set_data (cv, volume_strp);
	} else {
		/* If its not left, its right */
		data->volume[1] = volume;
		new_volume = (gfloat)(volume / 100.0);
		new_volume *= new_volume;
		data->new_volume_actual[1] = new_volume;
		cv = xmms_output_config_lookup (output, "volume.right");
		sprintf (volume_str, "%d", data->volume[1]);
		xmms_config_property_set_data (cv, volume_strp);
	}

	g_mutex_unlock (data->volume_change);

	return TRUE;
}

static gboolean
xmms_krad_volume_get (xmms_output_t *output, const gchar **names,
                      guint *values, guint *num_channels)
{
	xmms_krad_data_t *data;

	g_return_val_if_fail (output, FALSE);

	data = xmms_output_private_data_get (output);

	g_return_val_if_fail (data, FALSE);
	g_return_val_if_fail (num_channels, FALSE);

	if (!*num_channels) {
		*num_channels = 2;
		return TRUE;
	}

	g_return_val_if_fail (*num_channels == 2, FALSE);
	g_return_val_if_fail (names, FALSE);
	g_return_val_if_fail (values, FALSE);

	values[0] = data->volume[0];
	names[0] = "Left";

	values[1] = data->volume[1];
	names[1] = "Right";

	return TRUE;
}

static void
xmms_krad_error (const gchar *desc)
{
	xmms_log_error ("krad reported error: %s", desc);
}
