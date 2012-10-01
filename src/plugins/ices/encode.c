/* encode.c
 * - runtime encoding of PCM data.
 *
 * $Id: encode.c,v 1.16 2003/03/22 02:27:55 karl Exp $
 *
 * Copyright (c) 2001 Michael Smith <msmith@labyrinth.net.au>
 *
 * This program is distributed under the terms of the GNU General
 * Public License, version 2. You may use, modify, and redistribute
 * it under the terms of this license. A copy should be included
 * with this source.
 */

/*
 * Modifications for xmms2
 * Copyright (C) 2003-2012 XMMS2 Team
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <glib.h>

#include <ogg/ogg.h>
#include <opus.h>

#include "encode.h"
#include "xmms/xmms_log.h"
#include "xmms/xmms_sample.h"

#define MODULE "encode/"

typedef struct {
   int version;
   int channels; /* Number of channels: 1..255 */
   int preskip;
   ogg_uint32_t input_sample_rate;
   int gain; /* in dB S7.8 should be zero whenever possible */
   int channel_mapping;
   /* The rest is only used if channel_mapping != 0 */
   int nb_streams;
   int nb_coupled;
   unsigned char stream_map[255];
} OpusHeader;

struct encoder_state {
	/* General encoder configuration. */
	int bitrate;
	int last_bitrate;
	
	gboolean encoder_inited;

	/* Ogg state. Remains active for the lifetime of the encoder. */
	ogg_stream_state os;
	int serial;
	gboolean in_header; /* TRUE if the stream is still within a vorbis
						 * header. */
	gboolean flushing; /* TRUE if the end of stream is reached and
						* we're just flushing the ogg data. */

	/* Used for ogg page size management. See xmms_ices_encoder_output
	 * for details. */
	int samples_in_current_page;
	ogg_int64_t previous_granulepos;

	/* Opus state. */
    OpusEncoder *encoder;
	OpusHeader *header;
	unsigned char *header_data;
	unsigned char *tags;
	int tags_size;
	int header_size;
	
	int packetno;
	int granulepos;
	
	unsigned char *buffer;	
	ogg_packet op;
	
	unsigned char sbuffer[4096 * 8];
	int sbuffer_pos;
	int sbuffer_samples;
};

typedef struct {
   unsigned char *data;
   int maxlen;
   int pos;
} Packet;

typedef struct {
   const unsigned char *data;
   int maxlen;
   int pos;
} ROPacket;

static int opus_header_to_packet(const OpusHeader *h, unsigned char *packet, int len);

static int write_uint32(Packet *p, ogg_uint32_t val)
{
   if (p->pos>p->maxlen-4)
      return 0;
   p->data[p->pos  ] = (val    ) & 0xFF;
   p->data[p->pos+1] = (val>> 8) & 0xFF;
   p->data[p->pos+2] = (val>>16) & 0xFF;
   p->data[p->pos+3] = (val>>24) & 0xFF;
   p->pos += 4;
   return 1;
}

static int write_uint16(Packet *p, ogg_uint16_t val)
{
   if (p->pos>p->maxlen-2)
      return 0;
   p->data[p->pos  ] = (val    ) & 0xFF;
   p->data[p->pos+1] = (val>> 8) & 0xFF;
   p->pos += 2;
   return 1;
}

static int write_chars(Packet *p, const unsigned char *str, int nb_chars)
{
   int i;
   if (p->pos>p->maxlen-nb_chars)
      return 0;
   for (i=0;i<nb_chars;i++)
      p->data[p->pos++] = str[i];
   return 1;
}

int opus_header_to_packet(const OpusHeader *h, unsigned char *packet, int len)
{
   int i;
   Packet p;
   unsigned char ch;

   p.data = packet;
   p.maxlen = len;
   p.pos = 0;
   if (len<19)return 0;
   if (!write_chars(&p, (const unsigned char*)"OpusHead", 8))
      return 0;
   /* Version is 1 */
   ch = 1;
   if (!write_chars(&p, &ch, 1))
      return 0;

   ch = h->channels;
   if (!write_chars(&p, &ch, 1))
      return 0;

   if (!write_uint16(&p, h->preskip))
      return 0;

   if (!write_uint32(&p, h->input_sample_rate))
      return 0;

   if (!write_uint16(&p, h->gain))
      return 0;

   ch = h->channel_mapping;
   if (!write_chars(&p, &ch, 1))
      return 0;

   if (h->channel_mapping != 0)
   {
      ch = h->nb_streams;
      if (!write_chars(&p, &ch, 1))
         return 0;

      ch = h->nb_coupled;
      if (!write_chars(&p, &ch, 1))
         return 0;

      /* Multi-stream support */
      for (i=0;i<h->channels;i++)
      {
         if (!write_chars(&p, &h->stream_map[i], 1))
            return 0;
      }
   }

   return p.pos;
}

/* Create an ogg stream and vorbis encoder, with the configuration
 * specified in the encoder_state.
 */
gboolean
xmms_ices_encoder_create (encoder_state *s)
{
    int err;	
	ogg_packet op;

	if (s->encoder_inited) {
		XMMS_DBG ("OOPS: xmms_ices_encoder_create called "
		          "with s->encoder_inited == TRUE !");
	}

	/* Create the Opus encoder and headers. */

	err = 0;
	s->header = (OpusHeader *)calloc(1, sizeof(OpusHeader));
	s->header_data = (unsigned char *)calloc (1, 1024);	
	s->tags = (unsigned char *)calloc (1, 1024);
	s->buffer = (unsigned char *)calloc (1, 4 * 4096);
	s->header->gain = 0;
	s->header->channels = 2;
	s->header->input_sample_rate = 48000;
	s->encoder = opus_encoder_create (48000, 2, OPUS_APPLICATION_AUDIO, &err);
	opus_encoder_ctl (s->encoder, OPUS_SET_BITRATE(s->bitrate));
	if (s->encoder == NULL) {
		printf("Opus Encoder creation error: %s\n", opus_strerror (err));
		free (s->header_data);
		free (s->header);
		free (s->tags);
		free (s->buffer);
		return FALSE;
	}
	s->last_bitrate = s->bitrate;
	opus_encoder_ctl (s->encoder, OPUS_GET_LOOKAHEAD (&s->header->preskip));
	s->header_size = opus_header_to_packet (s->header, s->header_data, 100);

	s->tags_size = 
	8 + 4 + strlen (opus_get_version_string ()) + 4 + 4 + strlen ("ENCODER=") + strlen (XMMS_VERSION);
	
	memcpy (s->tags, "OpusTags", 8);
	
	s->tags[8] = strlen (opus_get_version_string ());
	
	memcpy (s->tags + 12, opus_get_version_string (), strlen (opus_get_version_string ()));

	s->tags[12 + strlen (opus_get_version_string ())] = 1;

	s->tags[12 + strlen (opus_get_version_string ()) + 4] = strlen ("ENCODER=") + strlen (XMMS_VERSION);
	
	memcpy (s->tags + 12 + strlen (opus_get_version_string ()) + 4 + 4, "ENCODER=", strlen ("ENCODER="));
	
	memcpy (s->tags + 12 + strlen (opus_get_version_string ()) + 4 + 4 + strlen ("ENCODER="),
			XMMS_VERSION,
			strlen (XMMS_VERSION));	

	/* Initialize the ogg stream and input the Opus header
	 * packets. */
	ogg_stream_init (&s->os, s->serial++);

	s->packetno = 0;
	s->granulepos = 0;
	
	op.b_o_s = 1;
	op.e_o_s = 0;
	op.granulepos = 0;
	op.packetno = s->packetno++;
	op.packet = s->header_data;
	op.bytes = s->header_size;

	ogg_stream_packetin (&s->os, &op);
	
	op.b_o_s = 0;
	op.e_o_s = 0;
	op.granulepos = 0;
	op.packetno = s->packetno++;
	op.packet = s->tags;
	op.bytes = s->tags_size;

	ogg_stream_packetin (&s->os, &op);

	s->in_header = TRUE;
	s->flushing = FALSE;
	s->samples_in_current_page = 0;
	s->previous_granulepos = 0;
	s->encoder_inited = TRUE;

	return TRUE;
}

/* Free the ogg and vorbis encoder state associated with
 * encoder_state, if the encoder is present.
 */
static void
xmms_ices_encoder_free (encoder_state *s)
{
	if (s->encoder_inited) {
		ogg_stream_clear (&s->os);
		opus_encoder_destroy (s->encoder);
		free (s->header_data);
		free (s->header);
		free (s->tags);
		free (s->buffer);
		s->encoder_inited = FALSE;
	}
}


encoder_state *
xmms_ices_encoder_init (int bitrate)
{
	encoder_state *s;

	s = g_new0 (encoder_state, 1);

	if ((bitrate < 9600) || (bitrate > 320000)) {
		s->bitrate = 132000;
	} else {
		s->bitrate = bitrate;
	}

	s->serial = 66631337;
	s->in_header = FALSE;
	s->encoder_inited = FALSE;

	return s;
}

void xmms_ices_encoder_fini (encoder_state *s) {
	xmms_ices_encoder_free (s);
	g_free (s);
}

/* Start a new logical ogg stream.
gboolean xmms_ices_encoder_stream_change (encoder_state *s, int rate,
                                          int channels, vorbis_comment *vc)
{
	xmms_ices_encoder_free (s);
	s->rate = rate;
	s->channels = channels;
	return xmms_ices_encoder_create (s, vc);
}
*/
/* Encode the given data into Ogg Opus. */
void xmms_ices_encoder_input (encoder_state *s, xmms_samplefloat_t *buf, int bytes)
{
	int ret;
	int samples = bytes / (sizeof (xmms_samplefloat_t)*2);
	int bytes_per_opus_frame;
	int samples_per_opus_frame;
	ret = 0;
	samples_per_opus_frame = 960;
	bytes_per_opus_frame = samples_per_opus_frame * sizeof (xmms_samplefloat_t)*2;
	
	memcpy (s->sbuffer + s->sbuffer_pos, buf, bytes);
	s->sbuffer_pos += bytes;
	s->sbuffer_samples += samples;
	
	if (s->sbuffer_samples >= samples_per_opus_frame) {
		ret = opus_encode_float (s->encoder, (float *)s->sbuffer, samples_per_opus_frame, s->buffer, 2048 * 4);
		//printf("Opus Encoder encoding %d samples, got back %d bytes\n", 960, ret);
		if (ret < 0) {
			printf("Opus Encoder error: %s\n", opus_strerror (ret));	
		}

		s->sbuffer_pos -= bytes_per_opus_frame;
		s->sbuffer_samples -= samples_per_opus_frame;
		memmove (s->sbuffer, s->sbuffer + bytes_per_opus_frame, bytes_per_opus_frame);		
	}
	
	if (ret > 0) {
		s->op.b_o_s = 0;
		s->op.e_o_s = 0;
		s->op.granulepos = s->granulepos;
		s->op.packetno = s->packetno++;
		s->op.packet = s->buffer;
		s->op.bytes = ret;
		s->granulepos += samples_per_opus_frame;
		ogg_stream_packetin (&s->os, &s->op);
	}
	
	s->samples_in_current_page += samples;
}

/* Mark the end of the vorbis encoding, flush the vorbis buffers, and
 * mark the ogg stream as being in the flushing state. */
void xmms_ices_encoder_finish (encoder_state *s)
{

	s->op.b_o_s = 0;
	s->op.e_o_s = 1;
	s->op.granulepos = s->granulepos;
	s->op.packetno = s->packetno++;
	s->op.packet = NULL;
	s->op.bytes = 0;

	ogg_stream_packetin (&s->os, &s->op);

	s->flushing = TRUE;
}

/* Returns TRUE if an ogg page was output, FALSE if there is nothing
 * left to do.
 */
gboolean xmms_ices_encoder_output (encoder_state *s, ogg_page *og)
{
	/* As long as we're still in the header, we still have the header
	 * packets to output. Loop over those before going to the actual
	 * vorbis data. */
	if (s->in_header) {
		if (ogg_stream_flush (&s->os, og))
			return TRUE;
		else
			s->in_header = FALSE;
	}

	/* If we're flushing the end of the stream, just output. */
	if (s->flushing) {
		if (ogg_stream_flush (&s->os, og))
			return TRUE;
		else
			return FALSE;
	}

	/* For live encoding, we want to stream pages regularly, rather
	 * than burst huge pages. Therefore, we periodically manually
	 * flush the stream. */
	if (s->samples_in_current_page > 4096) {
		if (!ogg_stream_flush (&s->os, og))
			return FALSE;
	} else {
		if (!ogg_stream_pageout (&s->os, og))
			return FALSE;
	}

	/* At this point, we have an ogg page in og. Keep bookkeeping
	 * accurate regarding the number of samples still in the page
	 * buffer, and return. */
	s->samples_in_current_page -= (ogg_page_granulepos (og)
	                               - s->previous_granulepos);
	s->previous_granulepos = ogg_page_granulepos (og);

	return TRUE;
}
