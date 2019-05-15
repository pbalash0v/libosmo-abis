/* OpenBSC Abis input driver for osmo-e1d */

/* (C) 2019 by Sylvain Munaut <tnt@246tNt.com>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "config.h"

#ifdef HAVE_E1D

#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/logging.h>

#include <osmocom/vty/vty.h>

#include <osmocom/abis/subchan_demux.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/lapd.h>

#include <osmocom/e1d/proto.h>
#include <osmocom/e1d/proto_clnt.h>


#define TS_SIGN_ALLOC_SIZE  300

struct osmo_e1dp_client *g_e1d;

/* pre-declaration */
extern struct e1inp_driver e1d_driver;
static int e1d_want_write(struct e1inp_ts *e1i_ts);


static int
handle_ts_sign_read(struct osmo_fd *bfd)
{
        struct e1inp_line *line = bfd->data;
        unsigned int ts_nr = bfd->priv_nr;
        struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg = msgb_alloc(TS_SIGN_ALLOC_SIZE, "E1D Signaling TS");
	int ret;

	if (!msg)
		return -ENOMEM;

	ret = read(bfd->fd, msg->data, TS_SIGN_ALLOC_SIZE - 16);
	if (ret < 0) {
		perror("read ");
		return ret;
	}

	msgb_put(msg, ret);
	if (ret <= 1) {
		perror("read ");
		return ret;
	}

        return e1inp_rx_ts_lapd(e1i_ts, msg);
}

static void
timeout_ts_sign_write(void *data)
{
	struct e1inp_ts *e1i_ts = (struct e1inp_ts *)data;

	/* trigger write of ts1, due to tx delay timer */
	e1d_want_write(e1i_ts);
}

static int
handle_ts_sign_write(struct osmo_fd *bfd)
{
        struct e1inp_line *line = bfd->data;
        unsigned int ts_nr = bfd->priv_nr;
        struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *sign_link;
	struct msgb *msg;

	bfd->when &= ~BSC_FD_WRITE;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, &sign_link);
	if (!msg) {
		/* no message after tx delay timer */
		return 0;
	}

	DEBUGP(DLMI, "TX: %s\n", osmo_hexdump(msg->data, msg->len));
	lapd_transmit(e1i_ts->lapd, sign_link->tei,
		sign_link->sapi, msg);

	/* set tx delay timer for next event */
	osmo_timer_setup(&e1i_ts->sign.tx_timer, timeout_ts_sign_write, e1i_ts);
	osmo_timer_schedule(&e1i_ts->sign.tx_timer, 0, 50000);

	return 0;
}


static void
e1d_write_msg(struct msgb *msg, void *cbdata)
{
	struct osmo_fd *bfd = cbdata;
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	int ret;

	ret = write(bfd->fd, msg->data, msg->len);
	msgb_free(msg);
	if (ret < 0)
		LOGP(DLMI, LOGL_NOTICE, "%s write failed %d\n", __func__, ret);
}

static int
e1d_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
        struct e1inp_line *line = bfd->data;
        unsigned int ts_nr = bfd->priv_nr;
        unsigned int idx = ts_nr-1;
        struct e1inp_ts *e1i_ts = &line->ts[idx];
	int ret = 0;

	switch (e1i_ts->type) {
	case E1INP_TS_TYPE_SIGN:
		//if (what & BSC_FD_EXCEPT)
		//FIXME: what to do ?!?!
		if (what & BSC_FD_READ)
			ret = handle_ts_sign_read(bfd);
		if (what & BSC_FD_WRITE)
			ret = handle_ts_sign_write(bfd);
		break;
	default:
		LOGP(DLINP, LOGL_NOTICE,
			"unknown/unsupported E1 TS type %u\n", e1i_ts->type);
		break;
	}

	return ret;
}


static int
e1d_want_write(struct e1inp_ts *e1i_ts)
{
        /* We never include the DAHDI B-Channel FD into the writeset */
	if (e1i_ts->type == E1INP_TS_TYPE_TRAU) {
		LOGP(DLINP, LOGL_DEBUG, "Trying to write TRAU ts\n");
		return 0;
	}

	e1i_ts->driver.e1d.fd.when |= BSC_FD_WRITE;

	return 0;
}

static int
e1d_line_update(struct e1inp_line *line)
{
	int ts;
	int ret;

	if (line->driver != &e1d_driver)
		return -EINVAL;


	LOGP(DLINP, LOGL_ERROR, "Line update %d %d %d\n", line->num, line->port_nr, line->num_ts);

	for (ts=1; ts<line->num_ts; ts++)
	{
		unsigned int idx = ts-1;
		struct e1inp_ts *e1i_ts = &line->ts[idx];
		struct osmo_fd *bfd = &e1i_ts->driver.e1d.fd;

		/* unregister FD if it was already registered */
		if (bfd->list.next && bfd->list.next != LLIST_POISON1)
			osmo_fd_unregister(bfd);

		bfd->data = line;
		bfd->priv_nr = ts;
		bfd->cb = e1d_fd_cb;

		switch (e1i_ts->type) {
		case E1INP_TS_TYPE_NONE:
			/* close/release LAPD instance, if any */
			if (e1i_ts->lapd) {
				lapd_instance_free(e1i_ts->lapd);
				e1i_ts->lapd = NULL;
			}
			if (bfd->fd) {
				close(bfd->fd);
				bfd->fd = 0;
			}
                        continue;
		case E1INP_TS_TYPE_SIGN:
			if (bfd->fd <= 0)
				bfd->fd = osmo_e1dp_client_ts_open(g_e1d, 0, 0, ts, E1DP_TSMODE_HDLCFCS);
			if (bfd->fd < 0) {
				LOGP(DLINP, LOGL_ERROR,
					"Could not open timeslot %d\n", ts);
				return -EIO;
			}
			bfd->when = BSC_FD_READ | BSC_FD_EXCEPT;

			if (!e1i_ts->lapd)
				e1i_ts->lapd = lapd_instance_alloc(1,
					e1d_write_msg, bfd, e1inp_dlsap_up,
					e1i_ts, &lapd_profile_abis);
			break;
		case E1INP_TS_TYPE_HDLC:
			break;
		case E1INP_TS_TYPE_TRAU:
			break;
		case E1INP_TS_TYPE_RAW:
			break;
		};

		ret = osmo_fd_register(bfd);
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR,
				"could not register FD: %s\n",
				strerror(ret));
			return ret;
		}
	}

	return 0;
}

static void
e1d_vty_show(struct vty *vty, struct e1inp_line *line)
{
	/* FIXME */
	vty_out(vty, "Not supported yet%s", VTY_NEWLINE);
}


struct e1inp_driver e1d_driver = {
	.name        = "e1d",
	.want_write  = e1d_want_write,
	.line_update = e1d_line_update,
	.vty_show    = e1d_vty_show,
};

int
e1inp_e1d_init(void)
{
	/* Connect to daemon */
	g_e1d = osmo_e1dp_client_create(NULL, "/tmp/osmo-e1d.ctl");
	if (!g_e1d) {
		 LOGP(DLINP, LOGL_ERROR, "Unable to connect to osmo-e1d daemon\n");
		return -EPIPE;
	}

	/* register the driver with the core */
	return e1inp_driver_register(&e1d_driver);
}

#endif /* HAVE_E1D */
