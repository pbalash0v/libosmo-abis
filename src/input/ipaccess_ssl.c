/* OpenBSC Abis input driver for ip.access */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by On-Waves
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "internal.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/macaddr.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/ipaccess.h>

#include <osmocom/abis/e1_input.h>

#include <osmocom/abis/ipa.h>

#include <osmocom/abis/ipaccess_ssl.h>
#include <osmocom/abis/ipa_ssl_common.h>
#include <osmocom/abis/ipa_ssl.h>

 
static void *tall_ipa_ssl_ctx;


#define TS1_ALLOC_SIZE	900

#define DEFAULT_TCP_KEEPALIVE_IDLE_TIMEOUT 30
#define DEFAULT_TCP_KEEPALIVE_INTERVAL     3
#define DEFAULT_TCP_KEEPALIVE_RETRY_COUNT  10

#define LOGIPA(link, level, fmt, args...) LOGP(DLINP, level, "%s:%u " fmt, link->addr, link->port, ## args)


struct ipaccess_ssl_line {
	int line_already_initialized;

	struct ssl_data* oml_ssl;
	struct ssl_data* rsl_ssl;

	enum ipa_ssl_client_conn_state	oml_state;
	enum ipa_ssl_client_conn_state	rsl_state;
};





// unified (OML/RSL) accepting server socket own call back
// called on select iteration for every new tcp/ip connected








static void ipa_ssl_msg_push_header(struct msgb *msg, uint8_t proto)
{
	struct ipaccess_head *hh;

	msg->l2h = msg->data;
	hh = (struct ipaccess_head *) msgb_push(msg, sizeof(*hh));
	hh->proto = proto;
	hh->len = htons(msgb_l2len(msg));
}

static int ipa_ssl_ccm_rcvmsg_base(struct msgb *msg, struct osmo_fd *bfd, struct ssl_data* ssl);

/* Returns -1 on error, and 0 or 1 on success. If -1 or 1 is returned, line has
 * been released and should not be used anymore by the caller. */
static int ipaccess_ssl_rcvmsg(struct e1inp_line *line, struct msgb *msg,
			   struct osmo_fd *bfd, struct ssl_data* ssl)
{
	struct tlv_parsed tlvp;
	uint8_t msg_type = *(msg->l2h);
	struct ipaccess_unit unit_data = {};
	struct e1inp_sign_link *sign_link;
	char *unitid;
	int len, ret;

	/* Handle IPA PING, PONG and ID_ACK messages. */
	ret = ipa_ssl_ccm_rcvmsg_base(msg, bfd, ssl);
	switch(ret) {
	case -1:
		/* error in IPA control message handling */
		goto err;
	case 1:
		/* this is an IPA control message, skip further processing */
		return 0;
	case 0:
		/* this is not an IPA control message, continue */
		break;
	default:
		LOGP(DLINP, LOGL_ERROR, "Unexpected return from "
					"ipa_ccm_rcvmsg_base "
					"(ret=%d)\n", ret);
		goto err;
	}

	switch (msg_type) {
	case IPAC_MSGT_ID_RESP:
		DEBUGP(DLMI, "ID_RESP\n");
		/* parse tags, search for Unit ID */
		ret = ipa_ccm_id_resp_parse(&tlvp, (const uint8_t *)msg->l2h+1, msgb_l2len(msg)-1);
		DEBUGP(DLMI, "\n");
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR, "IPA response message "
				"with malformed TLVs\n");
			goto err;
		}
		if (!TLVP_PRESENT(&tlvp, IPAC_IDTAG_UNIT)) {
			LOGP(DLINP, LOGL_ERROR, "IPA response message "
				"without unit ID\n");
			goto err;

		}
		len = TLVP_LEN(&tlvp, IPAC_IDTAG_UNIT);
		if (len < 1) {
			LOGP(DLINP, LOGL_ERROR, "IPA response message "
				"with too small unit ID\n");
			goto err;
		}
		unitid = (char *) TLVP_VAL(&tlvp, IPAC_IDTAG_UNIT);
		unitid[len - 1] = '\0';
		ipa_parse_unitid(unitid, &unit_data);

		if (!line->ops->sign_link_up) {
			LOGP(DLINP, LOGL_ERROR,
			     "Unable to set signal link, closing socket.\n");
			goto err;
		}
		/* the BSC creates the new sign links at this stage. */
		if (bfd->priv_nr == E1INP_SIGN_OML) {
			sign_link =
				line->ops->sign_link_up(&unit_data, line,
							E1INP_SIGN_OML);
			if (sign_link == NULL) {
				LOGP(DLINP, LOGL_ERROR,
					"Unable to set signal link, "
					"closing socket.\n");
				goto err;
			}
		} else if (bfd->priv_nr == E1INP_SIGN_RSL) {
			struct e1inp_ts *ts;
         struct osmo_fd *newbfd;
			struct e1inp_line *new_line;

			sign_link =
				line->ops->sign_link_up(&unit_data, line,
							E1INP_SIGN_RSL);
			if (sign_link == NULL) {
				LOGP(DLINP, LOGL_ERROR,
					"Unable to set signal link, "
					"closing socket.\n");
				goto err;
			}
			/* this is a bugtrap, the BSC should be using the
			 * virtual E1 line used by OML for this RSL link. */
			if (sign_link->ts->line == line) {
				LOGP(DLINP, LOGL_ERROR,
					"Fix your BSC, you should use the "
					"E1 line used by the OML link for "
					"your RSL link.\n");
				return 0;
			}
			/* Finally, we know which OML link is associated with
			 * this RSL link, attach it to this socket. */
			bfd->data = new_line = sign_link->ts->line;
			e1inp_line_get(new_line);

			// clone ssl data to new line
			struct ipaccess_ssl_line* il = line->driver_data;
			struct ipaccess_ssl_line* new_il = new_line->driver_data;
			new_il->oml_ssl = il->oml_ssl;
			new_il->rsl_ssl = il->rsl_ssl;
			new_il->oml_state = il->oml_state;
			new_il->rsl_state = il->rsl_state;

			ts = e1inp_line_ipa_rsl_ts(new_line, unit_data.trx_id);
			newbfd = &ts->driver.ipaccess.fd;

			/* get rid of our old temporary bfd */
			/* preserve 'newbfd->when' flags potentially set by sign_link_up() */
			osmo_fd_setup(newbfd, bfd->fd, newbfd->when | bfd->when, bfd->cb,
				      bfd->data, E1INP_SIGN_RSL + unit_data.trx_id);
			osmo_fd_unregister(bfd);
			bfd->fd = -1;
			ret = osmo_fd_register(newbfd);
			if (ret < 0) {
				LOGP(DLINP, LOGL_ERROR,
				     "could not register FD\n");
				goto err;
			}
			/* now we can release the dummy RSL line. */
			e1inp_line_put(line);
			return 1;
		}
		break;
	default:
		LOGP(DLINP, LOGL_ERROR, "Unknown IPA message type\n");
		goto err;
	}
	return 0;
err:
	osmo_fd_unregister(bfd);
	close(bfd->fd);
	bfd->fd = -1;
	e1inp_line_put(line);
	return -1;
}

static int ipaccess_ssl_drop(struct osmo_fd *bfd, struct e1inp_line *line)
{
	int ret = 1;
	struct e1inp_ts *e1i_ts;
	if (bfd->priv_nr == E1INP_SIGN_OML)
		e1i_ts = e1inp_line_ipa_oml_ts(line);
	else
		e1i_ts = e1inp_line_ipa_rsl_ts(line, bfd->priv_nr - E1INP_SIGN_RSL);

	/* Error case: we did not see any ID_RESP yet for this socket. */
	if (bfd->fd != -1) {
		LOGP(DLINP, LOGL_ERROR, "Forcing socket shutdown with "
					"no signal link set\n");
		osmo_fd_unregister(bfd);
		close(bfd->fd);
		bfd->fd = -1;
		ret = -ENOENT;
	}

	msgb_free(e1i_ts->pending_msg);
	e1i_ts->pending_msg = NULL;

	/* e1inp_sign_link_destroy releases the socket descriptors for us. */
	line->ops->sign_link_down(line);

	return ret;
}

static int ts_want_ssl_write(struct e1inp_ts *e1i_ts)
{
	e1i_ts->driver.ipaccess.fd.when |= BSC_FD_WRITE;
	return 0;
}

static void timeout_ts1_ssl_write(void *data)
{
	struct e1inp_ts *e1i_ts = (struct e1inp_ts *)data;

	/* trigger write of ts1, due to tx delay timer */
	ts_want_ssl_write(e1i_ts);
}

//
//unified write callback. used by BTS and BSC sides
//
static int __handle_ts1_ssl_write(struct osmo_fd* bfd, struct e1inp_line* line,
											struct ssl_data* ssl)
{
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts;
	struct e1inp_sign_link *sign_link;
	struct msgb *msg;
	int ret;

	if (bfd->priv_nr == E1INP_SIGN_OML)
		e1i_ts = e1inp_line_ipa_oml_ts(line);
	else
		e1i_ts = e1inp_line_ipa_rsl_ts(line, bfd->priv_nr - E1INP_SIGN_RSL);

	bfd->when &= ~BSC_FD_WRITE;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, &sign_link);
	if (!msg) {
		/* no message after tx delay timer */
		return 0;
	}

	switch (sign_link->type) {
	case E1INP_SIGN_OML:
	case E1INP_SIGN_RSL:
	case E1INP_SIGN_OSMO:
		break;
	default:
		bfd->when |= BSC_FD_WRITE; /* come back for more msg */
		ret = -EINVAL;
		goto out;
	}

	msg->l2h = msg->data;
	ipa_prepend_header(msg, sign_link->tei);

	DEBUGP(DLMI, "TX %u: %s\n", ts_nr, osmo_hexdump(msg->l2h, msgb_l2len(msg)));

	int written = SSL_write(ssl->ssl, msg->data, msg->len);
	OSMO_ASSERT(SSL_ERROR_NONE == SSL_get_error(ssl->ssl, written));

	char outbuf[8192] = {0};
	int read = BIO_read(ssl->output_bio, outbuf, sizeof(outbuf));
	OSMO_ASSERT(SSL_ERROR_NONE == SSL_get_error(ssl->ssl, read));

	ret = send(bfd->fd, outbuf, read, 0);
	//if (ret != rmsg->len) {
	if (ret <= 0) {		
		LOGP(DLINP, LOGL_ERROR, "failed to send A-bis IPA signalling "
			"message. Reason: %s\n", strerror(errno));
		goto err;
	}

	/* set tx delay timer for next event */
	osmo_timer_setup(&e1i_ts->sign.tx_timer, timeout_ts1_ssl_write, e1i_ts);

	/* Reducing this might break the nanoBTS 900 init. */
	osmo_timer_schedule(&e1i_ts->sign.tx_timer, 0, e1i_ts->sign.delay);

out:
	msgb_free(msg);
	return ret;
err:
	ipaccess_ssl_drop(bfd, line);
	msgb_free(msg);
	return ret;
}


//
//BSC side write callback. wrapper for __handle_ts1_ssl_write
//
static int handle_ts1_ssl_write(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	struct ipaccess_ssl_line* il = line->driver_data;
	struct ssl_data* ssl = bfd->priv_nr == E1INP_SIGN_OML ?
									il->oml_ssl : il->rsl_ssl;

	return __handle_ts1_ssl_write(bfd, line, ssl);
}

/* Returns -EBADF if bfd cannot be used by the caller anymore after return. */
static int handle_ts1_ssl_read(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	struct ipaccess_ssl_line* il = line->driver_data;
	struct ssl_data* ssl = bfd->priv_nr == E1INP_SIGN_OML ?
									il->oml_ssl : il->rsl_ssl;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts;
	struct e1inp_sign_link *link;
	struct ipaccess_head *hh;
	struct msgb *msg = NULL;
	int ret, rc;

	if (bfd->priv_nr == E1INP_SIGN_OML)
		e1i_ts = e1inp_line_ipa_oml_ts(line);
	else
		e1i_ts = e1inp_line_ipa_rsl_ts(line, bfd->priv_nr - E1INP_SIGN_RSL);

	// we have nothing in input_bio to parse,
	// hence need to read more encrypted data from socket
	if (!BIO_pending(ssl->input_bio)) {
		char buf[4096] = {0}; // size ???

		ret = recv(bfd->fd, buf, sizeof buf, 0);

		if (ret < 0) {
			if (ret == -EAGAIN)
				return 0;

			LOGP(DLINP, LOGL_NOTICE, "Sign link problems, "
				"closing socket. Reason: %s\n", strerror(-ret));
			goto err;
		} else if (ret == 0) {
			LOGP(DLINP, LOGL_NOTICE, "Sign link vanished, dead socket\n");
			goto err;
		}

		int written = BIO_write(ssl->input_bio, buf, ret);
		OSMO_ASSERT(SSL_ERROR_NONE == SSL_get_error(ssl->ssl, written));
	}

get_message_from_bio:
	ret = ipa_ssl_msg_recv_buffered(bfd, &msg, &e1i_ts->pending_msg, ssl->ssl);

	if (ret < 0) {
		if (ret == -EAGAIN)
			return 0;
		LOGP(DLINP, LOGL_NOTICE, "Sign link problems, "
			"closing socket. Reason: %s\n", strerror(-ret));
		goto err;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_NOTICE, "Sign link vanished, dead socket\n");
		goto err;
	}


	DEBUGP(DLMI, "RX %u: %s\n", ts_nr, osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)));

	hh = (struct ipaccess_head *) msg->data;
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		ret = ipaccess_ssl_rcvmsg(line, msg, bfd, ssl);
		/* BIG FAT WARNING: bfd might no longer exist here (ret != 0),
		 * since ipaccess_rcvmsg() might have free'd it !!! */
		msgb_free(msg);
		return ret != 0 ? -EBADF : 0;
	} else if (e1i_ts->type == E1INP_TS_TYPE_NONE) {
		/* this sign link is not know yet.. complain. */
		LOGP(DLINP, LOGL_ERROR, "Timeslot is not configured.\n");
		goto err_msg;
	}

	link = e1inp_lookup_sign_link(e1i_ts, hh->proto, 0);
	if (!link) {
		LOGP(DLINP, LOGL_ERROR, "no matching signalling link for "
			"hh->proto=0x%02x\n", hh->proto);
		goto err_msg;
	}
	msg->dst = link;

	/* XXX better use e1inp_ts_rx? */
	if (!e1i_ts->line->ops->sign_link) {
		LOGP(DLINP, LOGL_ERROR, "Fix your application, "
			"no action set for signalling messages.\n");
		goto err_msg;
	}

	LOGP(DLINP, LOGL_DEBUG, "before e1i_ts->line->ops->sign_link(msg)\n");
	rc = e1i_ts->line->ops->sign_link(msg);
	if (rc < 0) {
		/* Don't close the signalling link if the upper layers report
		 * an error, that's too strict. BTW, the signalling layer is
		 * resposible for releasing the message.
		 */
		LOGP(DLINP, LOGL_ERROR, "Bad signalling message,"
		     " sign_link returned error: %s.\n", strerror(-rc));
	}

	// check if we got some unсlaimed SSL data:
	// we can not return from func here, since there might be unсlaimed SSL data
	// which we already read from socket, but we only processed one message so far
	// hence loop back via goto until all already-socket-read data is processed
	if (BIO_pending(ssl->input_bio))
		goto get_message_from_bio;

	return rc;

err_msg:
	msgb_free(msg);
err:
	ipaccess_ssl_drop(bfd, line);
	return -EBADF;
}


static void e1inp_ipa_ssl_ssl_init(SSL_CTX* ctx, struct ssl_data* ssl)
{
	OSMO_ASSERT(ssl);
 	OSMO_ASSERT(ctx);

	ssl->output_bio = BIO_new(BIO_s_mem());
	ssl->input_bio = BIO_new(BIO_s_mem());

	ssl->ssl = SSL_new(ctx);

	SSL_set_bio(ssl->ssl, ssl->input_bio, ssl->output_bio);
	SSL_set_accept_state(ssl->ssl);
}


static int ipa_ssl_send(struct osmo_fd* ofd, const void *msg, size_t msglen,
								 struct ssl_data* ssl)
{
	int ret;
	char outbuf[4096] = {0}; //size ???

	int written = SSL_write(ssl->ssl, msg, msglen);
	OSMO_ASSERT(SSL_ERROR_NONE==SSL_get_error(ssl->ssl, written));

	int read = BIO_read(ssl->output_bio, outbuf, sizeof(outbuf));
	OSMO_ASSERT(SSL_ERROR_NONE == SSL_get_error(ssl->ssl, read));

	ret = write(ofd->fd, outbuf, read);
	if (ret < 0)
		return -errno;
	if (ret < read) {
		LOGP(DLINP, LOGL_ERROR, "ipa_ssl_send: short write\n");
		return -EIO;
	}
	return ret;
}



static int ipa_ssl_ccm_send_pong(struct osmo_fd* ofd, struct ssl_data* ssl);
static int ipa_ssl_ccm_send_id_ack(struct osmo_fd* ofd, struct ssl_data* ssl);
/* base handling of the ip.access protocol */
static int ipa_ssl_ccm_rcvmsg_base(struct msgb *msg, struct osmo_fd *bfd, struct ssl_data* ssl)
{
	uint8_t msg_type = *(msg->l2h);
	int ret;

	switch (msg_type) {
	case IPAC_MSGT_PING:
		ret = ipa_ssl_ccm_send_pong(bfd, ssl);
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR, "Cannot send PING "
			     "message. Reason: %s\n", strerror(errno));
			break;
		}
		ret = 1;
		break;
	case IPAC_MSGT_PONG:
		DEBUGP(DLMI, "PONG!\n");
		ret = 1;
		break;
	case IPAC_MSGT_ID_ACK:
		DEBUGP(DLMI, "ID_ACK? -> ACK!\n");
		ret = ipa_ssl_ccm_send_id_ack(bfd, ssl);
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR, "Cannot send ID_ACK "
			     "message. Reason: %s\n", strerror(errno));
			break;
		}
		ret = 1;
		break;
	default:
		/* This is not an IPA PING, PONG or ID_ACK message */
		ret = 0;
		break;
	}
	return ret;
}



/*
 * Common propietary IPA messages:
 *      - PONG: in reply to PING.
 *      - ID_REQUEST: first messages once OML has been established.
 *      - ID_ACK: in reply to ID_ACK.
 */
static const uint8_t ipa_pong_msg[] = {
	0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_PONG
};

static const uint8_t ipa_id_ack_msg[] = {
	0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_ACK
};

static const uint8_t ipa_id_req_msg[] = {
	0, 17, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_GET,
	0x01, IPAC_IDTAG_UNIT,
	0x01, IPAC_IDTAG_MACADDR,
	0x01, IPAC_IDTAG_LOCATION1,
	0x01, IPAC_IDTAG_LOCATION2,
	0x01, IPAC_IDTAG_EQUIPVERS,
	0x01, IPAC_IDTAG_SWVERSION,
	0x01, IPAC_IDTAG_UNITNAME,
	0x01, IPAC_IDTAG_SERNR,
};

static int ipa_ssl_ccm_send_pong(struct osmo_fd* ofd, struct ssl_data* ssl)
{
	return ipa_ssl_send(ofd, ipa_pong_msg, sizeof(ipa_pong_msg), ssl);
}

static int ipa_ssl_ccm_send_id_ack(struct osmo_fd* ofd, struct ssl_data* ssl)
{
	return ipa_ssl_send(ofd, ipa_id_ack_msg, sizeof(ipa_id_ack_msg), ssl);
}


//from BSC to BTS only ?
static int ipa_ssl_ccm_send_id_req(struct osmo_fd* ofd)
{
	struct e1inp_line* line = ofd->data;
	struct ipaccess_ssl_line* il = line->driver_data;
	struct ssl_data* ssl = ofd->priv_nr == E1INP_SIGN_OML ?
									il->oml_ssl : il->rsl_ssl;

	return ipa_ssl_send(ofd, ipa_id_req_msg, sizeof(ipa_id_req_msg), ssl);
}


static void ipaccess_ssl_close(struct e1inp_sign_link *sign_link)
{
	struct e1inp_ts *e1i_ts = sign_link->ts;
	struct osmo_fd *bfd = &e1i_ts->driver.ipaccess.fd;
	return e1inp_close_socket(e1i_ts, sign_link, bfd);
}


static int ipaccess_ssl_bts_write_cb(struct ipa_ssl_client_conn *link)
{
	struct e1inp_line *line = link->line;
	struct ssl_data ssl = {.ssl = link->ssl, .input_bio = link->input_bio,
								 .output_bio = link->output_bio};

	return __handle_ts1_ssl_write(link->ofd, line, &ssl);
}

//
// BSC side callback for any incoming raw socket data (unified, both OML & RSL)
//
// Q: what should retval mean and where is it checked ? A: probably select loop.
// But if so, than there is no any kind of retval check in
// (select.c) osmo_fd_disp_fds -> ufd->cb(ufd, flags) (???)
int ipaccess_ssl_bsc_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	int rc = 0;

	struct e1inp_line* line = bfd->data;
	struct ipaccess_ssl_line* il = line->driver_data;

	enum ipa_ssl_client_conn_state* state = (bfd->priv_nr == E1INP_SIGN_OML) ?
									&(il->oml_state) : &(il->rsl_state);
	struct ssl_data* ssl = 	(bfd->priv_nr == E1INP_SIGN_OML) ?
									il->oml_ssl : il->rsl_ssl;

	switch(*state) {
	case IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTING:
		{
			int error = 0;
			socklen_t len = sizeof(error);
			int ret = getsockopt(bfd->fd, SOL_SOCKET, SO_ERROR, &error, &len);
			OSMO_ASSERT(ret == 0);

			LOGP(DLINP, LOGL_NOTICE, "BTS %s tcp connected\n",
					 (bfd->priv_nr == E1INP_SIGN_OML) ? "OML" : "RSL");

			bfd->when &= ~BSC_FD_WRITE;
			bfd->when |= BSC_FD_READ;

			*state = IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTED;
		}
		break;

	case IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTED:
		{
			char buf[4096] = {0};
			int nbytes = recv(bfd->fd, buf, sizeof buf, 0);
			OSMO_ASSERT(nbytes > 0);

			int written = BIO_write(ssl->input_bio, buf, nbytes);
			OSMO_ASSERT(SSL_ERROR_NONE == SSL_get_error(ssl->ssl, written));

			int res = SSL_do_handshake(ssl->ssl);
			OSMO_ASSERT(SSL_ERROR_WANT_READ == SSL_get_error(ssl->ssl, res));

			bfd->when &= ~BSC_FD_READ;
			bfd->when |= BSC_FD_WRITE;

			*state = IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING;
		}
		break;

	// 1st case: we should sent hello, got writable socket
	// 2nd case: we expect more client data
	case IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING:
		{
			if (!BIO_ctrl_pending(ssl->output_bio)) {	//we have nothing to send
				char buf[4096] = {0}; //?

				int nbytes = recv(bfd->fd, buf, sizeof buf, 0);
				OSMO_ASSERT(nbytes > 0);

				int written = BIO_write(ssl->input_bio, buf, nbytes);
				OSMO_ASSERT(SSL_ERROR_NONE == SSL_get_error(ssl->ssl, written));

				if (!SSL_is_init_finished(ssl->ssl)) {
					int res = SSL_do_handshake(ssl->ssl);
					// we need more server data, need readable socket
					// next time through loop we should be here again
					// BIO_ctrl_pending(output_bio) should be false since
					// we haven't received enough to generate our reply
					if (SSL_get_error(ssl->ssl, res) == SSL_ERROR_WANT_READ) {
						bfd->when &= ~BSC_FD_WRITE;
						bfd->when |= BSC_FD_READ;
						*state = IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING;
						break;
					// now we have our reply, need writable socket to send it
					// BIO_ctrl_pending(output_bio) should be true
					} else if (SSL_get_error(ssl->ssl, res) == SSL_ERROR_NONE &&
									 BIO_ctrl_pending(ssl->output_bio)) {
						bfd->when |= BSC_FD_WRITE;
						bfd->when &= ~BSC_FD_READ;
						*state = IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING;
						break;
					} else {
						OSMO_ASSERT(false);
					}
				}

			//need send our server hello etc and have writable socket
			} else {
				char outbuf [8192] = {0}; // ?
				int read = BIO_read(ssl->output_bio, outbuf, sizeof outbuf);
				OSMO_ASSERT(SSL_ERROR_NONE == SSL_get_error(ssl->ssl, read));

				int nbytes = send(bfd->fd, outbuf, read, 0);
				OSMO_ASSERT(nbytes == read);

				//just in case if handshake is not yet complete
				//TODO can this even happen ???
				if (!SSL_is_init_finished(ssl->ssl)) {
					bfd->when &= ~BSC_FD_WRITE;
					bfd->when |= BSC_FD_READ;
					*state = IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING;
				} else {
					bfd->when |= BSC_FD_WRITE;
					bfd->when &= ~BSC_FD_READ;
					*state = IPA_SSL_CLIENT_LINK_STATE_SSL_CONNECTED;
				}
			}
		}
		break;

	case IPA_SSL_CLIENT_LINK_STATE_SSL_CONNECTED:
		rc = ipa_ssl_ccm_send_id_req(bfd);

		if (rc < 0) {
			LOGP(DLINP, LOGL_ERROR, "could not send ID REQ. Reason: %s\n",
				strerror(errno));
			goto err_socket;
		}

		bfd->when &= ~BSC_FD_WRITE;
		bfd->when |= BSC_FD_READ;
		*state = IPA_SSL_CLIENT_LINK_STATE_ESTABLISHED;
		break;

	case IPA_SSL_CLIENT_LINK_STATE_ESTABLISHED:
		if (what & BSC_FD_READ)
			rc = handle_ts1_ssl_read(bfd);
		if (rc != -EBADF && (what & BSC_FD_WRITE))
			rc = handle_ts1_ssl_write(bfd);
		break;
	default:
		OSMO_ASSERT(false);
		break;
	}

	if (0) {
err_socket:
		osmo_fd_unregister(bfd);
	}

	return rc;
}

static int ipaccess_ssl_line_update(struct e1inp_line *line);

//
// SSL driver name is "ipa" (probably should be like "ipa_ssl" or such)
// This is done to minimize intervention to code base, since
// "ipa" is hardcoded in BTS code:
// in osmo-bts/src/common/abis.c:285:		line = e1inp_line_create(0, "ipa");
// So default plain ipa driver name simultaneously changed to
// "_ipa" in ipaccess.c changed
struct e1inp_driver ipaccess_ssl_driver = {
	.name = "ipa",
	.want_write = ts_want_ssl_write,
	.line_update = ipaccess_ssl_line_update,
	.close = ipaccess_ssl_close,
	.default_delay = 0,
	.has_keepalive = 1,
};

static void update_fd_settings(struct e1inp_line *line, int fd)
{
	int ret;
	int val;

	if (line->keepalive_num_probes) {
		/* Enable TCP keepalive to find out if the connection is gone */
		val = 1;
		ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
		if (ret < 0)
			LOGP(DLINP, LOGL_NOTICE, "Failed to set keepalive: %s\n",
			     strerror(errno));
		else
			LOGP(DLINP, LOGL_NOTICE, "Keepalive is set: %i\n", ret);

#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
		/* The following options are not portable! */
		val = line->keepalive_idle_timeout > 0 ?
			line->keepalive_idle_timeout :
			DEFAULT_TCP_KEEPALIVE_IDLE_TIMEOUT;
		ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
				 &val, sizeof(val));
		if (ret < 0)
			LOGP(DLINP, LOGL_NOTICE,
			     "Failed to set keepalive idle time: %s\n",
			     strerror(errno));
		val = line->keepalive_probe_interval > -1 ?
			line->keepalive_probe_interval :
			DEFAULT_TCP_KEEPALIVE_INTERVAL;
		ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
				 &val, sizeof(val));
		if (ret < 0)
			LOGP(DLINP, LOGL_NOTICE,
			     "Failed to set keepalive interval: %s\n",
			     strerror(errno));
		val = line->keepalive_num_probes > 0 ?
			line->keepalive_num_probes :
			DEFAULT_TCP_KEEPALIVE_RETRY_COUNT;
		ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
				 &val, sizeof(val));
		if (ret < 0)
			LOGP(DLINP, LOGL_NOTICE,
			     "Failed to set keepalive count: %s\n",
			     strerror(errno));
#endif
	}
}

/* callback of the OML listening filedescriptor */
//
// called on server's OML accept,
// arg *link is kind of abstract link shell (template ?) since
// it is only used for accepting socket
// arg fd is accepted socket fd
static int ipaccess_ssl_bsc_oml_cb(struct ipa_server_link *link, int fd)
{
	int ret = 0;
	int i;
	struct e1inp_line *line;
	struct e1inp_ts *e1i_ts;
	struct osmo_fd *bfd;

	/* clone virtual E1 line for this new OML link. */
	line = e1inp_line_clone(tall_ipa_ssl_ctx, link->line);
	if (line == NULL) {
		LOGP(DLINP, LOGL_ERROR, "could not clone E1 line\n");
		return -ENOMEM;
	}

	struct ipaccess_ssl_line* il = line->driver_data;

	// bad idea (?)
	// context is tall_ipa_ssl_ctx since we need to survive
	// e1inp_line_put() in ipaccess_ssl_rcvmsg
	il->oml_ssl = talloc_zero(tall_ipa_ssl_ctx, struct ssl_data);
	if (il->oml_ssl == NULL) {
		LOGP(DLINP, LOGL_ERROR, "could not create SSL data for OML\n");
		return -ENOMEM;
	}

	e1inp_ipa_ssl_ssl_init(ssl_ctx, il->oml_ssl);

	/* create virtual E1 timeslots for signalling */
	e1inp_ts_config_sign(e1inp_line_ipa_oml_ts(line), line);

	/* initialize the fds */
	for (i = 0; i < ARRAY_SIZE(line->ts); ++i)
		line->ts[i].driver.ipaccess.fd.fd = -1;

	e1i_ts = e1inp_line_ipa_oml_ts(line);

	bfd = &e1i_ts->driver.ipaccess.fd;
	osmo_fd_setup(bfd, fd, BSC_FD_WRITE, ipaccess_ssl_bsc_fd_cb, line, E1INP_SIGN_OML);
	ret = osmo_fd_register(bfd);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not register FD\n");
		goto err_line;
	}

	update_fd_settings(line, bfd->fd);

	il->oml_state = IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTING;

	return ret;
	// this finishes the server's OML accepting socket callback
	// now select should wake ipaccess_ssl_bsc_fd_cb when fd becomes writable
	// there we check getsockopt for error
	// and conclude whether client tcp connected successfully



	//in SSL based version ipa_ccm_send_id_req should happen after SSL is established.
	/* Request ID. FIXME: request LOCATION, HW/SW VErsion, Unit Name, Serno */
/*	ret = ipa_ccm_send_id_req(bfd->fd);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not send ID REQ. Reason: %s\n",
			strerror(errno));
		goto err_socket;
	}
	return ret;

err_socket:
	osmo_fd_unregister(bfd);*/

err_line:
	close(bfd->fd);
	bfd->fd = -1;
	e1inp_line_put(line);
	return ret;
}

// called on server's RSL accept
// arg *link is kind of abstract link shell (template ?) since
// it is only used for accepting socket
// arg fd is accepted socket fd
//
// E1 line assigned here is temprary.
// The corresponding OML created ("real" ?) E1 line
// will be assigned in ipaccess_ssl_rcvmsg case IPAC_MSGT_ID_RESP:
static int ipaccess_ssl_bsc_rsl_cb(struct ipa_server_link *link, int fd)
{
	struct e1inp_line *line;
	struct e1inp_ts *e1i_ts;
	struct osmo_fd *bfd;
	int i, ret;

  /* We don't know yet which OML link to associate it with. Thus, we
   * allocate a temporary E1 line until we have received ID. */
	line = e1inp_line_clone(tall_ipa_ssl_ctx, link->line);
	if (line == NULL) {
		LOGP(DLINP, LOGL_ERROR, "could not clone E1 line\n");
		return -ENOMEM;
	}

	struct ipaccess_ssl_line* il = line->driver_data;
	
	// bad (?)
	// context is tall_ipa_ssl_ctx since we need to survive
	// e1inp_line_put() in ipaccess_ssl_rcvmsg
	il->rsl_ssl = talloc_zero(tall_ipa_ssl_ctx, struct ssl_data);
	if (il->oml_ssl == NULL) {
		LOGP(DLINP, LOGL_ERROR, "could not create SSL data for RSL\n");
		return -ENOMEM;
	}

	/* initialize the fds */
	for (i = 0; i < ARRAY_SIZE(line->ts); ++i)
		line->ts[i].driver.ipaccess.fd.fd = -1;

	/* we need this to initialize this in case to avoid crashes in case
	 * that the socket is closed before we've seen an ID_RESP. */
	e1inp_ts_config_sign(e1inp_line_ipa_oml_ts(line), line);

	e1i_ts = e1inp_line_ipa_rsl_ts(line, 0);

	bfd = &e1i_ts->driver.ipaccess.fd;
	osmo_fd_setup(bfd, fd, BSC_FD_WRITE, ipaccess_ssl_bsc_fd_cb, line, E1INP_SIGN_RSL);
	ret = osmo_fd_register(bfd);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not register FD\n");
		goto err_line;
	}
	update_fd_settings(line, bfd->fd);

	e1inp_ipa_ssl_ssl_init(ssl_ctx, il->rsl_ssl);
	il->rsl_state = IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTING;

	return ret;
	// this finishes the server's RSL accepting socket callback
	// now select should wake ipaccess_ssl_bsc_fd_cb when fd becomes writable
	// there we check getsockopt for error
	// and conclude whether client tcp connected successfully

	//in SSL based version ipa_ccm_send_id_req should happen after SSL is established.
	/* Request ID. FIXME: request LOCATION, HW/SW VErsion, Unit Name, Serno */
/*	ret = ipa_ccm_send_id_req(bfd->fd);
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not send ID REQ. Reason: %s\n",
			strerror(errno));
		goto err_socket;
	}



err_socket:
	osmo_fd_unregister(bfd);*/
err_line:
	close(bfd->fd);
	bfd->fd = -1;
	e1inp_line_put(line);
	return ret;
}

#define IPA_STRING_MAX 64

static struct msgb *
ipa_bts_id_resp(const struct ipaccess_unit *dev, uint8_t *data, int len, int trx_nr)
{
	struct msgb *nmsg;
	char str[IPA_STRING_MAX];
	uint8_t *tag;

	memset(str, 0, sizeof(str));

	nmsg = ipa_msg_alloc(0);
	if (!nmsg)
		return NULL;

	*msgb_put(nmsg, 1) = IPAC_MSGT_ID_RESP;
	while (len) {
		if (len < 2) {
			LOGP(DLINP, LOGL_NOTICE,
				"Short read of ipaccess tag\n");
			msgb_free(nmsg);
			return NULL;
		}
		switch (data[1]) {
		case IPAC_IDTAG_UNIT:
			snprintf(str, sizeof(str), "%u/%u/%u",
				dev->site_id, dev->bts_id, trx_nr);
			break;
		case IPAC_IDTAG_MACADDR:
			snprintf(str, sizeof(str),
				 "%02x:%02x:%02x:%02x:%02x:%02x",
				 dev->mac_addr[0], dev->mac_addr[1],
				 dev->mac_addr[2], dev->mac_addr[3],
				 dev->mac_addr[4], dev->mac_addr[5]);
			break;
		case IPAC_IDTAG_LOCATION1:
			if (dev->location1)
				osmo_strlcpy(str, dev->location1, sizeof(str));
			break;
		case IPAC_IDTAG_LOCATION2:
			if (dev->location2)
				osmo_strlcpy(str, dev->location2, sizeof(str));
			break;
		case IPAC_IDTAG_EQUIPVERS:
			if (dev->equipvers)
				osmo_strlcpy(str, dev->equipvers, sizeof(str));
			break;
		case IPAC_IDTAG_SWVERSION:
			if (dev->swversion)
				osmo_strlcpy(str, dev->swversion, sizeof(str));
			break;
		case IPAC_IDTAG_UNITNAME:
			snprintf(str, sizeof(str),
				 "%s-%02x-%02x-%02x-%02x-%02x-%02x",
				 dev->unit_name,
				 dev->mac_addr[0], dev->mac_addr[1],
				 dev->mac_addr[2], dev->mac_addr[3],
				 dev->mac_addr[4], dev->mac_addr[5]);
			break;
		case IPAC_IDTAG_SERNR:
			if (dev->serno)
				osmo_strlcpy(str, dev->serno, sizeof(str));
			break;
		default:
			LOGP(DLINP, LOGL_NOTICE,
				"Unknown ipaccess tag 0x%02x\n", *data);
			msgb_free(nmsg);
			return NULL;
		}

		LOGP(DLINP, LOGL_INFO, " tag %d: %s\n", data[1], str);
		tag = msgb_put(nmsg, 3 + strlen(str) + 1);
		tag[0] = 0x00;
		tag[1] = 1 + strlen(str) + 1;
		tag[2] = data[1];
		memcpy(tag + 3, str, strlen(str) + 1);
		data += 2;
		len -= 2;
	}
	ipa_ssl_msg_push_header(nmsg, IPAC_PROTO_IPACCESS);
	return nmsg;
}

static struct msgb *ipa_bts_id_ack(void)
{
	struct msgb *nmsg2;

	nmsg2 = ipa_msg_alloc(0);
	if (!nmsg2) {
		return NULL;
	}

	*msgb_put(nmsg2, 1) = IPAC_MSGT_ID_ACK;
	ipa_ssl_msg_push_header(nmsg2, IPAC_PROTO_IPACCESS);

	return nmsg2;
}

static void ipaccess_ssl_bts_updown_cb(struct ipa_ssl_client_conn *link, int up)
{
	struct e1inp_line *line = link->line;

	if (up) {
		return;
	}

	if (line->ops->sign_link_down) {
		line->ops->sign_link_down(line);
	}
}


static int ipa_ssl_ccm_rcvmsg_bts_base(struct msgb *msg, struct ipa_ssl_client_conn *link)
{
	uint8_t msg_type = *(msg->l2h);
	int ret = 0;

	switch (msg_type) {
	case IPAC_MSGT_PING:
		ret = ipa_ssl_ccm_send_pong(link->ofd, 
			&((struct ssl_data)
				{.ssl = link->ssl, .input_bio = link->input_bio, .output_bio = link->output_bio}));
		if (ret < 0) {
			LOGP(DLINP, LOGL_ERROR, "Cannot send PONG "
			     "message. Reason: %s\n", strerror(errno));
		}
		break;
	case IPAC_MSGT_PONG:
		DEBUGP(DLMI, "PONG!\n");
		break;
	case IPAC_MSGT_ID_ACK:
		DEBUGP(DLMI, "ID_ACK\n");
		break;
	default:
		DEBUGP(DLMI, "Got %d (Not IPAC_MSGT_PING, IPAC_MSGT_ID_ACK or ID_ACK)\n", msg_type);
		break;
	}
	return ret;
}

/* handle incoming message to BTS, check if it is an IPA CCM, and if yes,
 * handle it accordingly (PING/PONG/ID_REQ/ID_RESP/ID_ACK) */
static int ipaccess_ssl_bts_handle_ccm(struct ipa_ssl_client_conn *link,
			    struct ipaccess_unit *dev, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct msgb *rmsg;
	int ret = 0;

	/* special handling for IPA CCM. */
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		uint8_t msg_type = *(msg->l2h);

		/* handle ping, pong and acknowledgment cases. */
		ret = ipa_ssl_ccm_rcvmsg_bts_base(msg, link);
		if (ret < 0)
			goto err;

		/* this is a request for identification from the BSC. */
		if (msg_type == IPAC_MSGT_ID_GET) {
			uint8_t *data = msgb_l2(msg);
			int len = msgb_l2len(msg);
			int trx_nr = 0;

			if (link->ofd->priv_nr >= E1INP_SIGN_RSL)
				trx_nr = link->ofd->priv_nr - E1INP_SIGN_RSL;

			LOGP(DLINP, LOGL_NOTICE, "received ID get from %u/%u/%u\n",
			     dev->site_id, dev->bts_id, trx_nr);
			rmsg = ipa_bts_id_resp(dev, data + 1, len - 1, trx_nr);
			ret = ipa_ssl_send(link->ofd, rmsg->data, rmsg->len, &((struct ssl_data)
				{.ssl = link->ssl, .input_bio = link->input_bio, .output_bio = link->output_bio}));
			//if (ret != rmsg->len) {
			if (ret <= 0) {
				LOGP(DLINP, LOGL_ERROR, "cannot send ID_RESP "
				     "message. Reason: %s\n", strerror(errno));
				goto err_rmsg;
			}
			msgb_free(rmsg);

			/* send ID_ACK. */
			rmsg = ipa_bts_id_ack();
			ret = ipa_ssl_send(link->ofd, rmsg->data, rmsg->len, &((struct ssl_data)
				{.ssl = link->ssl, .input_bio = link->input_bio, .output_bio = link->output_bio}));
			//if (ret != rmsg->len) {
			if (ret <= 0) {
				LOGP(DLINP, LOGL_ERROR, "cannot send ID_ACK "
				     "message. Reason: %s\n", strerror(errno));
				goto err_rmsg;
			}
			msgb_free(rmsg);
		}
		return 1;
	}

	return 0;

err_rmsg:
	msgb_free(rmsg);
err:
	ipa_ssl_client_conn_close(link);
	return -1;
}

//a unified BTS-side OML/RSL callback
static int ipaccess_ssl_bts_read_cb(struct ipa_ssl_client_conn *link, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct e1inp_ts *e1i_ts = NULL;
	struct e1inp_sign_link *sign_link;
	uint8_t msg_type = *(msg->l2h);
	int ret = 0;

	/* special handling for IPA CCM. */
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		/* this is a request for identification from the BSC. */
		if (msg_type == IPAC_MSGT_ID_GET) {
			if (!link->line->ops->sign_link_up) {
				LOGP(DLINP, LOGL_ERROR,
					"Unable to set signal link, "
					"closing socket.\n");
				goto err;
			}
		}
	}

	/* core CCM handling */
	ret = ipaccess_ssl_bts_handle_ccm(link, link->line->ops->cfg.ipa.dev, msg);
	if (ret < 0)
		goto err;

	if (ret == 1 && hh->proto == IPAC_PROTO_IPACCESS) {
		if (msg_type == IPAC_MSGT_ID_GET) {
			sign_link = link->line->ops->sign_link_up(msg,
					link->line,
					link->ofd->priv_nr);
			if (sign_link == NULL) {
				LOGP(DLINP, LOGL_ERROR,
					"Unable to set signal link, "
					"closing socket.\n");
				goto err;
			}
		}
		msgb_free(msg);
		return ret;
	} else if (link->port == IPA_SSL_PORT_OML)
		e1i_ts = e1inp_line_ipa_oml_ts(link->line);
	else if (link->port == IPA_SSL_PORT_RSL)
		e1i_ts = e1inp_line_ipa_rsl_ts(link->line, link->ofd->priv_nr - E1INP_SIGN_RSL);

	OSMO_ASSERT(e1i_ts != NULL);

	if (e1i_ts->type == E1INP_TS_TYPE_NONE) {
		LOGP(DLINP, LOGL_ERROR, "Signalling link not initialized. Discarding."
		     " port=%u msg_type=%u\n", link->port, msg_type);
		goto err;
	}

	/* look up for some existing signaling link. */
	sign_link = e1inp_lookup_sign_link(e1i_ts, hh->proto, 0);
	if (sign_link == NULL) {
		LOGP(DLINP, LOGL_ERROR, "no matching signalling link for "
			"hh->proto=0x%02x\n", hh->proto);
		goto err;
	}
	msg->dst = sign_link;

	/* XXX better use e1inp_ts_rx? */
	if (!link->line->ops->sign_link) {
		LOGP(DLINP, LOGL_ERROR, "Fix your application, "
			"no action set for signalling messages.\n");
		goto err;
	}

	LOGP(DLINP, LOGL_DEBUG, "before link->line->ops->sign_link(msg)\n");
	return link->line->ops->sign_link(msg);

err:
	ipa_ssl_client_conn_close(link);
	msgb_free(msg);
	return -EBADF;
}



const char *e1inp_ipa_ssl_get_bind_addr(void);

//
// Driver specific initialization (?)
// (see struct e1inp_driver ipaccess_ssl_driver -> line_update
//
// Called by library user as driver->line_update (see below):
//
// if we are "ipa_ssl" type BTS then this function gets called 
// at least once on BTS startup (may be somewhere else, no idea yet)
// BTS: (main.c) bts_main -> (abis.c) abis_open ->
// -> (e1_input.c) e1inp_line_update -> corresponding driver's line_update func,
// which is ipaccess_ssl_line_update here below
//
// if we are BSC then this function gets called on 
// at least once on BSC startup (may be somewhere else, no idea yet)
// for every "ipa_ssl" type BTS configured in config file:
// (osmo_bsc_main.c) main -> (osmo_bsc_main.c) bsc_network_configure ->
// -> (e1_config.c) e1_reconfig_bts ->  e1inp_line_update -> corresponding driver's line_update func,
// which is ipaccess_ssl_line_update here below
//
static int ipaccess_ssl_line_update(struct e1inp_line *line)
{
	int ret = -ENOENT;
	struct ipaccess_ssl_line *il;

	if (!line->driver_data)
		line->driver_data = talloc_zero(line, struct ipaccess_ssl_line);

	if (!line->driver_data) {
		LOGP(DLINP, LOGL_ERROR, "ipaccess: OOM in line update\n");
		return -ENOMEM;
	}
	il = line->driver_data;

	/* We only initialize this line once. */
	if (il->line_already_initialized)
		return 0;

	il->line_already_initialized = 1;

	switch(line->ops->cfg.ipa.role) {
	case E1INP_LINE_R_BSC: {
		struct ipa_server_link *oml_link, *rsl_link;
		const char *ipa = e1inp_ipa_ssl_get_bind_addr();

		ipa_ssl_global_ssl_init(SSL_SERVER_STR, &ssl_ctx);

		LOGP(DLINP, LOGL_NOTICE, "enabling ipaccess BSC mode on %s "
		     "with OML %u and RSL %u TCP ports\n", ipa,
		     IPA_SSL_PORT_OML, IPA_SSL_PORT_RSL);

		oml_link = ipa_server_link_create(tall_ipa_ssl_ctx, line, ipa,
						  IPA_SSL_PORT_OML,
						  ipaccess_ssl_bsc_oml_cb, NULL);
		if (oml_link == NULL) {
			LOGP(DLINP, LOGL_ERROR, "cannot create OML "
				"BSC link: %s\n", strerror(errno));
			return -ENOMEM;
		}
		if (ipa_server_link_open(oml_link) < 0) { //registers server's (accepting) fd w/ select
			LOGP(DLINP, LOGL_ERROR, "cannot open OML BSC link: %s\n",
				strerror(errno));
			ipa_server_link_destroy(oml_link);
			return -EIO;
		}

		rsl_link = ipa_server_link_create(tall_ipa_ssl_ctx, line, ipa,
						  IPA_SSL_PORT_RSL,
						  ipaccess_ssl_bsc_rsl_cb, NULL);
		if (rsl_link == NULL) {
			LOGP(DLINP, LOGL_ERROR, "cannot create RSL "
				"BSC link: %s\n", strerror(errno));
			return -ENOMEM;
		}
		if (ipa_server_link_open(rsl_link) < 0) {
			LOGP(DLINP, LOGL_ERROR, "cannot open RSL BSC link: %s\n",
				strerror(errno));
			ipa_server_link_destroy(rsl_link);
			return -EIO;
		}
		LOGP(DLINP, LOGL_NOTICE, "enabled ipaccess BSC mode on %s "
		     "with OML %u and RSL %u TCP ports\n", ipa,
		     IPA_SSL_PORT_OML, IPA_SSL_PORT_RSL);
		ret = 0;
		break;
	}

	case E1INP_LINE_R_BTS: {
		struct ipa_ssl_client_conn *link;

		LOGP(DLINP, LOGL_NOTICE, "enabling ipaccess BTS mode, "
		     "OML connecting to %s:%u\n", line->ops->cfg.ipa.addr,
		     IPA_SSL_PORT_OML);

		ipa_ssl_global_ssl_init(SSL_CLIENT_STR, &ssl_ctx);

		link = ipa_ssl_client_conn_create(tall_ipa_ssl_ctx,
					      e1inp_line_ipa_oml_ts(line),
					      E1INP_SIGN_OML,
					      line->ops->cfg.ipa.addr,
					      IPA_SSL_PORT_OML,
					      ipaccess_ssl_bts_updown_cb,
					      ipaccess_ssl_bts_read_cb,
					      ipaccess_ssl_bts_write_cb,
					      line);
		if (link == NULL) {
			LOGP(DLINP, LOGL_ERROR, "cannot create OML "
				"BTS link: %s\n", strerror(errno));
			return -ENOMEM;
		}
		if (ipa_ssl_client_conn_open(link) < 0) {
			LOGP(DLINP, LOGL_ERROR, "cannot open OML BTS link: %s\n",
				strerror(errno));
			ipa_ssl_client_conn_close(link);
			ipa_ssl_client_conn_destroy(link);
			return -EIO;
		}
		ret = 0;
		break;
	}
	default:
		break;
	}
	return ret;
}


//
//used by user code of BTS to create one new RSL link per transiever (?)
//called when corresponding command arrives on OML (which one ?)
int e1inp_ipa_ssl_bts_rsl_connect_n(struct e1inp_line *line,
				const char *rem_addr, uint16_t rem_port,
				uint8_t trx_nr)
{
	struct ipa_ssl_client_conn *rsl_link;

	if (E1INP_SIGN_RSL+trx_nr-1 >= NUM_E1_TS) {
		LOGP(DLINP, LOGL_ERROR, "cannot create RSL BTS link: "
			"trx_nr (%d) out of range\n", trx_nr);
		return -EINVAL;
	}

	// hack !
	// IPA_SSL_PORT_RSL hardcoded, but should use port decoded from OML command
	rsl_link = ipa_ssl_client_conn_create(tall_ipa_ssl_ctx,
					  e1inp_line_ipa_rsl_ts(line, trx_nr),
					  E1INP_SIGN_RSL+trx_nr,
					  rem_addr, IPA_SSL_PORT_RSL,
					  ipaccess_ssl_bts_updown_cb,
					  ipaccess_ssl_bts_read_cb,
					  ipaccess_ssl_bts_write_cb,
					  line);
	if (rsl_link == NULL) {
		LOGP(DLINP, LOGL_ERROR, "cannot create RSL "
			"BTS link: %s\n", strerror(errno));
		return -ENOMEM;
	}

	if (ipa_ssl_client_conn_open(rsl_link) < 0) {
		LOGP(DLINP, LOGL_ERROR, "cannot open RSL BTS link: %s\n",
			strerror(errno));
		ipa_ssl_client_conn_close(rsl_link);
		ipa_ssl_client_conn_destroy(rsl_link);
		return -EIO;
	}
	return 0;
}

/* backwards compatibility */
int e1inp_ipa_ssl_bts_rsl_connect(struct e1inp_line *line,
			      const char *rem_addr, uint16_t rem_port)
{
	return e1inp_ipa_ssl_bts_rsl_connect_n(line, rem_addr, rem_port, 0);
}


//
// Overall users of abis lib should use libosmo_abis_init
// which, in turn, loads and registers drivers etc
// So e1inp_ipaccess_ssl_init probably shouldn't be called by any user code
//
// For example, abis_init is called in a common code of osmo-bts
// which is a 'wrapper' for libosmo_abis_init
//
// In osmo-bsc libosmo_abis_init is called as is in main
//
void e1inp_ipaccess_ssl_init(void)
{
	tall_ipa_ssl_ctx = talloc_named_const(libosmo_abis_ctx, 1, "ipa_ssl");
	e1inp_driver_register(&ipaccess_ssl_driver);
}

void e1inp_ipa_ssl_set_bind_addr(const char *ip_bind_addr)
{
	talloc_free((char*)ipaccess_ssl_driver.bind_addr);
	ipaccess_ssl_driver.bind_addr = NULL;

	if (ip_bind_addr)
		ipaccess_ssl_driver.bind_addr = talloc_strdup(tall_ipa_ssl_ctx,
							  ip_bind_addr);
}

const char *e1inp_ipa_ssl_get_bind_addr(void)
{
	return ipaccess_ssl_driver.bind_addr ?
		ipaccess_ssl_driver.bind_addr
		: "0.0.0.0";
}
