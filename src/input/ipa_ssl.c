#include "internal.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <osmocom/core/select.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/core/byteswap.h>

#include <osmocom/abis/e1_input.h>

#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/gsm/ipa.h>

#include <osmocom/abis/ipa_ssl.h>
#include <osmocom/abis/ipa_ssl_common.h>

#define LOGIPA(link, level, fmt, args...) LOGP(DLINP, level, "%s:%u " fmt, link->addr, link->port, ## args)


void ipa_ssl_client_conn_close(struct ipa_ssl_client_conn *link)
{
	/* be safe against multiple calls */
	if (link->ofd->fd != -1) {
		osmo_fd_unregister(link->ofd);
		close(link->ofd->fd);
		link->ofd->fd = -1;
	}
	msgb_free(link->pending_msg);
	link->pending_msg = NULL;
}



int ipa_ssl_client_read(struct ipa_ssl_client_conn *link)
{
	struct osmo_fd *ofd = link->ofd;
	struct msgb *msg;
	int ret;

	// we have nothing in input_bio to parse,
	// hence need to read more encrypted data from socket
	if (!BIO_pending(link->input_bio)) {
		char buf[4096] = {0}; // size ???

		ret = recv(ofd->fd, buf, sizeof buf, 0);

		if (ret <= 0) {
			if (ret == -EAGAIN) {
				return 0;
			} else if (ret == -EPIPE || ret == -ECONNRESET) {
				LOGIPA(link, LOGL_ERROR, "lost connection with server\n");
			} else if (ret == 0) {
				LOGIPA(link, LOGL_ERROR, "connection closed with server\n");
			}
			ipa_ssl_client_conn_close(link);
			if (link->updown_cb) {
				link->updown_cb(link, 0);
			}
			return -EBADF;
		}

		int written = BIO_write(link->input_bio, buf, ret);
		OSMO_ASSERT(SSL_ERROR_NONE == SSL_get_error(link->ssl, written));
	}

get_message_from_bio:
	ret = ipa_ssl_msg_recv_buffered(ofd, &msg, &link->pending_msg, link->ssl);

	int read_cb_res;
	if (ret > 0) {
		if (link->read_cb)
			//return link->read_cb(link, msg);
			read_cb_res = link->read_cb(link, msg);		
	} else if (ret != -EAGAIN) {
		OSMO_ASSERT(false);
	}

	// check if we got some unсlaimed SSL data
	if (BIO_pending(link->input_bio))
		goto get_message_from_bio;

	return 0;
}

static void ipa_ssl_client_write(struct ipa_ssl_client_conn *link)
{
	if (link->write_cb) {
		link->write_cb(link);
	}
}

static int ipa_ssl_client_write_default_cb(struct ipa_ssl_client_conn *link)
{
	struct osmo_fd *ofd = link->ofd;
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	LOGIPA(link, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&link->tx_queue)) {
		ofd->when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = link->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	ret = send(link->ofd->fd, msg->data, msg->len, 0);
	if (ret < 0) {
		if (errno == EPIPE || errno == ENOTCONN) {
			ipa_ssl_client_conn_close(link);
			if (link->updown_cb) {
				link->updown_cb(link, 0);
			}
		}
		LOGIPA(link, LOGL_ERROR, "error to send\n");
	}
	msgb_free(msg);
	return 0;
}

//lowest level callback on BTS socket (?)
//this is called any time when select clinet sock fd returns
//for write or read socket avialability
static int ipa_ssl_client_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct ipa_ssl_client_conn *link = ofd->data;
	int error, ret = 0;
	socklen_t len = sizeof(error);

	switch(link->state) {
	case IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTING:

		ret = getsockopt(ofd->fd, SOL_SOCKET, SO_ERROR, &error, &len);
		if (ret >= 0 && error > 0) {
			ipa_ssl_client_conn_close(link);
			if (link->updown_cb)
				link->updown_cb(link, 0);
			return 0;
		}

		ofd->when |= BSC_FD_WRITE;
		ofd->when &= ~BSC_FD_READ;

		LOGIPA(link, LOGL_DEBUG, "BTS %s tcp connected\n",
					 (ofd->priv_nr == E1INP_SIGN_OML) ? "OML" : "RSL");
		link->state = IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING;

/*		ofd->when &= ~BSC_FD_WRITE;
		LOGIPA(link, LOGL_NOTICE, "connection done\n");
		link->state = IPA_CLIENT_LINK_STATE_CONNECTED;
		if (link->updown_cb)
			link->updown_cb(link, 1);*/

		break;

	case IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING:
		ret = SSL_do_handshake(link->ssl);

		if (SSL_ERROR_WANT_READ == SSL_get_error(link->ssl, ret) &&
				BIO_ctrl_pending(link->output_bio)) {
			char outbuf[8192] = {0};

			int read = BIO_read(link->output_bio, outbuf, sizeof(outbuf));
			OSMO_ASSERT(SSL_ERROR_NONE==SSL_get_error(link->ssl, read));

			int sent = send(ofd->fd, outbuf, read, 0);
			OSMO_ASSERT(sent > 0 && sent == read); //not handling short socket writes

			ofd->when &= ~BSC_FD_WRITE;
			ofd->when |= BSC_FD_READ;
			link->state = IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING_NEED_RECV;
			break;
		} else if (SSL_ERROR_WANT_READ == SSL_get_error(link->ssl, ret) &&
						!BIO_ctrl_pending(link->output_bio)) {
			ofd->when &= ~BSC_FD_WRITE;
			ofd->when |= BSC_FD_READ;
			link->state = IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING_NEED_RECV;
			break;
		} else if (SSL_ERROR_NONE == SSL_get_error(link->ssl, ret) &&
						BIO_ctrl_pending(link->output_bio)) {
			char outbuf[8192] = {0};

			int read = BIO_read(link->output_bio, outbuf, sizeof(outbuf));
			OSMO_ASSERT(SSL_ERROR_NONE==SSL_get_error(link->ssl, read));

			int sent = send(ofd->fd, outbuf, read, 0);
			OSMO_ASSERT(sent > 0 && sent == read); //not handling short socket writes

			ofd->when &= ~BSC_FD_WRITE;
			ofd->when |= BSC_FD_READ;
			link->state = IPA_SSL_CLIENT_LINK_STATE_SSL_CONNECTED;
			break;
		} else if (SSL_ERROR_NONE == SSL_get_error(link->ssl, ret) &&
						SSL_is_init_finished(link->ssl)) {
			ofd->when &= ~BSC_FD_WRITE;
			ofd->when |= BSC_FD_READ;
			link->state = IPA_SSL_CLIENT_LINK_STATE_SSL_CONNECTED;
		} else {
			OSMO_ASSERT(false); //any other ssl error
		}
		break;

	case IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING_NEED_RECV:
			OSMO_ASSERT(!BIO_ctrl_pending(link->output_bio));

			char buf[8192] = {0};
			int nbytes = recv(ofd->fd, buf, sizeof buf, 0);
			OSMO_ASSERT(nbytes > 0);

			//we got nbytes of socket data, presumably server hello, cert etc...
			int written = BIO_write(link->input_bio, buf, nbytes);
			OSMO_ASSERT(SSL_ERROR_NONE == SSL_get_error(link->ssl, written));

			ofd->when |= BSC_FD_WRITE;
			ofd->when &= ~BSC_FD_READ;
			link->state = IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING;
		break;

	case IPA_SSL_CLIENT_LINK_STATE_SSL_CONNECTED:
		if (link->updown_cb) {
			link->updown_cb(link, 1);
		}
		//now we should wait for BSC's ID request
		ofd->when &= ~BSC_FD_WRITE;
		ofd->when |= BSC_FD_READ;
		link->state = IPA_SSL_CLIENT_LINK_STATE_ESTABLISHED;
		break;

	case IPA_SSL_CLIENT_LINK_STATE_ESTABLISHED:
		if (what & BSC_FD_READ) {
			LOGIPA(link, LOGL_DEBUG, "connected read\n");
			ret = ipa_ssl_client_read(link);
		}

		if (ret != -EBADF && (what & BSC_FD_WRITE)) {
			LOGIPA(link, LOGL_DEBUG, "connected write\n");
			ipa_ssl_client_write(link);
		}
		break;

	default:
		OSMO_ASSERT(false);
		break;
	}

	return 0;
}

static void ipa_ssl_link_ssl_init(struct ipa_ssl_client_conn* ipa_link) {
	OSMO_ASSERT(ipa_link);
	OSMO_ASSERT(ssl_ctx);

	ipa_link->output_bio = BIO_new(BIO_s_mem());
	ipa_link->input_bio = BIO_new(BIO_s_mem());

	ipa_link->ssl = SSL_new(ssl_ctx);

	SSL_set_bio(ipa_link->ssl, ipa_link->input_bio, ipa_link->output_bio);
	SSL_set_connect_state(ipa_link->ssl);
}


struct ipa_ssl_client_conn *
ipa_ssl_client_conn_create(void *ctx, struct e1inp_ts *ts,
		       int priv_nr, const char *addr, uint16_t port,
		       void (*updown_cb)(struct ipa_ssl_client_conn *link, int up),
		       int (*read_cb)(struct ipa_ssl_client_conn *link,
				      struct msgb *msgb),
		       int (*write_cb)(struct ipa_ssl_client_conn *link),
		       void *data)
{
	struct ipa_ssl_client_conn *ipa_ssl_link;

	ipa_ssl_link = talloc_zero(ctx, struct ipa_ssl_client_conn);
	if (!ipa_ssl_link) {
		return NULL;
	}

	if (ts) {
		if (ts->line->driver == NULL) {
			talloc_free(ipa_ssl_link);
			return NULL;
		}
		ipa_ssl_link->ofd = &ts->driver.ipaccess.fd;
	} else {
		ipa_ssl_link->ofd = talloc_zero(ctx, struct osmo_fd);
		if (ipa_ssl_link->ofd == NULL) {
			talloc_free(ipa_ssl_link);
			return NULL;
		}
	}

	ipa_ssl_link->ofd->when |= BSC_FD_READ | BSC_FD_WRITE;
	ipa_ssl_link->ofd->priv_nr = priv_nr;
	ipa_ssl_link->ofd->cb = ipa_ssl_client_fd_cb;
	ipa_ssl_link->ofd->data = ipa_ssl_link;
	ipa_ssl_link->ofd->fd = -1;
	ipa_ssl_link->state = IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTING;
	ipa_ssl_link->addr = talloc_strdup(ipa_ssl_link, addr);
	ipa_ssl_link->port = port;
	ipa_ssl_link->updown_cb = updown_cb;
	ipa_ssl_link->read_cb = read_cb;

	ipa_ssl_link_ssl_init(ipa_ssl_link);

	/* default to generic write callback if not set. */
	if (write_cb == NULL) {
		ipa_ssl_link->write_cb = ipa_ssl_client_write_default_cb;
	} else {
		ipa_ssl_link->write_cb = write_cb;
	}

	if (ts) {
		ipa_ssl_link->line = ts->line;
	}
	ipa_ssl_link->data = data;
	INIT_LLIST_HEAD(&ipa_ssl_link->tx_queue);

	return ipa_ssl_link;
}

void ipa_ssl_client_conn_destroy(struct ipa_ssl_client_conn *link)
{
	talloc_free(link);
}

int ipa_ssl_client_conn_open(struct ipa_ssl_client_conn *link)
{
	int ret;

	link->state = IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTING;

	ret = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
			     link->addr, link->port,
			     OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_NONBLOCK);
	if (ret < 0) {
		return ret;
	}

	link->ofd->fd = ret;
	link->ofd->when |= BSC_FD_WRITE;
	if (osmo_fd_register(link->ofd) < 0) {
		close(ret);
		link->ofd->fd = -1;
		return -EIO;
	}

	return 0;
}

void ipa_ssl_client_conn_send(struct ipa_ssl_client_conn *link, struct msgb *msg)
{
	msgb_enqueue(&link->tx_queue, msg);
	link->ofd->when |= BSC_FD_WRITE;
}

size_t ipa_ssl_client_conn_clear_queue(struct ipa_ssl_client_conn *link)
{
	size_t deleted = 0;

	while (!llist_empty(&link->tx_queue)) {
		struct msgb *msg = msgb_dequeue(&link->tx_queue);
		msgb_free(msg);
		deleted += 1;
	}

	link->ofd->when &= ~BSC_FD_WRITE;
	return deleted;
}



