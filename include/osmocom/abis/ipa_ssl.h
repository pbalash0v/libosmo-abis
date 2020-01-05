#pragma once


#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/ipa.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define IPA_SSL_PORT_OML	3442
#define IPA_SSL_PORT_RSL	3443

struct e1inp_line;
struct e1inp_ts;
struct msgb;
/**/

enum ipa_ssl_client_conn_state {
	IPA_SSL_CLIENT_LINK_STATE_NONE								= 0,
	IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTING					= 1,
	IPA_SSL_CLIENT_LINK_STATE_TCP_CONNECTED					= 2,
	IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING					= 3,
	IPA_SSL_CLIENT_LINK_STATE_SSL_HANDSHAKING_NEED_RECV 	= 4,
	IPA_SSL_CLIENT_LINK_STATE_SSL_CONNECTED					= 5,
	IPA_SSL_CLIENT_LINK_STATE_ESTABLISHED						= 6,
	IPA_SSL_CLIENT_LINK_STATE_MAX
};

struct ipa_ssl_client_conn {
	struct e1inp_line		*line;
	struct osmo_fd			*ofd;

	SSL_CTX	*ctx;	
	SSL		*ssl;
	BIO		*output_bio;
	BIO		*input_bio;

	struct llist_head		tx_queue;
	struct osmo_timer_list		timer;
	enum ipa_ssl_client_conn_state	state;
	const char			*addr;
	uint16_t			port;
	void (*updown_cb)(struct ipa_ssl_client_conn *link, int up);
	/* Callback when ofd has something to be read. -EBADF must be returned if the osmo_fd is destroyed. */
	int (*read_cb)(struct ipa_ssl_client_conn *link, struct msgb *msg);
	int (*write_cb)(struct ipa_ssl_client_conn *link);
	void				*data;
	struct msgb			*pending_msg;
};

struct ipa_ssl_client_conn *
ipa_ssl_client_conn_create(void *ctx, struct e1inp_ts *ts, int priv_nr,
			const char *addr, uint16_t port,
			void (*updown)(struct ipa_ssl_client_conn *link, int),
			int (*read_cb)(struct ipa_ssl_client_conn *link, struct msgb *msgb),
			int (*write_cb)(struct ipa_ssl_client_conn *link),
			void *data);
void ipa_ssl_client_conn_destroy(struct ipa_ssl_client_conn *link);

int ipa_ssl_client_conn_open(struct ipa_ssl_client_conn *link);
void ipa_ssl_client_conn_close(struct ipa_ssl_client_conn *link);

void ipa_ssl_client_conn_send(struct ipa_ssl_client_conn *link, struct msgb *msg);
size_t ipa_ssl_client_conn_clear_queue(struct ipa_ssl_client_conn *link);
