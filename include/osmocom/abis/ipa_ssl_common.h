// common functions used by ipa_ssl.c and ipaccess_ssl.c
#pragma once

#include <openssl/err.h>
#include <openssl/ssl.h>

#define IPA_ALLOC_SIZE 1200

#define SSL_SERVER_STR "server"
#define SSL_CLIENT_STR "client"

struct ssl_data {
	SSL*		ssl;
	BIO*		output_bio;
	BIO*		input_bio;
};

//global ssl context
extern SSL_CTX* ssl_ctx;

/*! 
	SSLized version of ipa_msg_recv_buffered from libosmocore
 */
int ipa_ssl_msg_recv_buffered(const struct osmo_fd*, struct msgb**, struct msgb**, SSL*);

void ipa_ssl_global_ssl_init(const char*, SSL_CTX**);
