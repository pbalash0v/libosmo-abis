#include <osmocom/core/socket.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/core/byteswap.h>

#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/core/logging.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <osmocom/abis/ipa_ssl_common.h>


SSL_CTX*	ssl_ctx;


int ipa_ssl_msg_recv_buffered(const struct osmo_fd* ofd, struct msgb **rmsg, struct msgb **tmp_msg,
													SSL* ssl)
{
	struct msgb *msg = tmp_msg ? *tmp_msg : NULL;
	struct ipaccess_head *hh;
	int len, ret;
	int needed;

	//first time iteration
	if (msg == NULL) {
		msg = ipa_msg_alloc(0);
		if (msg == NULL) {
			ret = -ENOMEM;
			goto discard_msg;
		}
		msg->l1h = msg->tail;
	}

	if (msg->l2h == NULL) {
		/* first read our 3-byte header */
		needed = sizeof(*hh) - msg->len;
		ret = SSL_read(ssl, msg->tail, needed);
		if (SSL_ERROR_WANT_READ == SSL_get_error(ssl, ret)) {
			return -EAGAIN;
		} else if (SSL_ERROR_NONE != SSL_get_error(ssl, ret)) {
			OSMO_ASSERT(false);
		}

		if (ret == 0)
		       goto discard_msg;

		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR)
				ret = 0;
			else {
				ret = -errno;
				goto discard_msg;
			}
		}

		msgb_put(msg, ret);

		if (ret < needed) {
			if (msg->len == 0) {
				ret = -EAGAIN;
				goto discard_msg;
			}

			LOGP(DLINP, LOGL_INFO,
			     "Received part of IPA message header (%d/%zu)\n",
			     msg->len, sizeof(*hh));
			if (!tmp_msg) {
				ret = -EIO;
				goto discard_msg;
			}
			*tmp_msg = msg;
			return -EAGAIN;
		}

		msg->l2h = msg->tail;
	}

	hh = (struct ipaccess_head *) msg->data;

	/* then read the length as specified in header */
	len = osmo_ntohs(hh->len);

	if (len < 0 || IPA_ALLOC_SIZE < len + sizeof(*hh)) {
		LOGP(DLINP, LOGL_ERROR, "bad message length of %d bytes, "
					"received %d bytes\n", len, msg->len);
		ret = -EIO;
		goto discard_msg;
	}

	needed = len - msgb_l2len(msg);

	if (needed > 0) {
		ret = SSL_read(ssl, msg->tail, needed);
		if (SSL_ERROR_WANT_READ == SSL_get_error(ssl, ret)) {
			return -EAGAIN;
		} else if (SSL_ERROR_NONE != SSL_get_error(ssl, ret)) {
			OSMO_ASSERT(false);
		}

		if (ret == 0)
			goto discard_msg;

		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR)
				ret = 0;
			else {
				ret = -errno;
				goto discard_msg;
			}
		}

		msgb_put(msg, ret);

		if (ret < needed) {
			LOGP(DLINP, LOGL_INFO,
			     "Received part of IPA message L2 data (%d/%d)\n",
			    msgb_l2len(msg), len);
			if (!tmp_msg) {
				ret = -EIO;
				goto discard_msg;
			}
			*tmp_msg = msg;
			return -EAGAIN;
		}
	}

	ret = msgb_l2len(msg);

	if (ret == 0) {
		LOGP(DLINP, LOGL_INFO,
		     "Discarding IPA message without payload\n");
		ret = -EAGAIN;
		goto discard_msg;
	}

	if (tmp_msg)
		*tmp_msg = NULL;
	*rmsg = msg;
	return ret;

discard_msg:
	if (tmp_msg)
		*tmp_msg = NULL;
	msgb_free(msg);
	return ret;
}


static int ssl_verify_peer(int ok __attribute__((unused)),
								 X509_STORE_CTX* ctx __attribute__((unused)))
{
  return 1;
}

void ipa_ssl_global_ssl_init(const char* type, SSL_CTX** ctx)
{
	OSMO_ASSERT(!(*ctx));
	OSMO_ASSERT(!strcmp(type, SSL_SERVER_STR) || !strcmp(type, SSL_CLIENT_STR));
	
	bool is_server = !strcmp(type, SSL_SERVER_STR);
	char* peer_type = is_server ? SSL_SERVER_STR : SSL_CLIENT_STR;

	char* path = "/usr/local/etc/osmocom/certs";

	LOGP(DLINP, LOGL_NOTICE, "Initialising SSL. Type: %s\n", type);

	/* SSL library initialisation */
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* create the SSL server context */
	SSL_CTX* _ctx = SSL_CTX_new(is_server ? 
							TLS_server_method() : TLS_client_method());
	OSMO_ASSERT(_ctx);
	*ctx = _ctx;

	/* the client doesn't have to send it's certificate */
	SSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, ssl_verify_peer);

	/* Load certificate and private key files, and check consistency */
	char certfile[1024] = {0};
	char keyfile[1024] = {0};
	snprintf(certfile, sizeof certfile, "%s/%s-cert.pem", path, peer_type);
	snprintf(keyfile, sizeof keyfile, "%s/%s-key.pem", path, peer_type);

	LOGP(DLINP, LOGL_NOTICE, "Using certfile: %s\n", certfile);
	LOGP(DLINP, LOGL_NOTICE, "Using keyfile: %s\n", keyfile);

	if (SSL_CTX_use_certificate_file(_ctx, certfile,  SSL_FILETYPE_PEM) != 1) {
		LOGP(DLINP, LOGL_FATAL, "SSL_CTX_use_certificate_file failed\n");
		OSMO_ASSERT(false);
	}

	if (SSL_CTX_use_PrivateKey_file(_ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
		LOGP(DLINP, LOGL_FATAL, "SSL_CTX_use_PrivateKey_file failed\n");
		OSMO_ASSERT(false);
	}

	/* Make sure the key and certificate file match. */
	if (SSL_CTX_check_private_key(_ctx) != 1) {
		LOGP(DLINP, LOGL_FATAL, "SSL_CTX_check_private_key failed\n");
		OSMO_ASSERT(false);
	} else 
		LOGP(DLINP, LOGL_NOTICE, "certificate and private key loaded and verified\n");

	/* Recommended to avoid SSLv2 & SSLv3 */
	SSL_CTX_set_options(_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);

	#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"

	//for debug in wireshark, can import key and decrypt if using only RSA
	//#define CIPHER_LIST "RSA"

	if (SSL_CTX_set_cipher_list(_ctx, CIPHER_LIST) != 1) {
		LOGP(DLINP, LOGL_FATAL, "Error setting cipher list (no valid ciphers)\n");
		OSMO_ASSERT(false);
	}
}


/*static char* get_ssl_str_error(const SSL* ssl, int res) {
	char* ret = "UNKNOWN ERR";

    switch (SSL_get_error(ssl, res)) {
		case SSL_ERROR_NONE:
			ret = "SSL_ERROR_NONE";
			break;
		case SSL_ERROR_WANT_READ:
			ret = "SSL_ERROR_WANT_READ";
			break;
		case SSL_ERROR_WANT_WRITE:
			ret = "SSL_ERROR_WANT_WRITE";
			break;
		case SSL_ERROR_ZERO_RETURN:
			ret = "SSL_ERROR_ZERO_RETURN";
			break;
		case SSL_ERROR_SYSCALL:
			ret = "SSL_ERROR_SYSCALL";
			break;
		case SSL_ERROR_SSL:
			ret = "SSL_ERROR_SSL";
			break;
		default:
			break;
    }

    return ret;
}
*/