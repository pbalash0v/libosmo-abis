#pragma once


#define IPA_SSL_PORT_OML	3442
#define IPA_SSL_PORT_RSL	3443

//used by BTS to create one new RSL link per transiever (?)
//called when corresponding command arrives on OML (which one ?)
int e1inp_ipa_ssl_bts_rsl_connect_n(struct e1inp_line *line,
				const char *rem_addr, uint16_t rem_port,
				uint8_t trx_nr);

/* backwards compatibility */
int e1inp_ipa_ssl_bts_rsl_connect(struct e1inp_line *line,
			      const char *rem_addr, uint16_t rem_port);
