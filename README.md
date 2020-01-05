
SSL implementation of libosmo-abis 
=============================================
This is an pure experimental implementation of Abis protocol over SSL.
Please note, that this implementation could **not** be considered stable
and working production grade software. There is no certificate checking
performed. It has not been tested with any real GSM hardware.

For testing please consider a simplest lab setup of 1 BTS (w/ 1 trx) GSM network.
The building procedure for SSLized version of libosmoabis is almost
the same as for plain version of libosmoabis, but you need to have OpenSSL library
installed and generate keys and certificates.

This could be done on Debian based Linux OS with:

	apt install libssl-dev
	autoreconf -fi
	./configure
	make 
	sudo make install
You also will need server and client keys and certificates.
To generate them you should issue:
```console
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem -out server-cert.pem
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout client-key.pem -out client-cert.pem
```
Create directory /usr/local/etc/osmocom/certs and copy generated files there.
Note: only this filenames, file formats and location are valid, since they are hardcoded in 
library sources.



original README.md below.

libosmo-abis - Osmocom Abis interface library
=============================================

This repository contains a set of C-language libraries that form the
A-bis interface library of [Osmocom](https://osmocom.org/) Open Source
Mobile Communications projects such as OpenBSC / OsmoBSC.

Historically, a lot of this code was developed as part of the
[OpenBSC](https://osmocom.org/projects/openbsc) project, but which are
of a more generic nature and thus useful to (at least) other programs
that we develop in the sphere of Free Software / Open Source mobile
communications.

The libosmo-abis.git repository build multiple libraries:

* **libosmoabis** contains some abstraction layer over E1/T1 and IP
  based ETSI/3GPP A-bis interface. It can use mISDN and DAHDI as
  underlying driver/hardware.
* **libosmotrau** contains routines related to A-bis TRAU frame handling

Homepage
--------

The official homepage of the project is
<https://osmocom.org/projects/libosmo-abis>

GIT Repository
--------------

You can clone from the official libosmo-abis.git repository using

	git clone git://git.osmocom.org/libosmo-abis.git

There is a cgit interface at <http://git.osmocom.org/libosmo-abis/>

Documentation
-------------

There is no Doxygen-generated API documentation yet for this library. It
would be great to some day have it, comparable to libosmocore.

Mailing List
------------

Discussions related to libosmo-abis are happening on the
openbsc@lists.osmocom.org mailing list, please see
<https://lists.osmocom.org/mailman/listinfo/openbsc> for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We us a gerrit based patch submission/review process for managing
contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for
more details

The current patch queue for libosmo-abis can be seen at
<https://gerrit.osmocom.org/#/q/project:libosmo-abis+status:open>
