/* SPDX-License-Identifier: GPL-3.0-only
 *
 * Copyright (C) 2022 ImmortalWrt.org
 */

'use strict';
'require baseclass';
'require fs';
'require uci';
'require ui';

return baseclass.extend({
	shadowsocks_encrypt_methods: [
		/* Stream */
		'none',
		/* AEAD */
		'aes-128-gcm',
		'aes-192-gcm',
		'aes-256-gcm',
		'chacha20-ietf-poly1305',
		'xchacha20-ietf-poly1305',
		/* AEAD 2022 */
		'2022-blake3-aes-128-gcm',
		'2022-blake3-aes-256-gcm',
		'2022-blake3-chacha20-poly1305'
	],

	tls_cipher_suites: [
		'TLS_RSA_WITH_AES_128_CBC_SHA',
		'TLS_RSA_WITH_AES_256_CBC_SHA',
		'TLS_RSA_WITH_AES_128_GCM_SHA256',
		'TLS_RSA_WITH_AES_256_GCM_SHA384',
		'TLS_AES_128_GCM_SHA256',
		'TLS_AES_256_GCM_SHA384',
		'TLS_CHACHA20_POLY1305_SHA256',
		'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
		'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
		'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
		'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
		'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
		'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
		'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
		'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
		'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
		'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
	],

	tls_versions: [
		'1.0',
		'1.1',
		'1.2',
		'1.3'
	],

	decodeBase64Str: function(str) {
		/* Thanks to luci-app-ssr-plus */
		str = str.replace(/-/g, '+').replace(/_/g, '/');
		var padding = (4 - str.length % 4) % 4;
		if (padding)
			str = str + Array(padding + 1).join('=');

		return decodeURIComponent(Array.prototype.map.call(atob(str), function (c) {
			return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
		}).join(''));
	},

	findBinary: function(binray) {
		return fs.exec('/usr/bin/which', [ binray ]).then(function (res) {
			if (res.stdout && res.stdout.trim() !== '')
				return true;
			else
				return false;
		});
	},

	uploadCertificate: function(type, filename, ev) {
		fs.exec('/bin/mkdir', [ '-p', '/etc/homeproxy/certs/' ]);

		return ui.uploadFile(String.format('/etc/homeproxy/certs/%s.pem', filename), ev.target)
		.then(L.bind(function(btn, res) {
			btn.firstChild.data = _('Checking %s...').format(_(type));

			if (res.size <= 0) {
				ui.addNotification(null, E('p', _('The uploaded %s is empty.').format(_(type))));
				return fs.remove(String.format('/etc/homeproxy/certs/%s.pem', filename));
			}

			ui.addNotification(null, E('p', _('Your %s was successfully uploaded. Size: %sB.').format(_(type), res.size)));
		}, this, ev.target))
		.catch(function(e) { ui.addNotification(null, E('p', e.message)) })
		.finally(L.bind(function(btn, input) {
			btn.firstChild.data = _('Upload...');
		}, this, ev.target));
	},

	validateUniqueLabel: function(uciconfig, ucisection, section_id, value) {
		if (section_id) {
			if (value === null || value === '')
				return _('Expecting: %s').format(_('non-empty value'));
			else {
				var duplicate = false;
				uci.sections(uciconfig, ucisection, function(res) {
					if (res['.name'] !== section_id)
						if (res.label === value)
							duplicate = true
				});
				if (duplicate)
					return _('The label was already taken.');
			}
		}
	
		return true;
	}
});
