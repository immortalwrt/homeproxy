/* SPDX-License-Identifier: GPL-3.0-only
 *
 * Copyright (C) 2022 ImmortalWrt.org
 */

'use strict';
'require form';
'require fs';
'require poll';
'require uci';
'require ui';
'require view';

return view.extend({
	cert_upload: function(type, filename, ev) {
		return ui.uploadFile(String.format('/etc/homeproxy/%s.pem.tmp', filename), ev.target)
		.then(L.bind(function(btn, res) {
			btn.firstChild.data = _('Checking %s...').format(_(type));
			return fs.stat(String.format('/etc/homeproxy/%s.pem.tmp', filename));
		}, this, ev.target))
		.then(L.bind(function(btn, res) {
			if (res.size <= 0) {
				ui.addNotification(null, E('p', _('The uploaded %s is empty.').format(_type)));
				return fs.remove(String.format('/etc/homeproxy/%s.pem.tmp', filename));
			}

			fs.exec('/bin/mv', [ String.format('/etc/homeproxy/%s.pem.tmp', filename), String.format('/etc/homeproxy/%s.pem', filename) ]);
			ui.addNotification(null, E('p', _('Your %s was successfully uploaded. Size: %s.').format(_(type), res.size)));
		}, this, ev.target))
		.catch(function(e) { ui.addNotification(null, E('p', e.message)) })
		.finally(L.bind(function(btn, input) {
			btn.firstChild.data = _('Upload...');
		}, this, ev.target));
	},

	load: function() {
		return Promise.all([
			uci.load('homeproxy')
		]);
	},

	render: function(data) {
		var m, s, o;

		m = new form.Map('homeproxy', _('Edit servers'));

		s = m.section(form.NamedSection, 'server', 'homeproxy', _('Global settings'));

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.disabled;
		o.rmempty = false;

		s = m.section(form.GridSection, 'server');
		s.addremove = true;
		s.anonymous = true;
		s.nodescriptions = true;
		s.sortable = true;
		s.modaltitle = function(section_id) {
			var alias = uci.get(data[0], section_id, 'alias');
			return alias ? _('Server') + ' » ' + alias : _('Add a server');
		}

		o = s.option(form.Value, 'alias', _('Alias'));
		o.rmempty = false;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.ListValue, 'type', _('Type'));
		o.value('http', _('HTTP'));
		o.value('shadowsocks', _('Shadowsocks'));
		o.value('socks', _('Socks'));
		o.value('vmess', _('VMess'));
		o.rmempty = false;

		o = s.option(form.Value, 'port', _('Port'),
			_('The port must be unique.'));
		o.datatype = 'port';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'username_password', _('Username / Password (UUID)'),
			_('Format as user:pass(uuid).'));
		o.validate = function(section_id, value) {
			if (section_id) {
				if (this.formvalue(section_id).length === 0)
					return _('Expecting: non-empty value');
				else if (!value)
					return true;

				var user = value.split(':')[0], pass = value.split(':')[1];
				if (value.split(':').length > 2 || !user || !pass)
					return _('Expecting: %s').format(_('valid user:pass(uuid) pair'));

				var type = this.map.lookupOption('type', section_id)[0].formvalue(section_id);
				if (type === 'shadowsocks') {
					var encmode = this.map.lookupOption('shadowsocks_encrypt_method', section_id)[0].formvalue(section_id);
					if (encmode === '2022-blake3-aes-128-gcm' && pass.length !== 16)
						return _('Expecting: %s').format(_('password with %d characters')).format(16);
					else if (['2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].includes(encmode) && pass.length !== 32)
						return _('Expecting: %s').format(_('password with %d characters')).format(32);
				} else if (type === 'vmess')
					if (pass.match('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') === null)
						return _('Expecting: %s').format(_('valid uuid string'));
			}

			return true;
		}
		o.modalonly = true;

		o = s.option(form.ListValue, 'shadowsocks_encrypt_method', _('Encrypt method'));
		o.value('none');
		o.value('aes-128-gcm');
		o.value('aes-192-gcm');
		o.value('aes-256-gcm');
		o.value('chacha20-ietf-poly1305');
		o.value('xchacha20-ietf-poly1305');
		o.value('2022-blake3-aes-128-gcm');
		o.value('2022-blake3-aes-256-gcm');
		o.value('2022-blake3-chacha20-poly1305');
		o.default = 'aes-128-gcm';
		o.depends('type', 'shadowsocks');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.modalonly = true;

		o = s.option(form.Flag, 'tls', _('TLS'));
		o.default = o.disabled;
		o.depends('type', 'http');
		o.depends('type', 'vmess');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'tls_sni', _('TLS SNI'),
			_('Used to verify the hostname on the returned certificates unless insecure is given.'));
		o.depends('tls', '1');
		o.modalonly = true;

		o = s.option(form.DynamicList, 'tls_alpn', _('TLS ALPN'),
			_('List of supported application level protocols, in order of preference.'));
		o.depends('tls', '1');
		o.modalonly = true;

		o = s.option(form.ListValue, 'tls_min_version', _('Minimum TLS version'),
			_('The minimum TLS version that is acceptable. Default to 1.0.'));
		o.value('1.0');
		o.value('1.1');
		o.value('1.2');
		o.value('1.3');
		o.default = '1.0';
		o.depends('tls', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.ListValue, 'tls_max_version', _('Maximum TLS version'),
			_('The maximum TLS version that is acceptable. Default to 1.3.'));
		o.value('1.0');
		o.value('1.1');
		o.value('1.2');
		o.value('1.3');
		o.default = '1.3';
		o.depends('tls', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.MultiValue, 'tls_cipher_suites', _('Cipher suites'),
			_('The elliptic curves that will be used in an ECDHE handshake, in preference order. If empty, the default will be used.'));
		o.value('TLS_RSA_WITH_AES_128_CBC_SHA');
		o.value('TLS_RSA_WITH_AES_256_CBC_SHA');
		o.value('TLS_RSA_WITH_AES_128_GCM_SHA256');
		o.value('TLS_RSA_WITH_AES_256_GCM_SHA384');
		o.value('TLS_AES_128_GCM_SHA256');
		o.value('TLS_AES_256_GCM_SHA384');
		o.value('TLS_CHACHA20_POLY1305_SHA256');
		o.value('TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA');
		o.value('TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA');
		o.value('TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA');
		o.value('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA');
		o.value('TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256');
		o.value('TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384');
		o.value('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256');
		o.value('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384');
		o.value('TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256');
		o.value('TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256');
		o.depends('tls', '1');
		o.optional = true;
		o.modalonly = true;

		o = s.option(form.Value, 'tls_cert_path', _('Certificate path'),
			_('The server public key, in PEM format.'));
		o.default = '/etc/homeproxy/server_publickey.pem';
		o.depends('tls', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Button, '_upload_cert', _('Upload certificate'),
			_('Your %s will be saved to "/etc/homeproxy/%s.pem".<br />' +
			'<strong>Save your configuration before uploading files!</strong>')
			.format(_('certificate'), 'server_publickey'));
		o.inputstyle = 'action';
		o.inputtitle = _('Upload...');
		o.depends('tls', '1');
		o.onclick = L.bind(this.cert_upload, this, 'certificate', 'server_publickey');
		o.modalonly = true;

		o = s.option(form.Value, 'tls_key_path', _('Key path'),
			_('The server private key, in PEM format.'));
		o.default = '/etc/homeproxy/server_privatekey.pem';
		o.depends('tls', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Button, '_upload_key', _('Upload key'),
			_('Your %s will be saved to "/etc/homeproxy/%s.pem".<br />' +
			'<strong>Save your configuration before uploading files!</strong>')
			.format(_('private key'), 'server_privatekey'));
		o.inputstyle = 'action';
		o.inputtitle = _('Upload...');
		o.depends('tls', '1');
		o.onclick = L.bind(this.cert_upload, this, 'private key', 'server_privatekey');
		o.modalonly = true;

		o = s.option(form.Flag, 'tcp_fast_open', _('TCP fast open'),
			_('Enable tcp fast open for listener.'));
		o.default = o.disabled;
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'sniff', _('Enable sniffing'),
			_('See <a target="_blank" href="https://sing-box.sagernet.org/configuration/route/sniff/">Sniff</a> for details.'));
		o.default = o.enabled;
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'sniff_override', _('Override destination'),
			_('Override the connection destination address with the sniffed domain.'));
		o.default = o.enabled;
		o.depends('sniff', '1');
		o.rmempty = false;

		o = s.option(form.ListValue, 'domain_strategy', _('Domain strategy'),
			_('If set, the requested domain name will be resolved to IP before routing.'));
		o.value('', _('Disable'));
		o.value('prefer_ipv4', _('Prefer IPv4'));
		o.value('prefer_ipv6', _('Prefer IPv6'));
		o.value('ipv4_only', _('IPv4 only'));
		o.value('ipv6_only', _('IPv6 only'));
		o.depends('type', 'http');
		o.depends('type', 'shadowsocks');
		o.depends('type', 'socks');
		o.depends('type', 'vmess');
		o.modalonly = true;

		o = s.option(form.ListValue, 'network', _('Network'));
		o.value('tcp', _('TCP'));
		o.value('udp', _('UDP'));
		o.value('both', _('Both'));
		o.default = 'both';
		o.depends('type', 'shadowsocks');
		o.modalonly = true;

		return m.render();
	}
});
