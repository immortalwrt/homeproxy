/* SPDX-License-Identifier: GPL-3.0-only
 *
 * Copyright (C) 2022 ImmortalWrt.org
 */

'use strict';
'require form';
'require uci';
'require view';
'require tools.homeproxy as hp';

return view.extend({
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

		o = s.option(form.Flag, 'auto_firewall', _('Auto configure firewall'));
		o.default = o.enabled;
		o.rmempty = false;

		s = m.section(form.GridSection, 'server');
		s.addremove = true;
		s.anonymous = true;
		s.nodescriptions = true;
		s.sortable = true;
		s.modaltitle = function(section_id) {
			var label = uci.get(data[0], section_id, 'label');
			return label ? _('Server') + ' » ' + label : _('Add a server');
		}

		o = s.option(form.Value, 'label', _('Label'));
		o.rmempty = false;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.ListValue, 'type', _('Type'));
		o.value('http', _('HTTP'));
		o.value('hysteria', _('Hysteria'));
		o.value('naive', _('NaïveProxy'));
		o.value('shadowsocks', _('Shadowsocks'));
		o.value('socks', _('Socks'));
		o.value('trojan', _('Trojan'));
		o.value('vmess', _('VMess'));
		o.rmempty = false;

		o = s.option(form.Value, 'port', _('Port'),
			_('The port must be unique.'));
		o.datatype = 'port';
		o.rmempty = false;

		o = s.option(form.Value, 'username', _('Username'));
		o.depends('type', 'http');
		o.depends('type', 'naive');
		o.depends('type', 'socks');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'password', _('Password (UUID)'));
		o.validate = function(section_id, value) {
			if (section_id) {
				if (!value)
					return _('Expecting: %s').format(_('non-empty value'));

				var type = this.map.lookupOption('type', section_id)[0].formvalue(section_id);
				if (type === 'shadowsocks') {
					var encmode = this.map.lookupOption('shadowsocks_encrypt_method', section_id)[0].formvalue(section_id);
					if (encmode === '2022-blake3-aes-128-gcm' && value.length !== 16)
						return _('Expecting: %s').format(_('password with %d characters')).format(16);
					else if (['2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].includes(encmode) && value.length !== 32)
						return _('Expecting: %s').format(_('password with %d characters')).format(32);
				} else if (type === 'vmess')
					if (value.match('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') === null)
						return _('Expecting: %s').format(_('valid uuid string'));
			}

			return true;
		}
		o.depends({'type': 'hysteria', '!reverse': true});
		o.modalonly = true;

		/* Hysteria config start */
		o = s.option(form.ListValue, 'hysteria_protocol', _('Protocol'));
		o.value('udp');
		/* WeChat-Video / FakeTCP are unsupported by sing-box currently
		   o.value('wechat-video');
		   o.value('faketcp');
		*/
		o.default = 'udp';
		o.depends('type', 'hysteria');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_downlink_capacity', _('Downlink capacity'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_uplink_capacity', _('Uplink capacity'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.ListValue, 'hysteria_auth_type', _('Authentication type'));
		o.value('disabled', _('Disable'));
		o.value('base64', _('Base64'));
		o.value('string', _('String'));
		o.default = 'disabled';
		o.depends('type', 'hysteria');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_auth_payload', _('Authentication payload'));
		o.depends({'type': 'hysteria', 'hysteria_auth_type': 'base64'});
		o.depends({'type': 'hysteria', 'hysteria_auth_type': 'string'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_obfs_password', _('Obfuscate password'));
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_recv_window_conn', _('QUIC stream receive window'),
			_('The QUIC stream-level flow control window for receiving data.'));
		o.datatype = 'uinteger';
		o.default = '67108864';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_recv_window_client', _('QUIC connection receive window'),
			_('The QUIC connection-level flow control window for receiving data.'));
		o.datatype = 'uinteger';
		o.default = '15728640';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_max_conn_client', _('QUIC maximum concurrent bidirectional streams'),
			_('The maximum number of QUIC concurrent bidirectional streams that a peer is allowed to open.'));
		o.datatype = 'uinteger';
		o.default = '1024';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable Path MTU discovery'),
			_('Disables Path MTU Discovery (RFC 8899). Packets will then be at most 1252 (IPv4) / 1232 (IPv6) bytes in size.'));
		o.default = o.disabled;
		o.depends('type', 'hysteria');
		o.rmempty = false;
		o.modalonly = true;
		/* Hysteria config end */

		/* Shadowsocks config */
		o = s.option(form.ListValue, 'shadowsocks_encrypt_method', _('Encrypt method'));
		for (var i in hp.shadowsocks_encrypt_methods)
			o.value(hp.shadowsocks_encrypt_methods[i]);
		o.default = 'aes-128-gcm';
		o.depends('type', 'shadowsocks');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.modalonly = true;

		/* TLS config start */
		o = s.option(form.Flag, 'tls', _('TLS'));
		o.default = o.disabled;
		o.depends('type', 'http');
		o.depends('type', 'naiveproxy');
		o.depends('type', 'trojan');
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
		for (var i in hp.tls_versions)
			o.value(hp.tls_versions[i])
		o.depends('tls', '1');
		o.modalonly = true;

		o = s.option(form.ListValue, 'tls_max_version', _('Maximum TLS version'),
			_('The maximum TLS version that is acceptable. Default to 1.3.'));
		for (var i in hp.tls_versions)
			o.value(hp.tls_versions[i])
		o.depends('tls', '1');
		o.modalonly = true;

		o = s.option(form.MultiValue, 'tls_cipher_suites', _('Cipher suites'),
			_('The elliptic curves that will be used in an ECDHE handshake, in preference order. If empty, the default will be used.'));
		for (var i in hp.tls_cipher_suites)
			o.value(hp.tls_cipher_suites[i])
		o.depends('tls', '1');
		o.optional = true;
		o.modalonly = true;

		o = s.option(form.Value, 'tls_cert_path', _('Certificate path'),
			_('The server public key, in PEM format.'));
		o.default = '/etc/homeproxy/certs/server_publickey.pem';
		o.depends('tls', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Button, '_upload_cert', _('Upload certificate'),
			_('Your %s will be saved to "/etc/homeproxy/certs/%s.pem".')
			.format(_('certificate'), 'server_publickey') +
			'<br/>' +
			_('<strong>Save your configuration before uploading files!</strong>'));
		o.inputstyle = 'action';
		o.inputtitle = _('Upload...');
		o.depends('tls', '1');
		o.onclick = L.bind(hp.uploadCertificate, this, 'certificate', 'server_publickey');
		o.modalonly = true;

		o = s.option(form.Value, 'tls_key_path', _('Key path'),
			_('The server private key, in PEM format.'));
		o.default = '/etc/homeproxy/certs/server_privatekey.pem';
		o.depends('tls', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Button, '_upload_key', _('Upload key'),
			_('Your %s will be saved to "/etc/homeproxy/certs/%s.pem".')
			.format(_('private'), 'server_privatekey') +
			'<br/>' +
			_('<strong>Save your configuration before uploading files!</strong>'));
		o.inputstyle = 'action';
		o.inputtitle = _('Upload...');
		o.depends('tls', '1');
		o.onclick = L.bind(hp.uploadCertificate, this, 'private key', 'server_privatekey');
		o.modalonly = true;
		/* TLS config end */

		/* Extra settings start */
		o = s.option(form.Flag, 'tcp_fast_open', _('TCP fast open'),
			_('Enable tcp fast open for listener.'));
		o.default = o.disabled;
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'sniff_override', _('Override destination'),
			_('Override the connection destination address with the sniffed domain.'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.ListValue, 'domain_strategy', _('Domain strategy'),
			_('If set, the requested domain name will be resolved to IP before routing.'));
		o.value('', _('Disable'));
		o.value('prefer_ipv4', _('Prefer IPv4'));
		o.value('prefer_ipv6', _('Prefer IPv6'));
		o.value('ipv4_only', _('IPv4 only'));
		o.value('ipv6_only', _('IPv6 only'));
		o.modalonly = true;

		o = s.option(form.ListValue, 'network', _('Network'));
		o.value('tcp', _('TCP'));
		o.value('udp', _('UDP'));
		o.value('', _('Both'));
		o.depends('type', 'naiveproxy');
		o.depends('type', 'shadowsocks');
		o.modalonly = true;
		/* Extra settings end */

		return m.render();
	}
});
