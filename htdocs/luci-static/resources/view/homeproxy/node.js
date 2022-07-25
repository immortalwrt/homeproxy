/* SPDX-License-Identifier: GPL-3.0-only
 *
 * Copyright (C) 2022 ImmortalWrt.org
 */

'use strict';
'require view';
'require poll';
'require uci';
'require rpc';
'require form';
'require fs';

function fs_installed(binray) {
	return fs.exec('/bin/ash', ['-c', 'type -t -p ' + binray]).then(function (res) {
		if (res.stdout && res.stdout.trim() !== '')
			return true;
		else
			return false;
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy'),
			fs_installed('hysteria'),
			fs_installed('naive'),
			fs_installed('ssr-local')
		]);
	},

	render: function(data) {
		var m, s, o;

		var have_hysteria = data[1];
		var have_naiveproxy = data[2];
		var have_shadowsocksr = data[3];

		m = new form.Map('homeproxy', _('Edit nodes'));

		s = m.section(form.NamedSection, 'subscription', 'homeproxy');

		o = s.option(form.Flag, 'auto_update', _('Auto update'),
			_('Auto update subscriptions, geoip and geosite.'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.ListValue, 'auto_update_time', 'Update time');
		for (var i = 0; i < 24; i++)
			o.value(i, i + ':00');
		o.default = '2';
		o.depends('auto_update', '1');

		o = s.option(form.Flag, 'update_via_proxy', _('Update via proxy'),
			_('Update subscriptions via proxy.'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.DynamicList, 'subscribe_url', _('Subscription URL'),
			_('Support Shadowsocks(R), Trojan(-Go), and V2RayN(G) online configuration delivery standard.'));

		o = s.option(form.ListValue, 'filter_nodes', _('Filter nodes'),
			_('Drop/keep specific node(s) from subscriptions.'));
		o.value('0', _('Disabled'));
		o.value('1', _('Blacklist mode'));
		o.value('2', _('Whitelist mode'));
		o.default = '0';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'filter_words', _('Filter keyword'),
			_('Drop/keep node(s) that contain the specific keyword.'));
		o.depends({'filter_nodes': '0', '!reverse': true});

		s = m.section(form.GridSection, 'node');
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		s.modaltitle = function(section_id) {
			var alias = uci.get(data[0], section_id, 'alias') || uci.get(data[0], section_id, 'address');
			return alias ? _('Node') + ' » ' + alias : _('Add a node');
		}

		o = s.option(form.Value, 'alias', _('Alias'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'type', _('Type'));
		o.value('http', _('HTTP'));
		if (have_hysteria)
			o.value('hysteria', _('Hysteria'));
		if (have_naiveproxy)
			o.value('naiveproxy', _('NaïveProxy'));
		o.value('shadowsocks', _('Shadowsocks'));
		if (have_shadowsocksr)
			o.value('shadowsocksr', _('ShadowsocksR'));
		o.value('socks', _('Socks'));
		o.value('v2ray', _('V2ray'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'v2ray_protocol', _('V2ray protocol'));
		o.value('http', _('HTTP'));
		o.value('shadowsocks', _('Shadowsocks'));
		o.value('shadowsocksr', _('ShadowsocksR'));
		o.value('socks', _('Socks'));
		o.value('trojan', _('Trojan'));
		o.value('vless', _('VLESS'));
		o.value('vmess', _('VMess'));
		o.value('wireguard', _('WireGuard'));
		o.depends('type', 'v2ray');
		o.modalonly = true;

		o = s.option(form.Value, 'address', _('Address'));
		o.datatype = 'host';
		o.rmempty = false;

		o = s.option(form.Value, 'port', _('Port'));
		o.datatype = 'port';
		o.rmempty = false;

		o = s.option(form.Value, 'username', _('Username'));
		o.depends('type', 'http');
		o.depends('type', 'naiveproxy');
		o.depends('type', 'socks');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'http'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'socks'});
		o.modalonly = true;

		o = s.option(form.Value, 'password', _('Password'));
		o.depends('type', 'http');
		o.depends('type', 'naiveproxy');
		o.depends('type', 'shadowsocks');
		o.depends('type', 'shadowsocksr');
		o.depends({'type': 'socks', 'socks_ver': '5'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'http'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.depends({'type': 'v2ray', 'v2ray_protoocl': 'shadowsocksr'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'socks', 'socks_ver': '5'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'trojan'});
		o.modalonly = true;

		/* NaïveProxy config start */
		o = s.option(form.ListValue, 'naiveproxy_network'), _('Network mode');
		o.value('h2', _('HTTP/2'));
		o.value('quic', _('QUIC'));
		o.depends('type', 'naiveproxy');
		o.modalonly = true;

		o = s.option(form.Value, 'naiveproxy_concurrency', _('Concurrency'));
		o.datatype = 'uinteger';
		o.depends('type', 'naiveproxy');
		o.modalonly = true;
		/* NaïveProxy config end */

		/* Hysteria config start */
		o = s.option(form.ListValue, 'hysteria_protocol', _('Protocol'));
		o.value('udp');
		o.value('wechat-video');
		o.value('faketcp');
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.ListValue, 'hysteria_auth_type', _('Authentication type'));
		o.value('0', _('disabled'));
		o.value('1', _('base64'));
		o.value('2', _('string'));
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_auth_payload', _('Authentication payload'));
		o.depends({'type': 'hysteria', 'auth_type': '1'});
		o.depends({'type': 'hysteria', 'auth_type': '2'});
		o.validate = function(section_id, value) {
			if (section_id && (value == null || value == ''))
				return _('Expecting: non-empty value');

			return true;
		}
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_password', _('Obfuscate password'));
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_revc_window', _('QUIC connection receive window'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_recv_window_conn', _('QUIC stream receive window'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Value, 'hysteria_quic_alpn', _('QUIC TLS ALPN'));
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable Path MTU discovery'));
		o.default = o.disabled;
		o.depends('type', 'hysteria');
		o.modalonly = true;
		/* Hysteria config end */

		/* Shadowsocks config start */
		o = s.option(form.ListValue, 'shadowsocks_encrypt_method', _('Encrypt method'));
		o.value('none');
		o.value('plain');
		o.value('aes-128-gcm');
		o.value('aes-192-gcm');
		o.value('aes-256-gcm');
		o.value('chacha20-ietf-poly1305');
		o.value('xchacha20-ietf-poly1305');
		o.value('2022-blake3-aes-128-gcm');
		o.value('2022-blake3-aes-256-gcm');
		o.value('2022-blake3-chacha20-poly1305');
		o.depends('type', 'shadowsocks');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.modalonly = true;

		o = s.option(form.Flag, 'shadowsocks_tfo', _('TCP fast open'));
		o.default = o.disabled;
		o.depends('type', 'shadowsocks');
		o.depends('type', 'shadowsocksr');
		o.modalonly = true;

		o = s.option(form.Flag, 'shadowsocks_uot', _('UDP over TCP'),
			_('Enable the SUoT protocol, requires server support.'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.modalonly = true;

		o = s.option(form.Flag, 'shadowsocks_ivcheck', _('Bloom filter'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocks_plugin', _('Plugin'));
		o.value('obfs-local');
		o.value('v2ray-plugin');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocks_plugin_opts', _('Plugin opts'));
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.modalonly = true;
		/* Shadowsocks config end */

		/* ShadowsocksR config start */
		o = s.option(form.ListValue, 'shadowsocksr_encrypt_method', _('Encrypt method'));
		o.value('none');
		o.value('table');
		o.value('rc4');
		o.value('rc4-md5-6');
		o.value('rc4-md5');
		o.value('aes-128-cfb');
		o.value('aes-192-cfb');
		o.value('aes-256-cfb');
		o.value('aes-128-ctr');
		o.value('aes-192-ctr');
		o.value('aes-256-ctr');
		o.value('bf-cfb');
		o.value('camellia-128-cfb');
		o.value('camellia-192-cfb');
		o.value('camellia-256-cfb');
		o.value('cast5-cfb');
		o.value('des-cfb');
		o.value('idea-cfb');
		o.value('rc2-cfb');
		o.value('seed-cfb');
		o.value('salsa20');
		o.value('chacha20');
		o.value('chacha20-ietf');
		o.depends('type', 'shadowsocksr');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.modalonly = true;

		o = s.option(form.ListValue, 'shadowsocksr_protocol', _('Protocol'));
		o.value('origin');
		o.value('verify_deflate');
		o.value('auth_sha1_v4');
		o.value('auth_aes128_sha1');
		o.value('auth_aes128_md5');
		o.value('auth_chain_a');
		o.value('auth_chain_b');
		o.value('auth_chain_c');
		o.value('auth_chain_d');
		o.value('auth_chain_e');
		o.value('auth_chain_f');
		o.depends('type', 'shadowsocksr');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocskr_protocol_param', _('Protocol param'));
		o.depends('type', 'shadowsocksr');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.modalonly = true;

		o = s.option(form.ListValue, 'shadowsocksr_obfs', _('Obfs'));
		o.value('plain');
		o.value('http_simple');
		o.value('http_post');
		o.value('random_head');
		o.value('tls1.2_ticket_auth');
		o.depends('type', 'shadowsocksr');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocksr_obfs_param', _('Obfs param'));
		o.depends('type', 'shadowsocksr');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.modalonly = true;
		/* ShadowsocksR config end */

		/* Socks config start */
		o = s.option(form.ListValue, 'socks_ver', _('Socks version'));
		o.value('4', _('Socks4'));
		o.value('4a', _('Socks4A'));
		o.value('5', _('Socks5'));
		o.depends('type', 'socks');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'socks'});
		o.modalonly = true;
		/* Socks config end */

		/* V2ray config start */
		o = s.option(form.Value, 'v2ray_uuid', _('UUID'));
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vmess'});
		o.validate = function(section_id, value) {
			if (section_id && (value == null || value == ''))
				return _('Expecting: non-empty value');
			else if (value.match('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') === null)
				return String.format(_('Expecting: %s'), _('valid uuid string'));

			return true;
		}
		o.modalonly = true;

		o = s.option(form.Value, 'v2ray_vless_encrypt', _('Encrypt method'));
		o.default = 'none';
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless'});
		o.validate = function(section_id, value) {
			if (section_id && (value == null || value == ''))
				return _('Expecting: non-empty value');

			return true;
		}
		o.modalonly = true;

		o = s.option(form.ListValue, 'v2ray_vmess_encrypt', _('Encrypt method'));
		o.value('auto');
		o.value('none');
		o.value('zero');
		o.value('aes-128-gcm');
		o.value('chacha20-poly1305');
		o.default = 'aes-128-gcm';
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vmess'});
		o.modalonly = true;

		/* Wireguard config start */
		o = s.option(form.DynamicList, 'wireguard_local_addresses', _('Local addresses'));
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'wireguard'});
		o.validate = function(section_id, value) {
			if (section_id && value == null || value == [])
				return _('Expecting: non-empty value');
		}
		o.modalonly = true;

		o = s.option(form.Value, 'wireguard_private_key', _('Private key'));
		o.password = true;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'wireguard'});
		o.validate = function(section_id, value) {
			if (section_id && value == null || value == '')
				return _('Expecting: non-empty value');
		}
		o.modalonly = true;

		o = s.option(form.Value, 'wireguard_peer_pubkey', _('Peer pubkic key'));
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'wireguard'});
		o.validate = function(section_id, value) {
			if (section_id && value == null || value == '')
				return _('Expecting: non-empty value');
		}
		o.modalonly = true;

		o = s.option(form.Value, 'wireguard_preshared_key', _('Pre-shared key'));
		o.password = true;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'wireguard'});
		o.validate = function(section_id, value) {
			if (section_id && value == null || value == '')
				return _('Expecting: non-empty value');
		}
		o.modalonly = true;
		/* Wireguard config end */

		o = s.option(form.ListValue, 'v2ray_transport', _('Transport'));
		o.value('grpc', _('gRPC'));
		o.value('h2', _('HTTP/2'));
		o.value('mkcp', _('mKCP'));
		o.value('quic', _('QUIC'));
		o.value('tcp', _('TCP'));
		o.value('websocket', _('WebSocket'));
		o.default = 'tcp';
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'http'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'socks'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'trojan'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vmess'});
		o.modalonly = true;

		/* gRPC/H2 config start */
		o = s.option(form.Value, 'grpc_servicename', _('gRPC service name'));
		o.depends({'type': 'v2ray', 'v2ray_transport': 'grpc'});
		o.modalonly = true;

		o = s.option(form.ListValue, 'grpc_mode', _('gRPC mode'));
		o.value('gun');
		o.value('multi');
		o.value('raw');
		o.depends({'type': 'v2ray', 'v2ray_transport': 'grpc'});
		o.modalonly = true;

		o = s.option(form.Value, 'h2_host', _('Host'));
		o.depends({'type': 'v2ray', 'v2ray_transport': 'h2'});
		o.depends({'type': 'v2ray', 'v2ray_transport': 'websocket'});
		o.modalonly = true;

		o = s.option(form.Value, 'h2_path', _('Path'));
		o.depends({'type': 'v2ray', 'v2ray_transport': 'h2'});
		o.depends({'type': 'v2ray', 'v2ray_transport': 'websocket'});
		o.modalonly = true;

		o = s.option(form.Flag, 'h2_health_check', _('Health check'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_transport': 'grpc'});
		o.depends({'type': 'v2ray', 'v2ray_transport': 'h2'});
		o.modalonly = true;

		o = s.option(form.Flag, 'h2_health_check_timeout', _('Health check timeout'));
		o.datatype = 'uintger';
		o.default = '20';
		o.depends('h2_health_check', '1');
		o.modalonly = true;

		o = s.option(form.Value, 'h2_idle_timeout', _('Idle timeout'));
		o.datatype = 'uinteger';
		o.default = '60';
		o.depends({'type': 'v2ray', 'v2ray_transport': 'grpc'});
		o.depends({'type': 'v2ray', 'v2ray_transport': 'h2'});
		o.modalonly = true;

		o = s.option(form.Flag, 'grpc_permit_without_stream', _('Permit Without Stream'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_transport': 'grpc'});
		o.modalonly = true;

		o = s.option(form.Flag, 'h2_health_check', _('Health check'));
		o.depends({'type': 'v2ray', 'v2ray_transport': 'grpc'});
		o.depends({'type': 'v2ray', 'v2ray_transport': 'h2'});
		o.modalonly = true;
		/* gRPC/H2 config end */

		/* mKCP config start */
		o = s.option(form.Value, 'mkcp_seed', _('mKCP seed'));
		o.depends({'type': 'v2ray', 'v2ray_transport': 'mkcp'});
		o.modalonly = true;

		o = s.option(form.Flag, 'mkcp_congestion', _('Congestion'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_transport': 'mkcp'});
		o.modalonly = true;

		o = s.option(form.ListValue, 'mkcp_header', _('Header type'));
		o.value('none', _('None'));
		o.value('dtls', _('DTLS 1.2'));
		o.value('srtp', _('Video call (SRTP)'));
		o.value('utp', _('BitTorrent (utp)'));
		o.value('wechat-video', _('Wechat video call'));
		o.value('wireguard', _('WireGuard'));
		o.depends({'type': 'v2ray', 'v2ray_transport': 'mkcp'});
		o.depends({'type': 'v2ray', 'v2ray_transport': 'quic'});
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_downlink_capacity', _('Downlink capacity'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.depends({'type': 'v2ray', 'v2ray_transport': 'mkcp'});
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_uplink_capacity', _('Uplink capacity'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.depends({'type': 'v2ray', 'v2ray_transport': 'mkcp'});
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_read_buffer_size', _('Read buffer size'));
		o.datatype = 'uinteger';
		o.depends({'type': 'v2ray', 'v2ray_transport': 'mkcp'});
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_write_buffer_size', _('Write buffer size'));
		o.datatype = 'uinteger';
		o.depends({'type': 'v2ray', 'v2ray_transport': 'mkcp'});
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_mtu', _('MTU'));
		o.datatype = 'range(0,9000)';
		o.depends({'type': 'v2ray', 'v2ray_transport': 'mkcp'});
		o.depends({'type': 'v2ray', 'v2ray_transport': 'wireguard'});
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_tti', _('TTI'));
		o.datatype = 'uinteger';
		o.depends({'type': 'v2ray', 'v2ray_transport': 'mkcp'});
		o.modalonly = true;
		/* mKCP config end */

		/* QUIC config start */
		o = s.option(form.ListValue, 'quic_security', _('QUIC security'));
		o.value('none');
		o.value('aes-128-gcm');
		o.value('chacha20-poly1305');
		o.depends({'type': 'v2ray', 'v2ray_transport': 'quic'});
		o.modalonly = true;

		o = s.option(form.Value, 'quic_key', _('QUIC key'));
		o.password = true;
		o.depends({'type': 'v2ray', 'v2ray_transport': 'quic'});
		o.modalonly = true;
		/* QUIC config end */

		/* TCP config start */
		o = s.option(form.ListValue, 'tcp_header', _('Header type'));
		o.value('none');
		o.value('http');
		o.depends({'type': 'v2ray', 'v2ray_transport': 'tcp'});
		o.modalonly = true;

		o = s.option(form.DynamicList, 'tcp_host', _('Host'));
		o.depends({'type': 'v2ray', 'v2ray_transport': 'tcp', 'tcp_header': 'http'});
		o.modalonly = true;

		o = s.option(form.Value, 'tcp_path', _('Path'));
		o.depends({'type': 'v2ray', 'v2ray_transport': 'tcp', 'tcp_header': 'http'});
		o.modalonly = true;
		/* TCP config end */

		/* WebSocket config start */
		o = s.option(form.Value, 'websocket_early_data', _('Early data'));
		o.datatype = 'uinteger';
		o.default = '2048';
		o.depends({'type': 'v2ray', 'v2ray_transport': 'websocket'});
		o.modalonly = true;

		o = s.option(form.Value, 'websocket_early_data_header', _('Early data header name'));
		o.default = 'Sec-WebSocket-Protocol';
		o.depends({'type': 'v2ray', 'v2ray_transport': 'websocket'});
		o.modalonly = true;
		/* WebSocket config end */

		/* Mux */
		o = s.option(form.Flag, 'v2ray_mux', _('Mux'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'http'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'socks'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'trojan'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vmess'});
		o.modalonly = true;

		/* XTLS config start */
		o = s.option(form.Flag, 'v2ray_xtls', _('XTLS'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'trojan', 'v2ray_transport': 'tcp', 'v2ray_mux': '0', 'tls': '0'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'trojan', 'v2ray_transport': 'mkcp', 'v2ray_mux': '0', 'tls': '0'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless', 'v2ray_transport': 'tcp', 'v2ray_mux': '0', 'tls': '0'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless', 'v2ray_transport': 'mkcp', 'v2ray_mux': '0', 'tls': '0'});
		o.modalonly = true;

		o = s.option(form.ListValue, 'v2ray_xtls_flow', _('Flow'));
		o.value('xtls-rprx-origin');
		o.value('xtls-rprx-origin-udp443');
		o.value('xtls-rprx-direct');
		o.value('xtls-rprx-direct-udp443');
		o.value('xtls-rprx-splice');
		o.value('xtls-rprx-splice-udp443');
		o.default = 'xtls-rprx-direct';
		o.depends('v2ray_xtls', '1');
		o.modalonly = true;
		/* XTLS config end */
		/* V2ray config end */

		/* TLS config start */
		o = s.option(form.Flag, 'tls', _('TLS'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'http'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'socks'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'trojan'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vmess'});
		o.modalonly = true;

		o = s.option(form.Value, 'tls_sni', _('TLS SNI'));
		o.depends('type', 'hysteria');
		o.depends('tls', '1');
		o.depends('v2ray_xtls', '1');
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_insecure', _('Allow insecure'),
			_('Allow insecure connection at TLS client. This is <b>DANGEROUS</b>, your traffic is almost <b>PLAIN TEXT</b>! Use at your own risk!'));
		o.default = o.disabled;
		o.depends('type', 'hysteria');
		o.depends('tls', '1');
		o.depends('v2ray_xtls', '1');
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_self_sign', _('Append self-signed certificate'),
			_('If you have the root certificate, use this option instead of enabling insecure.'));
		o.default = o.disabled;
		o.depends('tls_insecure', '0');
		o.modalonly = true;

		o = s.option(form.Value, 'tls_cert_path', _('Path to self-signed certificate'));
		o.default = '/etc/ssl/private/ca.pem';
		o.depends('tls_self_sign', '1');
		o.modalonly = true;
		/* TLS config end */

		return m.render();
	}
});
