/* SPDX-License-Identifier: GPL-3.0-only
 *
 * Copyright (C) 2022 ImmortalWrt.org
 */

'use strict';
'require form';
'require fs';
'require uci';
'require ui';
'require view';
'require tools.widgets as widgets';

function fs_installed(binray) {
	return fs.exec('/usr/bin/which', [ binray ]).then(function (res) {
		if (res.stdout && res.stdout.trim() !== '')
			return true;
		else
			return false;
	});
}

function parse_share_link(uri) {
	var config;

	uri = uri.split('://');
	if (uri[0] && uri[1]) {
		/* Thanks to luci-app-ssr-plus */
		function b64decode(str) {
			str = str.replace(/-/g, '+').replace(/_/g, '/');
			var padding = (4 - str.length % 4) % 4;
			if (padding)
				str = str + Array(padding + 1).join('=');

			return decodeURIComponent(Array.prototype.map.call(atob(str), function (c) {
				return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
			}).join(''));
		}

		switch (uri[0]) {
		case 'hysteria':
			/* https://github.com/HyNetwork/hysteria/wiki/URI-Scheme */
			var url = new URL('http://' + uri[1]);
			var params = url.searchParams;

			config = {
				alias: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'hysteria',
				address: url.hostname,
				port: url.port || '80',
				hysteria_protocol: params.get('protocol') || 'udp',
				hysteria_auth_type: params.get('auth') ? 'string' : null,
				hysteria_auth_payload: params.get('auth'),
				hysteria_password: params.get('obfsParam'),
				mkcp_downlink_capacity: params.get('downmbps'),
				mkcp_uplink_capacity: params.get('upmbps'),
				tls: '1',
				tls_sni: params.get('peer'),
				tls_alpn: params.get('alpn'),
				tls_insecure: params.get('insecure') || '0'
			}

			break;
		case 'ss':
			try {
				/* "Lovely" Shadowrocket format */
				try {
					var suri = uri[1].split('#');
					var salias = '';
					if (suri.length <= 2) {
						if (suri.length === 2)
							salias = '#' + suri[1];
						uri = [null, b64decode(suri[0]) + salias];
					}
				} catch(e) { }

				/* SIP002 format https://shadowsocks.org/guide/sip002.html */
				var url = new URL('http://' + uri[1]);
				var alias = url.hash ? decodeURIComponent(url.hash.slice(1)) : null;

				var userinfo;
				if (url.username && url.password)
					/* User info encoded with URIComponent, mostly for ss2022 */
					userinfo = [url.username, decodeURIComponent(url.password)];
				else if (url.username)
					/* User info encoded with base64 */
					userinfo = b64decode(url.username).split(':');

				var plugin, plugin_opts;
				if (url.search && url.searchParams.get('plugin')) {
					var plugin_info = url.searchParams.get('plugin').split(';');
					plugin = plugin_info[0];
					plugin_opts = plugin_info.slice(1) ? plugin_info.slice(1).join(';') : null;
				}

				config = {
					alias: alias,
					type: plugin ? 'v2ray' : 'shadowsocks',
					v2ray_protocol: plugin ? 'shadowsocks' : null,
					address: url.hostname,
					port: url.port || '80',
					shadowsocks_encrypt_method: userinfo[0],
					password: userinfo[1],
					shadowsocks_plugin: plugin,
					shadowsocks_plugin_opts: plugin_opts
				};

				break;
			} catch(e) {
				/* Legacy format https://github.com/shadowsocks/shadowsocks-org/commit/78ca46cd6859a4e9475953ed34a2d301454f579e */
				uri = uri[1].split('@');
				if (uri.length < 2)
					return null;
				else if (uri.length > 2)
					uri = [uri.slice(0, -1).join('@'), uri.slice(-1).toString()];

				var method = uri[0].split(':')[0];
				var password = uri[0].split(':').slice(1).join(':');

				config = {
					type: 'shadowsocks',
					address: uri[1].split(':')[0],
					port: uri[1].split(':')[1],
					shadowsocks_encrypt_method: method,
					password: password
				};

				break;
			}
		case 'ssr':
			/* https://coderschool.cn/2498.html */
			uri = b64decode(uri[1]).split('/');
			var userinfo = uri[0].split(':')

			/* Check if address, method and password exist */
			if (!userinfo[0] || !userinfo[3] || !userinfo[5])
				return null;

			var params = new URLSearchParams(uri[1]);
			var protoparam = params.get('protoparam') ? b64decode(params.get('protoparam')) : null;
			var obfsparam = params.get('obfsparam') ? b64decode(params.get('obfsparam')) : null;
			var remarks = params.get('remarks') ? b64decode(params.get('remarks')) : null;

			config = {
				alias: remarks,
				type: 'v2ray',
				v2ray_protocol: 'shadowsocksr',
				address: userinfo[0],
				port: userinfo[1],
				shadowsocksr_encrypt_method: userinfo[3],
				password: b64decode(userinfo[5]),
				shadowsocksr_protocol: userinfo[2],
				shadowsocksr_protocol_param: protoparam,
				shadowsocksr_obfs: userinfo[4],
				shadowsocksr_obfs_param: obfsparam
			};

			break;
		case 'trojan':
			/* https://p4gefau1t.github.io/trojan-go/developer/url/ */
			var url = new URL('http://' + uri[1]);

			config = {
				alias: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'v2ray',
				v2ray_protocol: 'trojan',
				address: url.hostname,
				port: url.port || '80',
				password: decodeURIComponent(url.username),
				tls: '1',
				tls_sni: url.searchParams.get('sni')
			};

			break;
		case 'vless':
			/* https://github.com/XTLS/Xray-core/discussions/716 */
			var url = new URL('http://' + uri[1]);
			var params = url.searchParams;

			/* Check if address, uuid and type exist */
			if (!url.hostname || !url.username || !params.get('type'))
				return null;

			config = {
				alias: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'v2ray',
				v2ray_protocol: 'vless',
				address: url.hostname,
				port: url.port || '80',
				v2ray_uuid: url.username,
				v2ray_vless_encrypt: params.get('encryption') || 'none',
				v2ray_transport: params.get('type'),
				tls: params.get('security') === 'tls' ? '1' : '0',
				tls_sni: params.get('sni'),
				tls_alpn: params.get('alpn') ? decodeURIComponent(params.get('alpn')).split(',') : null,
				v2ray_xtls: params.get('security') === 'xtls' ? '1' : '0',
				v2ray_xtls_flow: params.get('flow')
			};
			switch (config.v2ray_transport) {
			case 'grpc':
				config['grpc_servicename'] = params.get('serviceName');
				config['grpc_mode'] = params.get('mode') || 'gun';

				break;
			case 'h2':
			case 'tcp':
			case 'ws':
				config['http_header'] = config.v2ray_transport === 'tcp' ? params.get('headerType') || 'none' : null;
				config['h2_host'] = params.get('host') ? decodeURIComponent(params.get('host')) : null;
				config['h2_path'] = params.get('host') ? decodeURIComponent(params.get('path')) : null;
				if (config.h2_path && config.h2_path.includes('?ed=')) {
					config['websocket_early_data_header'] = 'Sec-WebSocket-Protocol';
					config['websocket_early_data'] = config.h2_path.split('?ed=')[1];
					config['h2_path'] = config.h2_path.split('?ed=')[0];
				}

				break;
			case 'mkcp':
				config['mkcp_seed'] = params.get('seed');
				config['mkcp_header'] = params.get('headerType') || 'none';
				/* Default settings from v2rayN */
				config['mkcp_downlink_capacity'] = '100';
				config['mkcp_uplink_capacity'] = '12';
				config['mkcp_read_buffer_size'] = '2';
				config['mkcp_write_buffer_size'] = '2';
				config['mkcp_mtu'] = '1350';
				config['mkcp_tti'] = '50';

				break;
			case 'quic':
				config['quic_security'] = params.get('quicSecurity') || 'none';
				config['quic_key'] = params.get('key');
				config['mkcp_header'] = params.get('headerType') || 'none';

				break;
			}

			break;
		case 'vmess':
			/* https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2) */
			uri = JSON.parse(b64decode(uri[1]));

			if (uri.v !== '2')
				return null;
			/* https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6 */
			else if (uri.aid && parseInt(uri.aid) !== 0)
				return null;

			config = {
				alias: uri.ps,
				type: 'v2ray',
				v2ray_protocol: 'vmess',
				address: uri.add,
				port: uri.port,
				v2ray_uuid: uri.id,
				v2ray_vmess_encrypt: uri.scy || 'auto',
				v2ray_transport: uri.net,
				tls: uri.tls === 'tls' ? '1' : '0',
				tls_sni: uri.sni || uri.host,
				tls_alpn: uri.alpn ? uri.alpn.split(',') : null
			};
			switch (config.v2ray_transport) {
			case 'grpc':
				config['grpc_servicename'] = uri.path;
				config['grpc_mode'] = 'gun';
				
				break;
			case 'h2':
			case 'tcp':
			case 'ws':
				config['http_header'] = config.v2ray_transport === 'tcp' ? uri.type || 'none' : null;
				config['h2_host'] = uri.host;
				config['h2_path'] = uri.path;
				if (config.h2_path && config.h2_path.includes('?ed=')) {
					config['websocket_early_data_header'] = 'Sec-WebSocket-Protocol';
					config['websocket_early_data'] = config.h2_path.split('?ed=')[1];
					config['h2_path'] = config.h2_path.split('?ed=')[0];
				}

				break;
			case 'mkcp':
				config['mkcp_seed'] = uri.path;
				config['mkcp_header'] = uri.type || 'none';
				/* Default settings from v2rayN */
				config['mkcp_downlink_capacity'] = '100';
				config['mkcp_uplink_capacity'] = '12';
				config['mkcp_read_buffer_size'] = '2';
				config['mkcp_write_buffer_size'] = '2';
				config['mkcp_mtu'] = '1350';
				config['mkcp_tti'] = '50';

				break;
			case 'quic':
				config['quic_security'] = uri.host || 'none';
				config['quic_key'] = uri.path;
				config['mkcp_header'] = uri.type || 'none';

				break;
			}

			break;
		}
	}

	if (config) {
		if (!config.address || !config.port)
			return null;
		else if (!config.alias)
			config['alias'] = config.address + ':' + config.port;
	}

	return config;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy'),
			fs_installed('hysteria'),
			fs_installed('naive')
		]);
	},

	render: function(data) {
		var m, s, o;

		var have_hysteria = data[1];
		var have_naiveproxy = data[2];

		var native_protocols = [ 'http', 'shadowsocks', 'socks', 'trojan', 'vmess' ];
		var v2ray_native_protocols = [ 'http', 'shadowsocks', 'socks', 'trojan', 'vless', 'vmess' ];

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

		o = s.option(form.DynamicList, 'subscription_url', _('Subscription URL'),
			_('Support Shadowsocks(R), Trojan, V2RayN(G), and VLESS online configuration delivery standard.'));
		o.validate = function(section_id, value) {
			if (section_id && value !== null && value !== '') {
				try {
					new URL(value);
				}
				catch(e) {
					return _('Expecting: %s').format(_('valid URL'));
				}
			}

			return true;
		}

		o = s.option(form.ListValue, 'filter_nodes', _('Filter nodes'),
			_('Drop/keep specific node(s) from subscriptions.'));
		o.value('disabled', _('Disable'));
		o.value('blacklist', _('Blacklist mode'));
		o.value('whitelist', _('Whitelist mode'));
		o.default = 'disabled';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'filter_words', _('Filter keyword'),
			_('Drop/keep node(s) that contain the specific keyword.'));
		o.depends({'filter_nodes': 'disabled', '!reverse': true});

		o = s.option(form.Button, '_save_subscriptions', _('Save subscriptions settings'),
			_('Save settings before updating subscriptions.'));
		o.inputstyle = 'apply';
		o.inputtitle = _('Save current settings');
		o.onclick = function() {
			ui.changes.apply(true);
			return this.map.save(null, true);
		}

		o = s.option(form.Button, '_update_subscriptions', _('Update nodes from subscriptions'));
		o.inputstyle = 'apply';
		o.inputtitle = function(section_id) {
			var sublist = uci.get(data[0], section_id, 'subscription_url') || [];
			if (sublist.length > 0)
				return _('Update %s subscription(s)').format(sublist.length);
			else {
				this.readonly = true;
				return _('No subscription available')
			}
		}
		o.onclick = function() {
			/* TODO: add corresponding script. */
		}

		o = s.option(form.Button, '_remove_subscriptions', _('Remove all nodes from subscriptions'));
		o.inputstyle = 'reset';
		o.inputtitle = function() {
			var subnodes = [];
			uci.sections(data[0], 'node', function(res) {
				if (res.from_subscription === '1')
					subnodes = subnodes.concat(res['.name'])
			});

			if (subnodes.length > 0) {
				return _('Remove %s node(s)').format(subnodes.length);
			} else {
				this.readonly = true;
				return _('No subscription node');
			}
		}
		o.onclick = function() {
			var subnodes = [];
			uci.sections(data[0], 'node', function(res) {
				if (res.from_subscription === '1')
					subnodes = subnodes.concat(res['.name'])
			});

			for (var i in subnodes)
				uci.remove(data[0], subnodes[i]);

			if (subnodes.includes(uci.get(data[0], 'config', 'main_server')))
				uci.set(data[0], 'config', 'main_server', 'nil');

			if (subnodes.includes(uci.get(data[0], 'config', 'main_udp_server')))
				uci.set(data[0], 'config', 'main_udp_server', 'nil');

			this.inputtitle = _('%s node(s) removed').format(subnodes.length);
			this.readonly = true;

			return this.map.save(null, true);
		}

		s = m.section(form.GridSection, 'node');
		s.addremove = true;
		s.anonymous = true;
		s.nodescriptions = true;
		s.sortable = true;
		s.modaltitle = function(section_id) {
			var alias = uci.get(data[0], section_id, 'alias') || uci.get(data[0], section_id, 'address');
			return alias ? _('Node') + ' » ' + alias : _('Add a node');
		}

		/* Import subscription links start */
		/* Thanks to luci-app-shadowsocks-libev
		 * Yousong Zhou <yszhou4tech@gmail.com>
		 */
		s.handleLinkImport = function() {
			var textarea = new ui.Textarea();
			ui.showModal(_('Import share links'), [
				E('p', _('Support Shadowsocks(R), Trojan, V2RayN(G), and VLESS online configuration delivery standard.')),
				textarea.render(),
				E('div', { class: 'right' }, [
					E('button', {
						class: 'btn',
						click: ui.hideModal
					}, [ _('Cancel') ]),
					'',
					E('button', {
						class: 'btn cbi-button-action',
						click: ui.createHandlerFn(this, function() {
							var input_links = textarea.getValue().trim().split('\n');
							if (input_links && input_links[0]) {
								/* Remove duplicate lines */
								input_links = input_links.reduce((pre, cur) =>
									(!pre.includes(cur) && pre.push(cur), pre), []);

								var imported_node = 0;
								input_links.forEach(function(s) {
									var config = parse_share_link(s);
									if (config) {
										var sid = uci.add(data[0], 'node');
										Object.keys(config).forEach(function(k) {
											uci.set(data[0], sid, k, config[k]);
										});
										imported_node++;
									}
								});

								if (imported_node === 0)
									ui.addNotification(null, E('p', _('No valid share link found.')));
								else
									ui.addNotification(null, E('p', _('Successfully imported %s node(s) of total %s.').format(imported_node, input_links.length)));

								return uci.save()
									.then(L.bind(this.map.load, this.map))
									.then(L.bind(this.map.reset, this.map))
									.then(L.ui.hideModal)
									.catch(function() {});
							} else
								return ui.hideModal();
						})
					}, [ _('Import') ])
				])
			])
		}
		s.renderSectionAdd = function(extra_class) {
			var el = form.GridSection.prototype.renderSectionAdd.apply(this, arguments);
			el.appendChild(E('button', {
				'class': 'cbi-button cbi-button-add',
				'title': _('Import share links'),
				'click': ui.createHandlerFn(this, 'handleLinkImport')
			}, [ _('Import share links') ]));
			return el;
		}
		/* Import subscription links end */

		o = s.option(form.Button, '_apply', _('Apply'));
		o.editable = true;
		o.modalonly = false;
		o.inputstyle = 'apply';
		o.inputtitle = function(section_id) {
			var main_server = uci.get(data[0], 'config', 'main_server');
			if (main_server == section_id) {
				this.readonly = true;
				return _('Applied');
			} else {
				this.readonly = false;
				return _('Apply');
			}
		}
		o.onclick = function(_, section_id) {
			uci.set(data[0], 'config', 'main_server', section_id);
			ui.changes.apply(true);

			return this.map.save(null, true);
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
		o.value('socks', _('Socks'));
		o.value('trojan', _('Trojan'));
		o.value('v2ray', _('V2ray'));
		o.value('vmess', _('VMess'));
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
		o.rmempty = false;
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
		o.password = true;
		o.depends('type', 'http');
		o.depends('type', 'naiveproxy');
		o.depends('type', 'shadowsocks');
		o.depends('type', 'trojan');
		o.depends({'type': 'socks', 'socks_ver': '5'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'http'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'socks', 'socks_ver': '5'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'trojan'});
		o.validate = function(section_id, value) {
			if (section_id && (value === null || value === '')) {
				var required_type = ['naiveproxy', 'shadowsocks', 'shadowsocksr', 'trojan'];
				var type = this.map.lookupOption('type', section_id)[0].formvalue(section_id);
				var v2ray_protocol = this.map.lookupOption('v2ray_protocol', section_id)[0].formvalue(section_id) || '';
				if (required_type.includes(type) || required_type.includes(v2ray_protocol))
					return _('Expecting: non-empty value');
			}

			return true;
		}
		o.modalonly = true;

		/* NaïveProxy config start */
		o = s.option(form.ListValue, 'naiveproxy_network'), _('Network mode');
		o.value('h2', _('HTTP/2'));
		o.value('quic', _('QUIC'));
		o.default = 'h2';
		o.depends('type', 'naiveproxy');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'naiveproxy_concurrency', _('Concurrency'));
		o.datatype = 'uinteger';
		o.default = '1';
		o.depends('type', 'naiveproxy');
		o.rmempty = false;
		o.modalonly = true;
		/* NaïveProxy config end */

		/* Hysteria config start */
		o = s.option(form.ListValue, 'hysteria_protocol', _('Protocol'));
		o.value('udp');
		o.value('wechat-video');
		o.value('faketcp');
		o.default = 'udp';
		o.depends('type', 'hysteria');
		o.rmempty = false;
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
		o.depends({'type': 'hysteria', 'auth_type': '1'});
		o.depends({'type': 'hysteria', 'auth_type': '2'});
		o.rmempty = false;
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

		o = s.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable Path MTU discovery'));
		o.default = o.disabled;
		o.depends('type', 'hysteria');
		o.rmempty = false;
		o.modalonly = true;
		/* Hysteria config end */

		/* Shadowsocks config start */
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
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'shadowsocks_uot', _('UDP over TCP'),
			_('Enable the SUoT protocol, requires server support. Conflict with multiplex.'));
		o.default = o.disabled;
		o.depends('type', 'shadowsocks');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'shadowsocks_ivcheck', _('Bloom filter'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.rmempty = false;
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
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.rmempty = false;
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
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocksr_protocol_param', _('Protocol param'));
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.modalonly = true;

		o = s.option(form.ListValue, 'shadowsocksr_obfs', _('Obfs'));
		o.value('plain');
		o.value('http_simple');
		o.value('http_post');
		o.value('random_head');
		o.value('tls1.2_ticket_auth');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocksr_obfs_param', _('Obfs param'));
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
		o.modalonly = true;
		/* ShadowsocksR config end */

		/* Socks config start */
		o = s.option(form.ListValue, 'socks_ver', _('Socks version'));
		o.value('4', _('Socks4'));
		o.value('4a', _('Socks4A'));
		o.value('5', _('Socks5'));
		o.default = '5';
		o.depends('type', 'socks');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'socks'});
		o.rmempty = false;
		o.modalonly = true;
		/* Socks config end */

		/* V2ray config start */
		o = s.option(form.Value, 'v2ray_uuid', _('UUID'));
		o.depends('type', 'vmess');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vmess'});
		o.validate = function(section_id, value) {
			if (section_id) {
				if (value == null || value == '')
					return _('Expecting: non-empty value');
				else if (value.match('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') === null)
					return _('Expecting: %s').format(_('valid uuid string'));
			}

			return true;
		}
		o.modalonly = true;

		o = s.option(form.Value, 'v2ray_vless_encrypt', _('Encrypt method'));
		o.default = 'none';
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.ListValue, 'v2ray_vmess_encrypt', _('Encrypt method'));
		o.value('auto');
		o.value('none');
		o.value('zero');
		o.value('aes-128-gcm');
		o.value('chacha20-poly1305');
		o.default = 'aes-128-gcm';
		o.depends('type', 'vmess');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vmess'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'vmess_global_padding', 'Global padding',
			_('Protocol parameter. Will waste traffic randomly if enabled (enabled by default in v2ray and cannot be disabled).'));
		o.default = o.enabled;
		o.depends('type', 'vmess');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'vmess_authenticated_length', _('Authenticated length'),
			_('Protocol parameter. Enable length block encryption.'));
		o.default = o.enabled;
		o.depends('type', 'vmess');
		o.rmempty = false;
		o.modalonly = true;

		/* Wireguard config start */
		o = s.option(form.DynamicList, 'wireguard_local_addresses', _('Local addresses'));
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'wireguard'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'wireguard_private_key', _('Private key'));
		o.password = true;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'wireguard'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'wireguard_peer_pubkey', _('Peer pubkic key'));
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'wireguard'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'wireguard_preshared_key', _('Pre-shared key'));
		o.password = true;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'wireguard'});
		o.rmempty = false;
		o.modalonly = true;
		/* Wireguard config end */

		o = s.option(form.ListValue, 'v2ray_transport', _('Transport'));
		o.value('grpc', _('gRPC'));
		o.value('h2', _('HTTP/2'));
		o.value('mkcp', _('mKCP'));
		o.value('quic', _('QUIC'));
		o.value('tcp', _('TCP'));
		o.value('ws', _('WebSocket'));
		o.default = 'tcp';
		for (i in v2ray_native_protocols)
			o.depends({'type': 'v2ray', 'v2ray_protocol': v2ray_native_protocols[i]})
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
		o.depends({'type': 'v2ray', 'v2ray_transport': 'ws'});
		o.modalonly = true;

		o = s.option(form.Value, 'h2_path', _('Path'));
		o.depends({'type': 'v2ray', 'v2ray_transport': 'h2'});
		o.depends({'type': 'v2ray', 'v2ray_transport': 'ws'});
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
		o.depends({'type': 'v2ray', 'v2ray_transport': 'ws'});
		o.modalonly = true;

		o = s.option(form.Value, 'websocket_early_data_header', _('Early data header name'));
		o.default = 'Sec-WebSocket-Protocol';
		o.depends({'type': 'v2ray', 'v2ray_transport': 'ws'});
		o.modalonly = true;
		/* WebSocket config end */

		/* XTLS config start */
		o = s.option(form.Flag, 'v2ray_xtls', _('XTLS'));
		o.default = o.disabled;
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'trojan', 'v2ray_transport': 'tcp', 'multiplex': '0', 'tls': '0'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'trojan', 'v2ray_transport': 'mkcp', 'multiplex': '0', 'tls': '0'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless', 'v2ray_transport': 'tcp', 'multiplex': '0', 'tls': '0'});
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'vless', 'v2ray_transport': 'mkcp', 'multiplex': '0', 'tls': '0'});
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

		/* Mux config start */
		o = s.option(form.Flag, 'multiplex', _('Multiplex'));
		o.default = o.disabled;
		o.depends('type', 'shadowsocks');
		o.depends('type', 'trojan');
		o.depends('type', 'vmess');
		for (i in v2ray_native_protocols)
			o.depends({'type': 'v2ray', 'v2ray_protocol': v2ray_native_protocols[i]})
		o.modalonly = true;

		o = s.option(form.ListValue, 'multiplex_protocol', _('Protocol'),
			_('Multiplex protocol.'));
		o.value('smux');
		o.value('yamux');
		o.default = 'smux';
		o.depends({'type': 'shadowsocks', 'multiplex': '1'});
		o.depends({'type': 'trojan', 'multiplex': '1'});
		o.depends({'type': 'vmess', 'multiplex': '1'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'max_connections', _('Maximum connections'));
		o.datatype = 'uinteger';
		o.depends({'type': 'shadowsocks', 'multiplex': '1'});
		o.depends({'type': 'trojan', 'multiplex': '1'});
		o.depends({'type': 'vmess', 'multiplex': '1'});
		o.modalonly = true;

		o = s.option(form.Value, 'min_streams', _('Minimum streams'),
			_('Minimum multiplexed streams in a connection before opening a new connection.'));
		o.datatype = 'uinteger';
		o.depends({'type': 'shadowsocks', 'multiplex': '1'});
		o.depends({'type': 'trojan', 'multiplex': '1'});
		o.depends({'type': 'vmess', 'multiplex': '1'});
		o.modalonly = true;

		o = s.option(form.Value, 'max_streams', _('Maximum streams'),
			_('Maximum multiplexed streams in a connection before opening a new connection.<br/>' +
				'Conflict with <code>Maximum connections</code> and <code>Minimum streams</code>.'));
		o.datatype = 'uinteger';
		o.depends({'type': 'shadowsocks', 'multiplex': '1', 'max_connections': '', 'min_streams': ''});
		o.depends({'type': 'trojan', 'multiplex': '1', 'max_connections': '', 'min_streams': ''});
		o.depends({'type': 'vmess', 'multiplex': '1', 'max_connections': '', 'min_streams': ''});
		o.modalonly = true;

		/* Mux config end */

		/* TLS config start */
		o = s.option(form.Flag, 'tls', _('TLS'));
		o.default = o.disabled;
		o.depends('type', 'http');
		o.depends('type', 'trojan');
		for (i in v2ray_native_protocols)
			o.depends({'type': 'v2ray', 'v2ray_protocol': v2ray_native_protocols[i]})
		o.depends('type', 'vmess');
		o.modalonly = true;

		o = s.option(form.Value, 'tls_sni', _('TLS SNI'),
			_('Used to verify the hostname on the returned certificates unless insecure is given.'));
		o.depends('type', 'hysteria');
		o.depends('tls', '1');
		o.depends('v2ray_xtls', '1');
		o.modalonly = true;

		o = s.option(form.DynamicList, 'tls_alpn', _('TLS ALPN'),
			_('List of supported application level protocols, in order of preference.'));
		o.depends('type', 'hysteria');
		o.depends('tls', '1');
		o.depends('v2ray_xtls', '1');
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_insecure', _('Allow insecure'),
			_('Allow insecure connection at TLS client. This is <b>DANGEROUS</b>, your traffic is almost like <b>PLAIN TEXT</b>! Use at your own risk!'));
		o.default = o.disabled;
		o.depends('type', 'hysteria');
		o.depends('tls', '1');
		o.depends('v2ray_xtls', '1');
		o.modalonly = true;

		o = s.option(form.ListValue, 'tls_min_version', _('Minimum TLS version'),
			_('The minimum TLS version that is acceptable. Default to 1.0.'));
		o.value('1.0');
		o.value('1.1');
		o.value('1.2');
		o.value('1.3');
		o.default = '1.0';
		o.depends({'type': 'http', 'tls': '1'});
		o.depends({'type': 'trojan', 'tls': '1'});
		o.depends({'type': 'vmess', 'tls': '1'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.ListValue, 'tls_max_version', _('Maximum TLS version'),
			_('The maximum TLS version that is acceptable. Default to 1.3.'));
		o.value('1.0');
		o.value('1.1');
		o.value('1.2');
		o.value('1.3');
		o.default = '1.3';
		o.depends({'type': 'http', 'tls': '1'});
		o.depends({'type': 'trojan', 'tls': '1'});
		o.depends({'type': 'vmess', 'tls': '1'});
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
		o.depends({'type': 'http', 'tls': '1'});
		o.depends({'type': 'trojan', 'tls': '1'});
		o.depends({'type': 'vmess', 'tls': '1'});
		o.optional = true;
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_self_sign', _('Append self-signed certificate'),
			_('If you have the root certificate, use this option instead of allowing insecure.'));
		o.default = o.disabled;
		o.depends('tls_insecure', '0');
		o.modalonly = true;

		o = s.option(form.Value, 'tls_cert_path', _('Certificate path'),
			_('The path to the server certificate, in PEM format.'));
		o.default = '/etc/homeproxy/certs/client_ca.pem';
		o.depends('tls_self_sign', '1');
		o.modalonly = true;

		o = s.option(form.Button, '_upload_cert', _('Upload certificate'),
			_('Your %s will be saved to "/etc/homeproxy/certs/%s.pem".<br />' +
			'<strong>Save your configuration before uploading files!</strong>')
			.format(_('certificate'), 'client_ca'));
		o.inputstyle = 'action';
		o.inputtitle = _('Upload...');
		o.depends('tls_self_sign', '1');
		o.onclick = function(ev) {
			fs.exec('/bin/mkdir', [ '-p', '/etc/homeproxy/certs/' ]);

			return ui.uploadFile('/etc/homeproxy/certs/client_ca.pem.tmp', ev.target)
			.then(L.bind(function(btn, res) {
				btn.firstChild.data = _('Checking certificate...');
				return fs.stat('/etc/homeproxy/certs/client_ca.pem.tmp');
			}, this, ev.target))
			.then(L.bind(function(btn, res) {
				if (res.size <= 0) {
					ui.addNotification(null, E('p', _('The uploaded certificate is empty.')));
					return fs.remove('/etc/homeproxy/certs/client_ca.pem.tmp');
				}

				fs.exec('/bin/mv', [ '/etc/homeproxy/certs/client_ca.pem.tmp', '/etc/homeproxy/certs/client_ca.pem' ]);
				ui.addNotification(null, E('p', _('Your certificate was successfully uploaded. Size: %s.').format(res.size)));
			}, this, ev.target))
			.catch(function(e) { ui.addNotification(null, E('p', e.message)) })
			.finally(L.bind(function(btn, input) {
				btn.firstChild.data = _('Upload...');
			}, this, ev.target));
		}
		o.modalonly = true;
		/* TLS config end */

		/* Extra settings start */
		o = s.option(form.ListValue, 'outbound', _('Outbound'),
			_('The tag of the upstream outbound. Other dial fields will be ignored when enabled.'));
		o.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			var _this = this;
			this.value('', _('None'));
			uci.sections(data[0], 'node', function(res) {
				if (res['.name'] !== section_id && native_protocols.includes(res.type))
					_this.value(res['.name'], String.format('[%s] %s',
						res.type, res.alias || res.server + ':' + res.server_port));
			});

			return this.super('load', section_id);
		}
		for (var i in native_protocols)
			o.depends('type', native_protocols[i])
		o.modalonly = true;

		o = s.option(widgets.DeviceSelect, 'bind_interface', _('Bind interface'),
			_('The network interface to bind to.'));
		o.multiple = false;
		for (var i in native_protocols)
			o.depends('type', native_protocols[i])
		o.modalonly = true;

		o = s.option(form.Flag, 'tcp_fast_open', _('TCP fast open'));
		o.default = o.disabled;
		for (var i in native_protocols)
			o.depends('type', native_protocols[i])
		for (i in v2ray_native_protocols)
			o.depends({'type': 'v2ray', 'v2ray_protocol': v2ray_native_protocols[i]})
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.ListValue, 'domain_strategy', _('Domain strategy'),
			_('If set, the server domain name will be resolved to IP before connecting.<br/>dns.strategy will be used if empty.'));
		o.value('', _('Default'));
		o.value('prefer_ipv4', _('Prefer IPv4'));
		o.value('prefer_ipv6', _('Prefer IPv6'));
		o.value('ipv4_only', _('IPv4 only'));
		o.value('ipv6_only', _('IPv6 only'));
		for (var i in native_protocols)
			o.depends('type', native_protocols[i])
		o.modalonly = true;
		/* Extra settings end */
		
		return m.render();
	}
});
