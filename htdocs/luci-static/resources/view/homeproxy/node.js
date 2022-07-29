/* SPDX-License-Identifier: GPL-3.0-only
 *
 * Copyright (C) 2022 ImmortalWrt.org
 */

'use strict';
'require form';
'require fs';
'require poll';
'require rpc';
'require uci';
'require ui';
'require view';

function fs_installed(binray) {
	return fs.exec('/bin/ash', ['-c', 'type -t -p ' + binray]).then(function (res) {
		if (res.stdout && res.stdout.trim() !== '')
			return true;
		else
			return false;
	});
}

function parse_subscription_link(uri) {
	var config;

	uri = uri.split('://');
	if (uri[0] && uri[1]) {
		/* Thanks to luci-app-ssr-plus */
		function b64decode(str) {
			str = str.replace(/-/g, '+').replace(/_/g, '/');
			var padding = (4 - str.length % 4) % 4;
			if (padding)
				str = str + Array(padding + 1).join('=');

			return atob(str);
		}

		function b64decodeUnicode(str) {
			return decodeURIComponent(Array.prototype.map.call(b64decode(str), function (c) {
				return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
			}).join(''));
		}

		switch (uri[0]) {
		case 'ss':
			try {
				/* "Lovely" Shadowrocket format */
				try {
					var suri = uri[1].split('#');
					var salias = '';
					if (suri.length <= 2)
						if (suri.length === 2)
							salias = '#' + suri[1];
						uri = [null, b64decode(suri[0]) + salias];
				} catch(e) { }

				/* SIP002 format https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html */
				var url = new URL('http://' + uri[1]);
				var alias = url.hash ? decodeURIComponent(url.hash.slice(1)) : null;

				var userinfo;
				if (url.username && url.password)
					/* User info encoded with URIComponent, mostly for ss2022 */
					userinfo = [url.username, decodeURIComponent(url.password)];
				else
					/* User info encoded with base64 */
					userinfo = b64decode(url.username).split(':');

				var plugin, plugin_opts;
				if (url.search) {
					var plugin_info = url.searchParams.get('plugin').split(';');
					plugin = plugin_info[0];
					plugin_opts = plugin_info.slice(1).join(';');
				}

				/* Check if address, method and password exist */
				if (!url.hostname || !userinfo || userinfo.length !== 2)
					return null;

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
				/* Legacy format https://shadowsocks.org/en/config/quick-guide.html */
				uri = uri[1].split('@');
				if (uri.length < 2)
					return null;
				else if (uri.length > 2)
					uri = [uri.slice(0, -1).join('@'), uri.slice(-1).toString()];

				var method = uri[0].split(':')[0];
				var password = uri[0].split(':').slice(1).join(':');

				/* Check if address, method and password exist */
				if (!uri[1].split(':')[0] || !method || !password)
					return false;

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
			uri = b64decode(uri[1]).split('/');

			/* Check if address, method and password exist */
			if (!uri[0].split(':')[0] || !uri[0].split(':')[3] || !uri[0].split(':')[5])
				return null;

			var params = new URLSearchParams(uri[1]);
			var protoparam = params.get('protoparam') ? b64decode(params.get('protoparam')) : null;
			var obfsparam = params.get('obfsparam') ? b64decode(params.get('obfsparam')) : null;
			var remarks = params.get('remarks') ? b64decodeUnicode(params.get('remarks')) : null;
			
			config = {
				alias: remarks,
				type: 'v2ray',
				v2ray_protocol: 'shadowsocksr',
				address: uri[0].split(':')[0],
				port: uri[0].split(':')[1],
				shadowsocksr_encrypt_method: uri[0].split(':')[3],
				password: b64decode(uri[0].split(':')[5]),
				shadowsocksr_protocol: uri[0].split(':')[2],
				shadowsocksr_protocol_param: protoparam,
				shadowsocksr_obfs: uri[0].split(':')[4],
				shadowsocksr_obfs_param: obfsparam
			};

			break;
		case 'trojan':
			/* https://p4gefau1t.github.io/trojan-go/developer/url/ */
			var url = new URL('http://' + uri[1]);

			/* Check if address and password exist */
			if (!url.hostname || !url.username)
				return null;

			config = {
				alias: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'v2ray',
				v2ray_protocol: 'trojan',
				address: url.hostname,
				port: url.port || '80',
				password: url.username,
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
				tls: params.get('security') === 'tls' ? 1 : 0,
				tls_sni: params.get('sni'),
				tls_alpn: params.get('alpn') ? decodeURIComponent(params.get('alpn')) : null,
				v2ray_xtls: params.get('security') === 'xtls' ? 1 : 0,
				v2ray_xtls_flow: params.get('flow')
			};
			if (config.v2ray_transport === 'grpc') {
				config['grpc_servicename'] = params.get('serviceName');
				config['grpc_mode'] = params.get('mode') || 'gun';
			} else if (['h2', 'tcp', 'ws'].includes(config.v2ray_transport)) {
				config['http_header'] = config.v2ray_transport === 'tcp' ? params.get('headerType') || 'none' : null;
				config['h2_host'] = params.get('host') ? decodeURIComponent(params.get('host')) : null;
				config['h2_path'] = params.get('host') ? decodeURIComponent(params.get('path')) : null;
				if (config.h2_path && config.h2_path.includes('?ed=')) {
					config['websocket_early_data_header'] = 'Sec-WebSocket-Protocol';
					config['websocket_early_data'] = config.h2_path.split('?ed=')[1];
					config['h2_path'] = config.h2_path.split('?ed=')[0];
				}
			} else if (config.v2ray_transport === 'mkcp') {
				config['mkcp_seed'] = params.get('seed');
				config['mkcp_header'] = params.get('headerType') || 'none';
			} else if (config.v2ray_transport === 'quic') {
				config['quic_security'] = params.get('quicSecurity') || 'none';
				config['quic_key'] = params.get('key');
				config['mkcp_header'] = params.get('headerType') || 'none';
			}

			break;
		case 'vmess':
			/* https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2) */
			uri = JSON.parse(b64decodeUnicode(uri[1]));

			if (uri.v === '2') {
				/* Check if address, uuid, type, and alterId exist */
				if (!uri.add || !uri.id || !uri.net || (uri.aid && parseInt(uri.aid) !== 0))
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
					tls: uri.tls === 'tls' ? 1 : 0,
					tls_sni: uri.sni || uri.host,
					tls_alpn: uri.alpn,
					tls_insecure: 1
				};
				if (config.v2ray_transport === 'grpc') {
					config['grpc_servicename'] = uri.path;
					config['grpc_mode'] = 'gun';
				} else if (['h2', 'tcp', 'ws'].includes(config.v2ray_transport)) {
					config['http_header'] = config.v2ray_transport === 'tcp' ? uri.type || 'none' : null;
					config['h2_host'] = uri.host;
					config['h2_path'] = uri.path;
					if (config.h2_path && config.h2_path.includes('?ed=')) {
						config['websocket_early_data_header'] = 'Sec-WebSocket-Protocol';
						config['websocket_early_data'] = config.h2_path.split('?ed=')[1];
						config['h2_path'] = config.h2_path.split('?ed=')[0];
					}
				} else if (config.v2ray_transport === 'mkcp') {
					config['mkcp_seed'] = uri.path;
					config['mkcp_header'] = uri.type || 'none';
				} else if (config.v2ray_transport === 'quic') {
					config['quic_security'] = uri.host || 'none';
					config['quic_key'] = uri.path;
					config['mkcp_header'] = uri.type || 'none';
				}
			} else
				return null;

			break;
		}
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

		var subnodes = [];
		for (var i of uci.sections(data[0], 'node')) {
			if (i.from_subscription === '1')
				subnodes = subnodes.concat(i['.name'])
		}

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
		o.value('0', _('Disabled'));
		o.value('1', _('Blacklist mode'));
		o.value('2', _('Whitelist mode'));
		o.default = '0';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'filter_words', _('Filter keyword'),
			_('Drop/keep node(s) that contain the specific keyword.'));
		o.depends({'filter_nodes': '0', '!reverse': true});

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
			var sublist = uci.get(data[0],section_id, 'subscription_url') || [];
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
			if (subnodes.length > 0) {
				return _('Remove %s node(s)').format(subnodes.length);
			} else {
				this.readonly = true;
				return _('No subscription node');
			}
		}
		o.onclick = function() {
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
									var config = parse_subscription_link(s);
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
		};
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
		/* o.rmempty = false; */

		o = s.option(form.ListValue, 'type', _('Type'));
		o.value('http', _('HTTP'));
		if (have_hysteria)
			o.value('hysteria', _('Hysteria'));
		if (have_naiveproxy)
			o.value('naiveproxy', _('NaïveProxy'));
		o.value('shadowsocks', _('Shadowsocks'));
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
		o.password = true;
		o.depends('type', 'http');
		o.depends('type', 'naiveproxy');
		o.depends('type', 'shadowsocks');
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
		o.default = 'aes-128-gcm';
		o.depends('type', 'shadowsocks');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.modalonly = true;

		o = s.option(form.Flag, 'shadowsocks_tfo', _('TCP fast open'));
		o.default = o.disabled;
		o.depends('type', 'shadowsocks');
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
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocksr'});
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
				return _('Expecting: %s').format(_('valid uuid string'));

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
		o.value('ws', _('WebSocket'));
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

		o = s.option(form.Value, 'tls_alpn', _('TLS ALPN'));
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
		
		o = s.option(form.Button, '_upload_cert', _('Upload certificate'),
			_('Your certificate will be saved to "/etc/ssl/private/ca.pem".'));
		o.inputstyle = 'action';
		o.inputtitle = _('Upload...');
		o.depends('tls_self_sign', '1');
		o.onclick = function(ev) {
			return ui.uploadFile('/etc/ssl/private/ca.pem.tmp', ev.target)
			.then(L.bind(function(btn, res) {
				btn.firstChild.data = _('Checking certificate...');
				return fs.stat('/etc/ssl/private/ca.pem.tmp');
			}, this, ev.target))
			.then(L.bind(function(btn, res) {
				if (res.size <= 0) {
					ui.addNotification(null, E('p', _('The uploaded certificate is empty.')));
					return fs.remove('/etc/ssl/private/ca.pem.tmp');
				}

				fs.exec('/bin/mv', [ '/etc/ssl/private/ca.pem.tmp', '/etc/ssl/private/ca.pem' ]);
				ui.addNotification(null, E('p', _('Your certificate was successfully uploaded. Size: %s.').format(res.size)));
			}, this, ev.target))
			.catch(function(e) { ui.addNotification(null, E('p', e.message)) })
			.finally(L.bind(function(btn, input) {
				btn.firstChild.data = _('Upload...');
			}, this, ev.target));
		}
		o.modalonly = true;
		/* TLS config end */

		return m.render();
	}
});
