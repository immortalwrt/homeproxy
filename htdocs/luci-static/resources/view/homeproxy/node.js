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
'require tools.homeproxy as hp';
'require tools.widgets as widgets';

function parse_share_link(uri) {
	var config;

	uri = uri.split('://');
	if (uri[0] && uri[1]) {
		switch (uri[0]) {
		case 'hysteria':
			/* https://github.com/HyNetwork/hysteria/wiki/URI-Scheme */
			var url = new URL('http://' + uri[1]);
			var params = url.searchParams;

			/* WeChat-Video / FakeTCP are unsupported by sing-box currently */
			if (params.get('protocol') && params.get('protocol') !== 'udp')
				return null;

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'hysteria',
				address: url.hostname,
				port: url.port || '80',
				hysteria_protocol: params.get('protocol') || 'udp',
				hysteria_auth_type: params.get('auth') ? 'string' : null,
				hysteria_auth_payload: params.get('auth'),
				hysteria_obfs_password: params.get('obfsParam'),
				mkcp_downlink_capacity: params.get('downmbps'),
				mkcp_uplink_capacity: params.get('upmbps'),
				tls: '1',
				tls_sni: params.get('peer'),
				tls_alpn: params.get('alpn'),
				tls_insecure: params.get('insecure') ? '1' : '0'
			}

			break;
		case 'ss':
			try {
				/* "Lovely" Shadowrocket format */
				try {
					var suri = uri[1].split('#'), slabel = '';
					if (suri.length <= 2) {
						if (suri.length === 2)
							slabel = '#' + suri[1];
						uri[1] = hp.decodeBase64Str(suri[0]) + slabel;
					}
				} catch(e) { }

				/* SIP002 format https://shadowsocks.org/guide/sip002.html */
				var url = new URL('http://' + uri[1]);

				var userinfo;
				if (url.username && url.password)
					/* User info encoded with URIComponent */
					userinfo = [url.username, decodeURIComponent(url.password)];
				else if (url.username)
					/* User info encoded with base64 */
					userinfo = hp.decodeBase64Str(url.username).split(':');

				if (!hp.shadowsocks_encrypt_methods.includes(userinfo[0]))
					return null;

				var plugin, plugin_opts;
				if (url.search && url.searchParams.get('plugin')) {
					var plugin_info = url.searchParams.get('plugin').split(';');
					plugin = plugin_info[0];
					plugin_opts = plugin_info.slice(1) ? plugin_info.slice(1).join(';') : null;
				}

				config = {
					label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
					type: 'shadowsocks',
					address: url.hostname,
					port: url.port || '80',
					shadowsocks_encrypt_method: userinfo[0],
					password: userinfo[1],
					shadowsocks_plugin: plugin,
					shadowsocks_plugin_opts: plugin_opts
				};
			} catch(e) {
				/* Legacy format https://github.com/shadowsocks/shadowsocks-org/commit/78ca46cd6859a4e9475953ed34a2d301454f579e */
				uri = uri[1].split('@');
				if (uri.length < 2)
					return null;
				else if (uri.length > 2)
					uri = [ uri.slice(0, -1).join('@'), uri.slice(-1).toString() ];

				var method = uri[0].split(':')[0];
				var password = uri[0].split(':').slice(1).join(':');

				config = {
					type: 'shadowsocks',
					address: uri[1].split(':')[0],
					port: uri[1].split(':')[1],
					shadowsocks_encrypt_method: method,
					password: password
				};
			}

			/* Check if method and password exist */
			if (!config.shadowsocks_encrypt_method || !config.password)
				return null;

			break;
		case 'ssr':
			/* https://coderschool.cn/2498.html */
			uri = hp.decodeBase64Str(uri[1]).split('/');
			var userinfo = uri[0].split(':')

			/* Check if method and password exist */
			if (!userinfo[3] || !userinfo[5])
				return null;

			var params = new URLSearchParams(uri[1]);
			var protoparam = params.get('protoparam') ? hp.decodeBase64Str(params.get('protoparam')) : null;
			var obfsparam = params.get('obfsparam') ? hp.decodeBase64Str(params.get('obfsparam')) : null;
			var remarks = params.get('remarks') ? hp.decodeBase64Str(params.get('remarks')) : null;

			config = {
				label: remarks,
				type: 'shadowsocksr',
				address: userinfo[0],
				port: userinfo[1],
				shadowsocksr_encrypt_method: userinfo[3],
				password: hp.decodeBase64Str(userinfo[5]),
				shadowsocksr_protocol: userinfo[2],
				shadowsocksr_protocol_param: protoparam,
				shadowsocksr_obfs: userinfo[4],
				shadowsocksr_obfs_param: obfsparam
			};

			break;
		case 'trojan':
			/* https://p4gefau1t.github.io/trojan-go/developer/url/ */
			var url = new URL('http://' + uri[1]);

			/* Check if password exists */
			if (!url.username)
				return null;

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'trojan',
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

			/* Check if uuid and type exist */
			if (!url.username || !params.get('type'))
				return null;

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'v2ray',
				v2ray_protocol: 'vless',
				address: url.hostname,
				port: url.port || '80',
				v2ray_uuid: url.username,
				v2ray_vless_encrypt: params.get('encryption') || 'none',
				v2ray_transport: params.get('type') || 'tcp',
				tls: params.get('security') === 'tls' ? '1' : '0',
				tls_sni: params.get('sni'),
				tls_alpn: params.get('alpn') ? decodeURIComponent(params.get('alpn')).split(',') : null,
				v2ray_xtls: params.get('security') === 'xtls' ? '1' : '0',
				v2ray_xtls_flow: params.get('flow')
			};
			switch (config.v2ray_transport) {
			case 'grpc':
				config.grpc_servicename = params.get('serviceName');
				config.grpc_mode = params.get('mode') || 'gun';

				break;
			case 'http':
				config.v2ray_transport = 'h2';
				config.h2_host = params.get('host') ? decodeURIComponent(params.get('host')).split(',') : null;
				config.h2_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;

				break;
			case 'kcp':
				config.v2ray_transport = 'mkcp';
				config.mkcp_seed = params.get('seed');
				config.mkcp_header = params.get('headerType') || 'none';
				/* Default settings from v2rayN */
				config.mkcp_downlink_capacity = '100';
				config.mkcp_uplink_capacity = '12';
				config.mkcp_read_buffer_size = '2';
				config.mkcp_write_buffer_size = '2';
				config.mkcp_mtu = '1350';
				config.mkcp_tti = '50';

				break;
			case 'quic':
				config.quic_security = params.get('quicSecurity') || 'none';
				config.quic_key = params.get('key');
				config.mkcp_header = params.get('headerType') || 'none';

				break;
			case 'tcp':
				config.tcp_header = params.get('headerType') || 'none';
				if (config.tcp_header === 'http') {
					config.tcp_host = params.get('host') ? decodeURIComponent(params.get('host')).split(',') : null;
					config.tcp_path = params.get('path') ? decodeURIComponent(params.get('path')).split(',') : null;
				}

				break;
			case 'ws':
				config.ws_host = config.tls !== '1' ? (params.get('host') ? decodeURIComponent(params.get('host')) : null) : null;
				config.ws_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
				if (config.ws_path && config.ws_path.includes('?ed=')) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = config.ws_path.split('?ed=')[1];
					config.ws_path = config.ws_path.split('?ed=')[0];
				}

				break;
			}

			break;
		case 'vmess':
			/* "Lovely" shadowrocket format */
			if (uri.includes('&'))
				return null;

			/* https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2) */
			uri = JSON.parse(hp.decodeBase64Str(uri[1]));

			if (uri.v !== '2')
				return null;
			/* https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6 */
			else if (uri.aid && parseInt(uri.aid) !== 0)
				return null;

			config = {
				label: uri.ps,
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
				config.grpc_servicename = uri.path;
				config.grpc_mode = 'gun';
				
				break;
			case 'h2':
				config.h2_host = uri.host ? uri.host.split(',') : null;
				config.h2_path = uri.path;

				break;
			case 'kcp':
				config.v2ray_transport = 'mkcp';
				config.mkcp_seed = uri.path;
				config.mkcp_header = uri.type || 'none';
				/* Default settings from v2rayN */
				config.mkcp_downlink_capacity = '100';
				config.mkcp_uplink_capacity = '12';
				config.mkcp_read_buffer_size = '2';
				config.mkcp_write_buffer_size = '2';
				config.mkcp_mtu = '1350';
				config.mkcp_tti = '50';

				break;
			case 'quic':
				config.quic_security = uri.host || 'none';
				config.quic_key = uri.path;
				config.mkcp_header = uri.type || 'none';

				break;
			case 'tcp':
				config.tcp_header = uri.type === "http" ? "http" : 'none';
				if (config.tcp_header === 'http') {
					config.tcp_host = uri.host ? uri.host.split(',') : null;
					config.tcp_path = uri.path ? uri.path.split(',') : null;
				}

				break;
			case 'ws':
				config.ws_host = config.tls !== '1' ? uri.host : null;
				config.ws_path = uri.path;
				if (config.ws_path && config.ws_path.includes('?ed=')) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = config.ws_path.split('?ed=')[1];
					config.ws_path = config.ws_path.split('?ed=')[0];
				}

				break;
			}

			break;
		}
	}

	if (config) {
		if (!config.address || !config.port)
			return null;
		else if (!config.label)
			config.label = config.address + ':' + config.port;
	}

	return config;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy')
		]);
	},

	render: function(data) {
		var m, s, o;

		var routing_mode = uci.get(data[0], 'config', 'routing_mode');

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
			_('Support Hysteria, Shadowsocks(R), Trojan, v2rayN (VMess), and XTLS (VLESS) online configuration delivery standard.'));
		o.validate = function(section_id, value) {
			if (section_id && value) {
				try {
					var url = new URL(value);
					if (!url.hostname)
						return _('Expecting: %s').format(_('valid URL'));
				}
				catch(e) {
					return _('Expecting: %s').format(_('valid URL'));
				}
			}

			return true;
		}

		o = s.option(form.ListValue, 'filter_nodes', _('Filter nodes'),
			_('Drop/keep specific nodes from subscriptions.'));
		o.value('disabled', _('Disable'));
		o.value('blacklist', _('Blacklist mode'));
		o.value('whitelist', _('Whitelist mode'));
		o.default = 'disabled';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'filter_keywords', _('Filter keywords'),
			_('Drop/keep nodes that contain the specific keywords. <a target="_blank" href="https://www.lua.org/pil/20.2.html">Regex</a> is supported.'));
		o.depends({'filter_nodes': 'disabled', '!reverse': true});
		o.rmempty = false;

		o = s.option(form.Flag, 'allow_insecure_in_subs', _('Allow insecure'),
			_('Allow insecure connection by default when add nodes form subscriptions.') +
			'<br/>' +
			_('This is <b>DANGEROUS</b>, your traffic is almost like <b>PLAIN TEXT</b>! Use at your own risk!'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.option(form.ListValue, 'default_packet_encoding', _('Default packet encoding'));
		o.value('none', _('None'));
		o.value('packet', _('packet (v2ray-core v5+)'));
		o.value('xudp', _('Xudp (Xray-core)'));
		o.default = 'xudp';
		o.rmempty = false;

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
				return _('Update %s %s').format(sublist.length, sublist.length === 1 ? _('subscription') : _('subscriptions'));
			else {
				this.readonly = true;
				return _('No subscription available')
			}
		}
		o.onclick = function() {
			return fs.exec('/etc/homeproxy/scripts/update_subscribe.lua').then((res) => {
				return location.reload();
			}).catch((err) => {
				ui.addNotification(null, E('p', _('An error occurred during updating subscriptions: %s').format(err)));
				return this.map.reset();
			});
		}

		o = s.option(form.Button, '_remove_subscriptions', _('Remove all nodes from subscriptions'));
		o.inputstyle = 'reset';
		o.inputtitle = function() {
			var subnodes = [];
			uci.sections(data[0], 'node', (res) => {
				if (res.grouphash)
					subnodes = subnodes.concat(res['.name'])
			});

			if (subnodes.length > 0) {
				return _('Remove %s %s').format(subnodes.length, subnodes.length === 1 ? _('node') : _('nodes'));
			} else {
				this.readonly = true;
				return _('No subscription node');
			}
		}
		o.onclick = function() {
			var subnodes = [];
			uci.sections(data[0], 'node', (res) => {
				if (res.grouphash)
					subnodes = subnodes.concat(res['.name'])
			});

			for (var i in subnodes)
				uci.remove(data[0], subnodes[i]);

			if (subnodes.includes(uci.get(data[0], 'config', 'main_server')))
				uci.set(data[0], 'config', 'main_server', 'nil');

			if (subnodes.includes(uci.get(data[0], 'config', 'main_udp_server')))
				uci.set(data[0], 'config', 'main_udp_server', 'nil');

			this.inputtitle = _('%s %s removed').format(subnodes.length, subnodes.length === 1 ? _('node') : _('nodes'));
			this.readonly = true;

			return this.map.save(null, true);
		}

		s = m.section(form.GridSection, 'node');
		s.addremove = true;
		s.sortable = true;
		s.nodescriptions = true;
		s.modaltitle = L.bind(hp.loadModalTitle, this, _('Node'), _('Add a node'), data[0]);
		s.sectiontitle = L.bind(hp.loadDefaultLabel, this, data[0]);

		/* Import subscription links start */
		/* Thanks to luci-app-shadowsocks-libev */
		s.handleLinkImport = function() {
			var textarea = new ui.Textarea();
			ui.showModal(_('Import share links'), [
				E('p', _('Support Hysteria, Shadowsocks(R), Trojan, v2rayN (VMess), and XTLS (VLESS) online configuration delivery standard.')),
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

								var allow_insecure = uci.get(data[0], 'subscription', 'allow_insecure_in_subs') || '0';
								var packet_encoding = uci.get(data[0], 'subscription', 'default_packet_encoding') || 'xudp';
								var imported_node = 0;
								input_links.forEach((s) => {
									var config = parse_share_link(s);
									if (config) {
										if (config.tls === '1')
											config.tls_insecure = allow_insecure
										if (config.type === 'v2ray' && ['vless', 'vmess'].includes(config.v2ray_protocol))
											config.v2ray_packet_encoding = packet_encoding

										var nameHash = hp.calcStringMD5(config.label);
										var sid = uci.add(data[0], 'node', nameHash);
										Object.keys(config).forEach((k) => {
											uci.set(data[0], sid, k, config[k]);
										});
										imported_node++;
									}
								});

								if (imported_node === 0)
									ui.addNotification(null, E('p', _('No valid share link found.')));
								else
									ui.addNotification(null, E('p', _('Successfully imported %s %s of total %s.').format(
										imported_node, imported_node === 1 ? _('node') : _('nodes'), input_links.length)));

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
			var el = form.GridSection.prototype.renderSectionAdd.apply(this, arguments),
				nameEl = el.querySelector('.cbi-section-create-name');

			ui.addValidator(nameEl, 'uciname', true, (v) => {
				var button = el.querySelector('.cbi-section-create > .cbi-button-add');
				var uciconfig = this.uciconfig || this.map.config;

				if (!v) {
					button.disabled = true;
					return true;
				} else if (uci.get(uciconfig, v)) {
					button.disabled = true;
					return _('Expecting: %s').format(_('unique UCI identifier'));
				} else {
					button.disabled = null;
					return true;
				}
			}, 'blur', 'keyup');

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
			if (routing_mode === 'custom')
				this.readonly = true;
			else {
				var main_server = uci.get(data[0], 'config', 'main_server');
				if (main_server == section_id) {
					this.readonly = true;
					return _('Applied');
				} else {
					this.readonly = false;
					return _('Apply');
				}
			}
		}
		o.onclick = function(ev, section_id) {
			uci.set(data[0], 'config', 'main_server', section_id);
			ui.changes.apply(true);

			return this.map.save(null, true);
		}

		o = s.option(form.Value, 'label', _('Label'));
		o.load = L.bind(hp.loadDefaultLabel, this, data[0]);
		o.validate = L.bind(hp.validateUniqueValue, this, data[0], 'node', 'label');
		o.modalonly = true;

		o = s.option(form.ListValue, 'type', _('Type'));
		o.value('direct', _('Direct'));
		o.value('http', _('HTTP'));
		o.value('hysteria', _('Hysteria'));
		o.value('shadowsocks', _('Shadowsocks'));
		o.value('shadowsocksr', _('ShadowsocksR'));
		o.value('socks', _('Socks'));
		o.value('trojan', _('Trojan'));
		o.value('v2ray', _('V2ray'));
		o.value('wireguard', _('WireGuard'));
		o.value('vmess', _('VMess'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'v2ray_protocol', _('V2ray protocol'));
		o.value('http', _('HTTP'));
		o.value('shadowsocks', _('Shadowsocks'));
		o.value('socks', _('Socks'));
		o.value('trojan', _('Trojan'));
		o.value('vless', _('VLESS'));
		o.value('vmess', _('VMess'));
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
		o.depends('type', 'socks');
		o.depends('v2ray_protocol', 'http');
		o.depends('v2ray_protocol', 'socks');
		o.modalonly = true;

		o = s.option(form.Value, 'password', _('Password'));
		o.password = true;
		o.depends('type', 'http');
		o.depends('type', 'shadowsocks');
		o.depends('type', 'shadowsocksr');
		o.depends('type', 'trojan');
		o.depends({'type': 'socks', 'socks_version': '5'});
		o.depends('v2ray_protocol', 'http');
		o.depends('v2ray_protocol', 'shadowsocks');
		o.depends('v2ray_protocol', 'trojan');
		o.depends({'v2ray_protocol': 'socks', 'socks_version': '5'});
		o.validate = function(section_id, value) {
			if (section_id) {
				var type = this.map.lookupOption('type', section_id)[0].formvalue(section_id);
				var v2ray_type = this.map.lookupOption('v2ray_protocol', section_id)[0].formvalue(section_id) || '';

				var required_type = [ 'shadowsocks', 'shadowsocksr', 'trojan' ];
				if (required_type.includes(type) || required_type.includes(v2ray_type)) {
					if (!value)
						return _('Expecting: %s').format(_('non-empty value'));
					else if (type === 'shadowsocks') {
						var encmode = this.map.lookupOption('shadowsocks_encrypt_method', section_id)[0].formvalue(section_id);
						if (encmode === '2022-blake3-aes-128-gcm' && value.length !== 16)
							return _('Expecting: %s').format(_('password with %d characters')).format(16);
						else if (['2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'].includes(encmode) && value.length !== 32)
							return _('Expecting: %s').format(_('password with %d characters')).format(32);
					}
				}
			}

			return true;
		}
		o.modalonly = true;

		/* Direct config */
		o = s.option(form.ListValue, 'proxy_protocol', _('Proxy protocol'),
			_('Write Proxy Protocol in the connection header.'));
		o.value('', _('Disable'));
		o.value('1');
		o.value('2');
		o.depends('type', 'direct');
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

		o = s.option(form.Value, 'hysteria_revc_window', _('QUIC connection receive window'),
			_('The QUIC connection-level flow control window for receiving data.'));
		o.datatype = 'uinteger';
		o.default = '15728640';
		o.depends('type', 'hysteria');
		o.modalonly = true;

		o = s.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable Path MTU discovery'),
			_('Disables Path MTU Discovery (RFC 8899). Packets will then be at most 1252 (IPv4) / 1232 (IPv6) bytes in size.'));
		o.default = o.disabled;
		o.depends('type', 'hysteria');
		o.rmempty = false;
		o.modalonly = true;
		/* Hysteria config end */

		/* Shadowsocks config start */
		o = s.option(form.ListValue, 'shadowsocks_encrypt_method', _('Encrypt method'));
		for (var i of hp.shadowsocks_encrypt_methods)
			o.value(i);
		o.default = 'aes-128-gcm';
		o.depends('type', 'shadowsocks');
		o.depends('v2ray_protocol', 'shadowsocks');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'shadowsocks_ivcheck', _('Bloom filter'));
		o.default = o.disabled;
		o.depends('v2ray_protocol', 'shadowsocks');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocks_plugin', _('Plugin'));
		o.value('obfs-local');
		o.value('v2ray-plugin');
		o.depends('type', 'shadowsocks');
		o.depends('v2ray_protocol', 'shadowsocks');
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocks_plugin_opts', _('Plugin opts'));
		o.depends({'shadowsocks_plugin': null, '!reverse': true});
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
		o.depends('type', 'shadowsocksr');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocksr_protocol_param', _('Protocol param'));
		o.depends('type', 'shadowsocksr');
		o.modalonly = true;

		o = s.option(form.ListValue, 'shadowsocksr_obfs', _('Obfs'));
		o.value('plain');
		o.value('http_simple');
		o.value('http_post');
		o.value('random_head');
		o.value('tls1.2_ticket_auth');
		o.depends('type', 'shadowsocksr');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocksr_obfs_param', _('Obfs param'));
		o.depends('type', 'shadowsocksr');
		o.modalonly = true;
		/* ShadowsocksR config end */

		/* Socks config start */
		o = s.option(form.ListValue, 'socks_version', _('Socks version'));
		o.value('4', _('Socks4'));
		o.value('4a', _('Socks4A'));
		o.value('5', _('Socks5'));
		o.default = '5';
		o.depends('type', 'socks');
		o.depends('v2ray_protocol', 'socks');
		o.rmempty = false;
		o.modalonly = true;
		/* Socks config end */

		/* VMess config start */
		o = s.option(form.Value, 'v2ray_uuid', _('UUID'));
		o.depends('type', 'vmess');
		o.depends('v2ray_protocol', 'vless');
		o.depends('v2ray_protocol', 'vmess');
		o.validate = function(section_id, value) {
			if (section_id) {
				if (!value)
					return _('Expecting: %s').format(_('non-empty value'));
				else if (value.match('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') === null)
					return _('Expecting: %s').format(_('valid uuid'));
			}

			return true;
		}
		o.modalonly = true;

		o = s.option(form.Value, 'v2ray_vless_encrypt', _('Encrypt method'));
		o.default = 'none';
		o.depends('v2ray_protocol', 'vless');
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
		o.depends('v2ray_protocol', 'vmess');
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

		o = s.option(form.Flag, 'vmess_packet_addr', _('Packet encoding support'));
		o.default = o.enabled;
		o.depends('type', 'vmess');
		o.rmempty = false;
		o.modalonly = true;
		/* VMess config end */

		/* Transport config */
		o = s.option(form.ListValue, 'transport', _('Transport'),
			_('No TCP transport, plain HTTP is merged into the HTTP transport.'));
		o.value('', _('None'));
		o.value('grpc', _('gRPC'));
		o.value('http', _('HTTP'));
		o.value('quic', _('QUIC'));
		o.value('ws', _('WebSocket'));
		o.onchange = function(ev, section_id, value) {
			var desc = this.map.findElement('id', 'cbid.homeproxy.%s.transport'.format(section_id)).nextElementSibling;
			if (value === 'http')
				desc.innerHTML = _('TLS is not enforced. If TLS is not configured, plain HTTP 1.1 is used.');
			else if (value === 'quic')
				desc.innerHTML = _('No additional encryption support: It\'s basically duplicate encryption.');
			else
				desc.innerHTML = _('No TCP transport, plain HTTP is merged into the HTTP transport.');
		}
		o.depends('type', 'trojan');
		o.depends('type', 'vmess');
		o.modalonly = true;

		/* V2ray config start */
		o = s.option(form.ListValue, 'v2ray_transport', _('Transport'));
		o.value('grpc', _('gRPC'));
		o.value('h2', _('HTTP/2'));
		o.value('mkcp', _('mKCP'));
		o.value('quic', _('QUIC'));
		o.value('tcp', _('TCP'));
		o.value('ws', _('WebSocket'));
		o.default = 'tcp';
		for (var i of hp.v2ray_native_protocols)
			o.depends('v2ray_protocol', i);
		o.modalonly = true;

		/* gRPC config start */
		o = s.option(form.Value, 'grpc_servicename', _('gRPC service name'));
		o.depends('transport', 'grpc');
		o.depends('v2ray_transport', 'grpc');
		o.modalonly = true;

		o = s.option(form.ListValue, 'grpc_mode', _('gRPC mode'));
		o.value('gun');
		o.value('multi');
		o.value('raw');
		o.depends('v2ray_transport', 'grpc');
		o.modalonly = true;

		o = s.option(form.Flag, 'grpc_health_check', _('Health check'));
		o.default = o.disabled;
		o.depends('v2ray_transport', 'grpc');
		o.modalonly = true;

		o = s.option(form.Flag, 'grpc_health_check_timeout', _('Health check timeout'));
		o.datatype = 'uintger';
		o.default = '20';
		o.depends('grpc_health_check', '1');
		o.modalonly = true;

		o = s.option(form.Value, 'grpc_idle_timeout', _('Idle timeout'));
		o.datatype = 'uinteger';
		o.default = '60';
		o.depends('v2ray_transport', 'grpc');
		o.modalonly = true;

		o = s.option(form.Flag, 'grpc_permit_without_stream', _('Permit without stream'));
		o.default = o.disabled;
		o.depends('v2ray_transport', 'grpc');
		o.modalonly = true;

		o = s.option(form.Flag, 'grpc_health_check', _('Health check'));
		o.depends('v2ray_transport', 'grpc');
		o.modalonly = true;
		/* gRPC config end */

		/* HTTP/2 config start */
		o = s.option(form.DynamicList, 'h2_host', _('Host'));
		o.datatype = 'hostname';
		o.depends('transport', 'http');
		o.depends('v2ray_transport', 'h2');
		o.modalonly = true;

		o = s.option(form.Value, 'h2_path', _('Path'));
		o.depends('transport', 'http');
		o.depends('v2ray_transport', 'h2');
		o.modalonly = true;

		o = s.option(form.Value, 'h2_method', _('Method'));
		o.value('get', _('GET'));
		o.value('put', _('PUT'));
		o.depends('transport', 'http');
		o.depends('v2ray_transport', 'h2');
		o.modalonly = true;
		/* HTTP/2 config end */

		/* mKCP config start */
		o = s.option(form.Value, 'mkcp_seed', _('mKCP seed'));
		o.depends('v2ray_transport', 'mkcp');
		o.modalonly = true;

		o = s.option(form.Flag, 'mkcp_congestion', _('Congestion'));
		o.default = o.disabled;
		o.depends('v2ray_transport', 'mkcp');
		o.modalonly = true;

		o = s.option(form.ListValue, 'mkcp_header', _('Header type'));
		o.value('none', _('None'));
		o.value('dtls', _('DTLS 1.2'));
		o.value('srtp', _('Video call (SRTP)'));
		o.value('utp', _('BitTorrent (utp)'));
		o.value('wechat-video', _('Wechat video call'));
		o.value('wireguard', _('WireGuard'));
		o.depends('v2ray_transport', 'mkcp');
		o.depends('v2ray_transport', 'quic');
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_downlink_capacity', _('Downlink capacity'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.depends('v2ray_transport', 'mkcp');
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_uplink_capacity', _('Uplink capacity'));
		o.datatype = 'uinteger';
		o.depends('type', 'hysteria');
		o.depends('v2ray_transport', 'mkcp');
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_read_buffer_size', _('Read buffer size'));
		o.datatype = 'uinteger';
		o.depends('v2ray_transport', 'mkcp');
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_write_buffer_size', _('Write buffer size'));
		o.datatype = 'uinteger';
		o.depends('v2ray_transport', 'mkcp');
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_mtu', _('MTU'));
		o.datatype = 'range(0,9000)';
		o.depends('type', 'wireguard');
		o.depends('v2ray_transport', 'mkcp');
		o.modalonly = true;

		o = s.option(form.Value, 'mkcp_tti', _('TTI'));
		o.datatype = 'uinteger';
		o.depends('v2ray_transport', 'mkcp');
		o.modalonly = true;
		/* mKCP config end */

		/* QUIC config start */
		o = s.option(form.ListValue, 'quic_security', _('QUIC security'));
		o.value('none');
		o.value('aes-128-gcm');
		o.value('chacha20-poly1305');
		o.depends('v2ray_transport', 'quic');
		o.modalonly = true;

		o = s.option(form.Value, 'quic_key', _('QUIC key'));
		o.password = true;
		o.depends('v2ray_transport', 'quic');
		o.modalonly = true;
		/* QUIC config end */

		/* TCP config start */
		o = s.option(form.ListValue, 'tcp_header', _('Header type'));
		o.value('none');
		o.value('http');
		o.default = 'none';
		o.depends('v2ray_transport', 'tcp');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.DynamicList, 'tcp_host', _('Host'));
		o.datatype = 'hostname';
		o.depends({'v2ray_transport': 'tcp', 'tcp_header': 'http'});
		o.modalonly = true;

		o = s.option(form.DynamicList, 'tcp_path', _('Path'));
		o.depends({'v2ray_transport': 'tcp', 'tcp_header': 'http'});
		o.modalonly = true;
		/* TCP config end */

		/* WebSocket config start */
		o = s.option(form.Value, 'ws_host', _('Host'));
		o.depends('transport', 'ws');
		o.depends('v2ray_transport', 'ws');
		o.modalonly = true;

		o = s.option(form.Value, 'ws_path', _('Path'));
		o.depends('transport', 'ws');
		o.depends('v2ray_transport', 'ws');
		o.modalonly = true;

		o = s.option(form.Value, 'websocket_early_data', _('Early data'),
			_('Allowed payload size is in the request.'));
		o.datatype = 'uinteger';
		o.default = '2048';
		o.depends('transport', 'ws');
		o.depends('v2ray_transport', 'ws');
		o.modalonly = true;

		o = s.option(form.Value, 'websocket_early_data_header', _('Early data header name'));
		o.default = 'Sec-WebSocket-Protocol';
		o.depends('transport', 'ws');
		o.depends('v2ray_transport', 'ws');
		o.modalonly = true;
		/* WebSocket config end */

		/* XTLS config start */
		o = s.option(form.Flag, 'v2ray_xtls', _('XTLS'));
		o.default = o.disabled;
		o.depends({'v2ray_protocol': /^(trojan|vless)$/, 'v2ray_transport': /^(tcp|mkcp)$/, 'multiplex': '0', 'tls': '0'});
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

		o = s.option(form.ListValue, 'v2ray_packet_encoding', _('Packet encoding'));
		o.value('none', _('None'));
		o.value('packet', _('packet (v2ray-core v5+)'));
		o.value('xudp', _('Xudp (Xray-core)'));
		o.default = 'xudp';
		o.depends('v2ray_protocol', 'vless');
		o.depends('v2ray_protocol', 'vmess');
		o.rmempty = false;
		o.modalonly = true;
		/* V2ray config end */

		/* Wireguard config start */
		o = s.option(form.DynamicList, 'wireguard_local_address', _('Local address'),
			_('List of IP (v4 or v6) addresses prefixes to be assigned to the interface.'));
		o.datatype = 'cidr';
		o.depends('type', 'wireguard');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'wireguard_private_key', _('Private key'),
			_('WireGuard requires base64-encoded private keys.'));
		o.password = true;
		o.depends('type', 'wireguard');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'wireguard_peer_public_key', _('Peer pubkic key'),
			_('WireGuard peer public key.'));
		o.depends('type', 'wireguard');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'wireguard_pre_shared_key', _('Pre-shared key'),
			_('WireGuard pre-shared key.'));
		o.password = true;
		o.depends('type', 'wireguard');
		o.rmempty = false;
		o.modalonly = true;
		/* Wireguard config end */

		/* Mux config start */
		o = s.option(form.Flag, 'multiplex', _('Multiplex'));
		o.default = o.disabled;
		o.depends('type', 'shadowsocks');
		o.depends('type', 'trojan');
		o.depends('type', 'vmess');
		for (var i of hp.v2ray_native_protocols)
			o.depends('v2ray_protocol', i);
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'v2ray_concurrency', _('Concurrency'));
		o.datatype = 'range(0,1024)';
		o.default = '4';
		for (var i of hp.v2ray_native_protocols)
			o.depends({'v2ray_protocol': i, 'multiplex': '1'});
		o.rmempty = false;
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

		o = s.option(form.Value, 'multiplex_max_connections', _('Maximum connections'));
		o.datatype = 'uinteger';
		o.depends({'type': 'shadowsocks', 'multiplex': '1'});
		o.depends({'type': 'trojan', 'multiplex': '1'});
		o.depends({'type': 'vmess', 'multiplex': '1'});
		o.modalonly = true;

		o = s.option(form.Value, 'multiplex_min_streams', _('Minimum streams'),
			_('Minimum multiplexed streams in a connection before opening a new connection.'));
		o.datatype = 'uinteger';
		o.depends({'type': 'shadowsocks', 'multiplex': '1'});
		o.depends({'type': 'trojan', 'multiplex': '1'});
		o.depends({'type': 'vmess', 'multiplex': '1'});
		o.modalonly = true;

		o = s.option(form.Value, 'multiplex_max_streams', _('Maximum streams'),
			_('Maximum multiplexed streams in a connection before opening a new connection.<br/>' +
				'Conflict with <code>Maximum connections</code> and <code>Minimum streams</code>.'));
		o.datatype = 'uinteger';
		o.depends({'type': /^(shadowsocks|trojan|vmess)$/, 'multiplex': '1', 'multiplex_max_connections': '', 'multiplex_min_streams': ''});
		o.modalonly = true;
		/* Mux config end */

		/* TLS config start */
		o = s.option(form.Flag, 'tls', _('TLS'));
		o.default = o.disabled;
		o.depends('type', 'http');
		o.depends('type', 'trojan');
		o.depends('type', 'vmess');
		for (var i of hp.v2ray_native_protocols)
			o.depends('v2ray_protocol', i);
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
			_('Allow insecure connection at TLS client.') +
			'<br/>' +
			_('This is <b>DANGEROUS</b>, your traffic is almost like <b>PLAIN TEXT</b>! Use at your own risk!'));
		o.default = o.disabled;
		o.depends('type', 'hysteria');
		o.depends('tls', '1');
		o.depends('v2ray_xtls', '1');
		o.modalonly = true;

		o = s.option(form.ListValue, 'tls_min_version', _('Minimum TLS version'),
			_('The minimum TLS version that is acceptable.'));
		for (var i of hp.tls_versions)
			o.value(i);
		o.default = '1.2';
		o.depends({'type': 'http', 'tls': '1'});
		o.depends({'type': 'trojan', 'tls': '1'});
		o.depends({'type': 'vmess', 'tls': '1'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.ListValue, 'tls_max_version', _('Maximum TLS version'),
			_('The maximum TLS version that is acceptable.'));
		for (var i of hp.tls_versions)
			o.value(i);
		o.default = '1.3';
		o.depends({'type': 'http', 'tls': '1'});
		o.depends({'type': 'trojan', 'tls': '1'});
		o.depends({'type': 'vmess', 'tls': '1'});
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.MultiValue, 'tls_cipher_suites', _('Cipher suites'),
			_('The elliptic curves that will be used in an ECDHE handshake, in preference order. If empty, the default will be used.'));
		for (var i of hp.tls_cipher_suites)
			o.value(i);
		o.depends({'type': 'http', 'tls': '1'});
		o.depends({'type': 'trojan', 'tls': '1'});
		o.depends({'type': 'vmess', 'tls': '1'});
		o.optional = true;
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_self_sign', _('Append self-signed certificate'),
			_('If you have the root certificate, use this option instead of allowing insecure.'));
		o.default = o.disabled;
		o.depends('tls_insecure', '0');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'tls_cert_path', _('Certificate path'),
			_('The path to the server certificate, in PEM format.'));
		o.value('/etc/homeproxy/certs/client_ca.pem');
		o.depends('tls_self_sign', '1');
		o.modalonly = true;

		o = s.option(form.Button, '_upload_cert', _('Upload certificate'),
			_('<strong>Save your configuration before uploading files!</strong>'));
		o.inputstyle = 'action';
		o.inputtitle = _('Upload...');
		o.depends({'tls_self_sign': '1', 'tls_cert_path': '/etc/homeproxy/certs/client_ca.pem'});
		o.onclick = L.bind(hp.uploadCertificate, this, o, _('certificate'), 'client_ca');
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_ech', _('Enable ECH'),
			_('ECH (Encrypted Client Hello) is a TLS extension that allows a client to encrypt the first part of its ClientHello message.'));
		o.depends({'type': 'http', 'tls': '1'});
		o.depends({'type': 'trojan', 'tls': '1'});
		o.depends({'type': 'vmess', 'tls': '1'});
		o.default = o.disabled;
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_ech_tls_enable_drs', _('Enable dynamic record sizing'));
		o.depends('tls_ech', '1');
		o.default = o.enabled;
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_ech_enable_pqss', _('Enable PQ signature schemes'));
		o.depends('tls_ech', '1');
		o.default = o.disabled;
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'tls_ech_config', _('ECH config'));
		o.depends('tls_ech', '1');
		o.modalonly = true;

		o = s.option(form.ListValue, 'tls_utls', _('uTLS fingerprint'),
			_('uTLS is a fork of "crypto/tls", which provides ClientHello fingerprinting resistance.'));
		o.value('', _('Disable'));
		o.value('android', _('Android'));
		o.value('chrome', _('Chrome'));
		o.value('firefox', _('Firefox'));
		o.value('ios', _('iOS'));
		o.value('random', _('Random'));
		o.depends({'type': 'http', 'tls': '1'});
		o.depends({'type': 'trojan', 'tls': '1'});
		o.depends({'type': 'vmess', 'tls': '1'});
		o.modalonly = true;
		/* TLS config end */

		/* Extra settings start */
		o = s.option(form.Flag, 'tcp_fast_open', _('TCP fast open'));
		o.default = o.disabled;
		for (var i of hp.native_protocols)
			o.depends('type', i)
		for (var i of hp.v2ray_native_protocols)
			o.depends('v2ray_protocol', i);
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'udp_fragment', _('UDP Fragment'),
			_('Enable UDP fragmentation.'));
		o.default = o.disabled;
		for (var i of hp.native_protocols)
			o.depends('type', i)
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Flag, 'udp_over_tcp', _('UDP over TCP'),
			_('Enable the SUoT protocol, requires server support. Conflict with multiplex.'));
		o.default = o.disabled;
		o.depends('type', 'socks');
		o.depends({'type': 'shadowsocks', 'multiplex': '0'});
		o.depends({'v2ray_protocol': 'shadowsocks', 'multiplex': '0'});
		o.rmempty = false;
		o.modalonly = true;
		/* Extra settings end */

		return m.render();
	}
});
