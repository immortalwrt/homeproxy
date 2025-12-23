#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023 ImmortalWrt.org
 */

'use strict';

import { md5 } from 'digest';
import { open } from 'fs';
import { connect } from 'ubus';
import { cursor } from 'uci';

import { urldecode, urlencode } from 'luci.http';
import { init_action } from 'luci.sys';

import {
	wGET, decodeBase64Str, getTime, isEmpty, parseURL,
	validation, HP_DIR, RUN_DIR
} from 'homeproxy';

/* UCI config start */
const uci = cursor();

const uciconfig = 'homeproxy';
uci.load(uciconfig);

const ucimain = 'config',
      ucinode = 'node',
      ucisubscription = 'subscription';

const allow_insecure = uci.get(uciconfig, ucisubscription, 'allow_insecure') || '0',
      filter_mode = uci.get(uciconfig, ucisubscription, 'filter_nodes') || 'disabled',
      filter_keywords = uci.get(uciconfig, ucisubscription, 'filter_keywords') || [],
      packet_encoding = uci.get(uciconfig, ucisubscription, 'packet_encoding') || 'xudp',
      subscription_urls = uci.get(uciconfig, ucisubscription, 'subscription_url') || [],
      user_agent = uci.get(uciconfig, ucisubscription, 'user_agent'),
      via_proxy = uci.get(uciconfig, ucisubscription, 'update_via_proxy') || '0';

const routing_mode = uci.get(uciconfig, ucimain, 'routing_mode') || 'bypass_mainalnd_china';
let main_node, main_udp_node;
if (routing_mode !== 'custom') {
	main_node = uci.get(uciconfig, ucimain, 'main_node') || 'nil';
	main_udp_node = uci.get(uciconfig, ucimain, 'main_udp_node') || 'nil';
}
/* UCI config end */

/* String helper start */
function filter_check(name) {
	if (isEmpty(name) || filter_mode === 'disabled' || isEmpty(filter_keywords))
		return false;

	let ret = false;
	for (let i in filter_keywords) {
		const patten = regexp(i);
		if (match(name, patten))
			ret = true;
	}
	if (filter_mode === 'whitelist')
		ret = !ret;

	return ret;
}
/* String helper end */

/* Common var start */
const node_cache = {},
      node_result = [];

const ubus = connect();
const sing_features = ubus.call('luci.homeproxy', 'singbox_get_features', {}) || {};
/* Common var end */

/* Log */
system(`mkdir -p ${RUN_DIR}`);
function log(...args) {
	const logfile = open(`${RUN_DIR}/homeproxy.log`, 'a');
	logfile.write(`${getTime()} [SUBSCRIBE] ${join(' ', args)}\n`);
	logfile.close();
}

function has_value(value) {
	return value !== null && value !== '' && value !== 'nil';
}

function to_string(value) {
	return has_value(value) ? sprintf('%s', value) : null;
}

function bool_to_uci(value) {
	if (value === true)
		return '1';
	if (value === false)
		return '0';
	return null;
}

function normalize_list(value) {
	if (!has_value(value))
		return null;
	if (type(value) === 'array')
		return value;
	return [to_string(value)];
}

function normalize_host_list(value) {
	if (!has_value(value))
		return null;
	if (type(value) === 'array')
		return value;
	return split(to_string(value), ',');
}

function normalize_first(value) {
	if (!has_value(value))
		return null;
	if (type(value) === 'array')
		return length(value) ? value[0] : null;
	return to_string(value);
}

function normalize_hysteria_hopping_port(mport) {
	if (!has_value(mport))
		return null;

	let ports = [];
	for (let p in split(to_string(mport), ',')) {
		p = trim(p);
		if (!p)
			continue;
		if (match(p, /^\d+$/))
			p = p + ':' + p;
		else
			p = replace(p, '-', ':');
		push(ports, p);
	}

	return length(ports) ? ports : null;
}

function normalize_mihomo_ports(ports) {
	if (!has_value(ports))
		return null;

	if (type(ports) === 'array')
		return map(ports, (p) => {
			const v = to_string(p);
			if (match(v, /^\d+$/))
				return v + ':' + v;
			return replace(v, '-', ':');
		});

	return normalize_hysteria_hopping_port(to_string(ports));
}

function parse_mihomo_speed(value) {
	if (!has_value(value))
		return null;

	const str = to_string(value);
	const match_val = match(str, /[0-9]+(\.[0-9]+)?/);
	if (!match_val)
		return null;

	const num_str = type(match_val) === 'array' ? match_val[0] : match_val;
	if (!num_str)
		return null;

	const num = int(num_str);
	if (num === null || num != num)
		return null;

	return to_string(num);
}

function get_header_host(headers) {
	if (type(headers) !== 'object')
		return null;

	return headers.Host || headers.host || headers['HOST'];
}

function apply_transport_opts(config, proxy) {
	const network = proxy.network;
	if (!has_value(network) || network === 'tcp')
		return;

	let ws_opts = proxy['ws-opts'] || {};
	let grpc_opts = proxy['grpc-opts'] || {};
	let http_opts = proxy['http-opts'] || proxy['h2-opts'] || {};
	let httpupgrade_opts = proxy['http-upgrade-opts'] || {};

	switch (network) {
	case 'ws':
		config.transport = 'ws';
		config.ws_path = ws_opts.path ? to_string(ws_opts.path) : null;
		config.ws_host = get_header_host(ws_opts.headers);
		config.websocket_early_data = ws_opts['early-data'] ? to_string(ws_opts['early-data']) : null;
		config.websocket_early_data_header = ws_opts['early-data-header-name'] ?
			to_string(ws_opts['early-data-header-name']) : null;
		break;
	case 'grpc':
		config.transport = 'grpc';
		config.grpc_servicename = to_string(grpc_opts['grpc-service-name'] || grpc_opts['service-name']);
		break;
	case 'http':
	case 'h2':
		config.transport = 'http';
		config.http_path = normalize_first(http_opts.path);
		config.http_host = normalize_host_list(get_header_host(http_opts.headers) || http_opts.host);
		break;
	case 'httpupgrade':
		config.transport = 'httpupgrade';
		config.httpupgrade_host = get_header_host(httpupgrade_opts.headers) || httpupgrade_opts.host;
		config.http_path = normalize_first(httpupgrade_opts.path);
		break;
	}
}

function parse_mihomo_proxy(proxy) {
	if (type(proxy) !== 'object')
		return null;

	let config;
	const tls_sni = proxy.servername || proxy.sni;
	const tls_fingerprint = proxy['client-fingerprint'] || proxy.fingerprint;

	switch (proxy.type) {
	case 'vmess':
		config = {
			label: proxy.name,
			type: 'vmess',
			address: proxy.server,
			port: to_string(proxy.port),
			uuid: proxy.uuid,
			vmess_alterid: has_value(proxy.alterId) ? to_string(proxy.alterId) : null,
			vmess_encrypt: proxy.cipher,
			packet_encoding: proxy['packet-encoding'],
			tls: (proxy.tls === true) ? '1' : '0',
			tls_sni,
			tls_alpn: normalize_list(proxy.alpn),
			tls_insecure: bool_to_uci(proxy['skip-cert-verify']),
			tls_utls: sing_features.with_utls ? tls_fingerprint : null,
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		apply_transport_opts(config, proxy);
		break;
	case 'hysteria2':
		if (!sing_features.with_quic) {
			log(sprintf('Skipping unsupported %s node: %s.', proxy.type, proxy.name || proxy.server));
			log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));
			return null;
		}
		config = {
			label: proxy.name,
			type: 'hysteria2',
			address: proxy.server,
			port: to_string(proxy.port),
			password: proxy.password,
			hysteria_hopping_port: normalize_mihomo_ports(proxy.ports),
			hysteria_down_mbps: parse_mihomo_speed(proxy.down),
			hysteria_up_mbps: parse_mihomo_speed(proxy.up),
			hysteria_obfs_type: proxy.obfs,
			hysteria_obfs_password: proxy['obfs-password'],
			tls: '1',
			tls_sni,
			tls_alpn: normalize_list(proxy.alpn),
			tls_insecure: bool_to_uci(proxy['skip-cert-verify']),
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		break;
	case 'hysteria':
		if (!sing_features.with_quic) {
			log(sprintf('Skipping unsupported %s node: %s.', proxy.type, proxy.name || proxy.server));
			log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));
			return null;
		}
		config = {
			label: proxy.name,
			type: 'hysteria',
			address: proxy.server,
			port: to_string(proxy.port),
			hysteria_hopping_port: normalize_mihomo_ports(proxy.ports),
			hysteria_protocol: proxy.protocol,
			hysteria_auth_type: proxy['auth-str'] ? 'string' : (proxy.auth ? 'base64' : null),
			hysteria_auth_payload: proxy['auth-str'] || proxy.auth,
			hysteria_obfs_password: proxy.obfs,
			hysteria_down_mbps: parse_mihomo_speed(proxy.down),
			hysteria_up_mbps: parse_mihomo_speed(proxy.up),
			tls: '1',
			tls_sni,
			tls_alpn: normalize_list(proxy.alpn),
			tls_insecure: bool_to_uci(proxy['skip-cert-verify']),
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		break;
	case 'vless':
		config = {
			label: proxy.name,
			type: 'vless',
			address: proxy.server,
			port: to_string(proxy.port),
			uuid: proxy.uuid,
			vless_flow: proxy.flow,
			packet_encoding: proxy['packet-encoding'],
			tls: (proxy.tls === true || proxy['reality-opts']) ? '1' : '0',
			tls_sni,
			tls_insecure: bool_to_uci(proxy['skip-cert-verify']),
			tls_utls: sing_features.with_utls ? tls_fingerprint : null,
			tls_reality: proxy['reality-opts'] ? '1' : '0',
			tls_reality_public_key: proxy['reality-opts'] ? proxy['reality-opts']['public-key'] : null,
			tls_reality_short_id: proxy['reality-opts'] ? proxy['reality-opts']['short-id'] : null,
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		apply_transport_opts(config, proxy);
		break;
	case 'trojan':
		config = {
			label: proxy.name,
			type: 'trojan',
			address: proxy.server,
			port: to_string(proxy.port),
			password: proxy.password,
			tls: (proxy.tls === false) ? '0' : '1',
			tls_sni,
			tls_alpn: normalize_list(proxy.alpn),
			tls_insecure: bool_to_uci(proxy['skip-cert-verify']),
			tls_utls: sing_features.with_utls ? tls_fingerprint : null,
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		apply_transport_opts(config, proxy);
		break;
	case 'ss': {
		let ss_plugin = proxy.plugin;
		if (ss_plugin === 'simple-obfs')
			ss_plugin = 'obfs-local';
		config = {
			label: proxy.name,
			type: 'shadowsocks',
			address: proxy.server,
			port: to_string(proxy.port),
			shadowsocks_encrypt_method: proxy.cipher,
			password: proxy.password,
			shadowsocks_plugin: ss_plugin,
			shadowsocks_plugin_opts: proxy['plugin-opts'],
			udp_over_tcp: bool_to_uci(proxy['udp-over-tcp']),
			udp_over_tcp_version: to_string(proxy['udp-over-tcp-version']),
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		break;
	}
	case 'ssr':
		log(sprintf('Skipping unsupported ssr node: %s.', proxy.name || proxy.server));
		return null;
	case 'socks5':
	case 'socks':
	case 'socks4':
	case 'socks4a':
		config = {
			label: proxy.name,
			type: 'socks',
			address: proxy.server,
			port: to_string(proxy.port),
			username: proxy.username,
			password: proxy.password,
			socks_version: (proxy.type === 'socks4a') ? '4a' : ((proxy.type === 'socks4') ? '4' : '5'),
			tls: (proxy.tls === true) ? '1' : '0',
			tls_sni,
			tls_insecure: bool_to_uci(proxy['skip-cert-verify']),
			tls_utls: sing_features.with_utls ? tls_fingerprint : null,
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		break;
	case 'http':
		config = {
			label: proxy.name,
			type: 'http',
			address: proxy.server,
			port: to_string(proxy.port),
			username: proxy.username,
			password: proxy.password,
			tls: (proxy.tls === true) ? '1' : '0',
			tls_sni,
			tls_insecure: bool_to_uci(proxy['skip-cert-verify']),
			tls_utls: sing_features.with_utls ? tls_fingerprint : null,
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		break;
	case 'tuic': {
		if (!sing_features.with_quic) {
			log(sprintf('Skipping unsupported %s node: %s.', proxy.type, proxy.name || proxy.server));
			log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));
			return null;
		}
		let tuic_heartbeat = proxy['heartbeat-interval'];
		if (has_value(tuic_heartbeat)) {
			tuic_heartbeat = int(tuic_heartbeat);
			if (tuic_heartbeat >= 1000)
				tuic_heartbeat = int(tuic_heartbeat / 1000);
		}
		config = {
			label: proxy.name,
			type: 'tuic',
			address: proxy.server,
			port: to_string(proxy.port),
			uuid: proxy.uuid,
			password: proxy.password || proxy.token,
			tuic_congestion_control: proxy['congestion-controller'],
			tuic_udp_relay_mode: proxy['udp-relay-mode'],
			tuic_udp_over_stream: bool_to_uci(proxy['udp-over-stream']),
			tuic_enable_zero_rtt: bool_to_uci(proxy['zero-rtt-handshake']),
			tuic_heartbeat: has_value(tuic_heartbeat) ? to_string(tuic_heartbeat) : null,
			tls: '1',
			tls_sni: proxy['disable-sni'] ? null : tls_sni,
			tls_alpn: normalize_list(proxy.alpn),
			tls_insecure: bool_to_uci(proxy['skip-cert-verify']),
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		break;
	}
	case 'ssh':
		config = {
			label: proxy.name,
			type: 'ssh',
			address: proxy.server,
			port: to_string(proxy.port),
			username: proxy.username,
			password: proxy.password,
			ssh_client_version: proxy['client-version'],
			ssh_host_key: normalize_list(proxy['host-key']),
			ssh_host_key_algo: normalize_list(proxy['host-key-algorithms']),
			ssh_priv_key: normalize_list(proxy['private-key']),
			ssh_priv_key_pp: proxy['private-key-passphrase'],
			tcp_fast_open: (proxy.tfo === true) ? '1' : null
		};
		break;
	case 'wireguard': {
		let wg_addresses = [];
		if (has_value(proxy.ip))
			push(wg_addresses, to_string(proxy.ip));
		if (has_value(proxy.ipv6))
			push(wg_addresses, to_string(proxy.ipv6));
		config = {
			label: proxy.name,
			type: 'wireguard',
			address: proxy.server,
			port: to_string(proxy.port),
			wireguard_local_address: length(wg_addresses) ? wg_addresses : null,
			wireguard_private_key: proxy['private-key'],
			wireguard_peer_public_key: proxy['public-key'],
			wireguard_pre_shared_key: proxy['pre-shared-key'],
			wireguard_reserved: normalize_list(proxy.reserved),
			wireguard_mtu: to_string(proxy.mtu),
			wireguard_persistent_keepalive_interval: to_string(proxy['persistent-keepalive'] || proxy['persistent-keepalive-interval'] || proxy.keepalive)
		};
		break;
	}
	default:
		return null;
	}

	return config;
}

function parse_uri(uri) {
	let config, url, params;

	if (type(uri) === 'object') {
		if (uri.nodetype === 'mihomo') {
			return parse_mihomo_proxy(uri);
		}
		if (uri.nodetype === 'sip008') {
			/* https://shadowsocks.org/guide/sip008.html */
			config = {
				label: uri.remarks,
				type: 'shadowsocks',
				address: uri.server,
				port: uri.server_port,
				shadowsocks_encrypt_method: uri.method,
				password: uri.password,
				shadowsocks_plugin: uri.plugin,
				shadowsocks_plugin_opts: uri.plugin_opts
			};
		}
	} else if (type(uri) === 'string') {
		uri = split(trim(uri), '://');

		switch (uri[0]) {
		case 'anytls':
			/* https://github.com/anytls/anytls-go/blob/v0.0.8/docs/uri_scheme.md */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'anytls',
				address: url.hostname,
				port: url.port,
				password: urldecode(url.username),
				tls: '1',
				tls_sni: params.sni,
				tls_insecure: (params.insecure === '1') ? '1' : '0'
			};

			break;
		case 'http':
		case 'https':
			url = parseURL('http://' + uri[1]) || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'http',
				address: url.hostname,
				port: url.port,
				username: url.username ? urldecode(url.username) : null,
				password: url.password ? urldecode(url.password) : null,
				tls: (uri[0] === 'https') ? '1' : '0'
			};

			break;
		case 'hysteria':
			/* https://github.com/HyNetwork/hysteria/wiki/URI-Scheme */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams;

			if (!sing_features.with_quic || (params.protocol && params.protocol !== 'udp')) {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				if (!sing_features.with_quic)
					log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));

				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'hysteria',
				address: url.hostname,
				port: url.port,
				hysteria_hopping_port: normalize_hysteria_hopping_port(params.mport),
				hysteria_protocol: params.protocol || 'udp',
				hysteria_auth_type: params.auth ? 'string' : null,
				hysteria_auth_payload: params.auth,
				hysteria_obfs_password: params.obfsParam,
				hysteria_down_mbps: params.downmbps,
				hysteria_up_mbps: params.upmbps,
				tls: '1',
				tls_insecure: (params.insecure in ['true', '1']) ? '1' : '0',
				tls_sni: params.peer,
				tls_alpn: params.alpn
			};

			break;
		case 'hysteria2':
		case 'hy2':
			/* https://v2.hysteria.network/docs/developers/URI-Scheme/ */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams;

			if (!sing_features.with_quic) {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));
				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'hysteria2',
				address: url.hostname,
				port: url.port,
				password: url.username ? (
					urldecode(url.username + (url.password ? (':' + url.password) : ''))
				) : null,
				hysteria_hopping_port: normalize_hysteria_hopping_port(params.mport),
				hysteria_obfs_type: params.obfs,
				hysteria_obfs_password: params['obfs-password'],
				tls: '1',
				tls_insecure: (params.insecure === '1') ? '1' : '0',
				tls_sni: params.sni
			};

			break;
		case 'socks':
		case 'socks4':
		case 'socks4a':
		case 'socsk5':
		case 'socks5h':
			url = parseURL('http://' + uri[1]) || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'socks',
				address: url.hostname,
				port: url.port,
				username: url.username ? urldecode(url.username) : null,
				password: url.password ? urldecode(url.password) : null,
				socks_version: (match(uri[0], /4/)) ? '4' : '5'
			};

			break;
		case 'ss':
			/* "Lovely" Shadowrocket format */
			const ss_suri = split(uri[1], '#');
			let ss_slabel = '';
			if (length(ss_suri) <= 2) {
				if (length(ss_suri) === 2)
					ss_slabel = '#' + urlencode(ss_suri[1]);
				if (decodeBase64Str(ss_suri[0]))
					uri[1] = decodeBase64Str(ss_suri[0]) + ss_slabel;
			}

			/* Legacy format is not supported, it should be never appeared in modern subscriptions */
			/* https://github.com/shadowsocks/shadowsocks-org/commit/78ca46cd6859a4e9475953ed34a2d301454f579e */

			/* SIP002 format https://shadowsocks.org/guide/sip002.html */
			url = parseURL('http://' + uri[1]) || {};

			let ss_userinfo = {};
			if (url.username && url.password)
				/* User info encoded with URIComponent */
				ss_userinfo = [url.username, urldecode(url.password)];
			else if (url.username)
				/* User info encoded with base64 */
				ss_userinfo = split(decodeBase64Str(urldecode(url.username)), ':', 2);

			let ss_plugin, ss_plugin_opts;
			if (url.search && url.searchParams.plugin) {
				const ss_plugin_info = split(url.searchParams.plugin, ';', 2);
				ss_plugin = ss_plugin_info[0];
				if (ss_plugin === 'simple-obfs')
					/* Fix non-standard plugin name */
					ss_plugin = 'obfs-local';
				ss_plugin_opts = ss_plugin_info[1];
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'shadowsocks',
				address: url.hostname,
				port: url.port,
				shadowsocks_encrypt_method: ss_userinfo[0],
				password: ss_userinfo[1],
				shadowsocks_plugin: ss_plugin,
				shadowsocks_plugin_opts: ss_plugin_opts
			};

			break;
		case 'trojan':
			/* https://p4gefau1t.github.io/trojan-go/developer/url/ */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'trojan',
				address: url.hostname,
				port: url.port,
				password: urldecode(url.username),
				transport: (params.type !== 'tcp') ? params.type : null,
				tls: '1',
				tls_sni: params.sni
			};
			switch(params.type) {
			case 'grpc':
				config.grpc_servicename = params.serviceName;
				break;
			case 'ws':
				config.ws_host = params.host ? urldecode(params.host) : null;
				config.ws_path = params.path ? urldecode(params.path) : null;
				if (config.ws_path && match(config.ws_path, /\?ed=/)) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = split(config.ws_path, '?ed=')[1];
					config.ws_path = split(config.ws_path, '?ed=')[0];
				}
				break;
			}

			break;
		case 'tuic':
			/* https://github.com/daeuniverse/dae/discussions/182 */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			if (!sing_features.with_quic) {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));

				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'tuic',
				address: url.hostname,
				port: url.port,
				uuid: url.username,
				password: url.password ? urldecode(url.password) : null,
				tuic_congestion_control: params.congestion_control,
				tuic_udp_relay_mode: params.udp_relay_mode,
				tls: '1',
				tls_sni: params.sni,
				tls_alpn: params.alpn ? split(urldecode(params.alpn), ',') : null,
			};

			break;
		case 'vless':
			/* https://github.com/XTLS/Xray-core/discussions/716 */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams;

			/* Unsupported protocol */
			if (params.type === 'kcp') {
				log(sprintf('Skipping sunsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				return null;
			} else if (params.type === 'quic' && ((params.quicSecurity && params.quicSecurity !== 'none') || !sing_features.with_quic)) {
				log(sprintf('Skipping sunsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				if (!sing_features.with_quic)
					log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));

				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'vless',
				address: url.hostname,
				port: url.port,
				uuid: url.username,
				transport: (params.type !== 'tcp') ? params.type : null,
				tls: (params.security in ['tls', 'xtls', 'reality']) ? '1' : '0',
				tls_sni: params.sni,
				tls_alpn: params.alpn ? split(urldecode(params.alpn), ',') : null,
				tls_reality: (params.security === 'reality') ? '1' : '0',
				tls_reality_public_key: params.pbk ? urldecode(params.pbk) : null,
				tls_reality_short_id: params.sid,
				tls_utls: sing_features.with_utls ? params.fp : null,
				vless_flow: (params.security in ['tls', 'reality']) ? params.flow : null
			};
			switch(params.type) {
			case 'grpc':
				config.grpc_servicename = params.serviceName;
				break;
			case 'http':
			case 'tcp':
				if (params.type === 'http' || params.headerType === 'http') {
					config.http_host = params.host ? split(urldecode(params.host), ',') : null;
					config.http_path = params.path ? urldecode(params.path) : null;
				}
				break;
			case 'httpupgrade':
				config.httpupgrade_host = params.host ? urldecode(params.host) : null;
				config.http_path = params.path ? urldecode(params.path) : null;
				break;
			case 'ws':
				config.ws_host = params.host ? urldecode(params.host) : null;
				config.ws_path = params.path ? urldecode(params.path) : null;
				if (config.ws_path && match(config.ws_path, /\?ed=/)) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = split(config.ws_path, '?ed=')[1];
					config.ws_path = split(config.ws_path, '?ed=')[0];
				}
				break;
			}

			break;
		case 'vmess':
			/* "Lovely" shadowrocket format */
			if (match(uri, /&/)) {
				log(sprintf('Skipping unsupported %s format.', uri[0]));
				return null;
			}

			/* https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link */
			try {
				uri = json(decodeBase64Str(uri[1])) || {};
			} catch(e) {
				log(sprintf('Skipping unsupported %s format.', uri[0]));
				return null;
			}

			if (uri.v != '2') {
				log(sprintf('Skipping unsupported %s format.', uri[0]));
				return null;
			/* Unsupported protocol */
			} else if (uri.net === 'kcp') {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], uri.ps || uri.add));
				return null;
			} else if (uri.net === 'quic' && ((uri.type && uri.type !== 'none') || uri.path || !sing_features.with_quic)) {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], uri.ps || uri.add));
				if (!sing_features.with_quic)
					log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));

				return null;
			}
			/*
			 * https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6
			 * else if (uri.aid && int(uri.aid) !== 0) {
			 * 	log(sprintf('Skipping unsupported %s node: %s.', uri[0], uri.ps || uri.add));
			 * 	return null;
			 * }
			 */

			config = {
				label: uri.ps ? urldecode(uri.ps) : null,
				type: 'vmess',
				address: uri.add,
				port: uri.port,
				uuid: uri.id,
				vmess_alterid: uri.aid,
				vmess_encrypt: uri.scy || 'auto',
				vmess_global_padding: '1',
				transport: (uri.net !== 'tcp') ? uri.net : null,
				tls: (uri.tls === 'tls') ? '1' : '0',
				tls_sni: uri.sni || uri.host,
				tls_alpn: uri.alpn ? split(uri.alpn, ',') : null,
				tls_utls: sing_features.with_utls ? uri.fp : null
			};
			switch (uri.net) {
			case 'grpc':
				config.grpc_servicename = uri.path;
				break;
			case 'h2':
			case 'tcp':
				if (uri.net === 'h2' || uri.type === 'http') {
					config.transport = 'http';
					config.http_host = uri.host ? split(uri.host, ',') : null;
					config.http_path = uri.path;
				}
				break;
			case 'httpupgrade':
				config.httpupgrade_host = uri.host;
				config.http_path = uri.path;
				break;
			case 'ws':
				config.ws_host = uri.host;
				config.ws_path = uri.path;
				if (config.ws_path && match(config.ws_path, /\?ed=/)) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = split(config.ws_path, '?ed=')[1];
					config.ws_path = split(config.ws_path, '?ed=')[0];
				}
				break;
			}

			break;
		}
	}

	if (!isEmpty(config)) {
		if (config.address)
			config.address = replace(config.address, /\[|\]/g, '');

		if (!validation('host', config.address) || !validation('port', config.port)) {
			log(sprintf('Skipping invalid %s node: %s.', config.type, config.label || 'NULL'));
			return null;
		} else if (!config.label)
			config.label = (validation('ip6addr', config.address) ?
				`[${config.address}]` : config.address) + ':' + config.port;
	}

	return config;
}

function parse_mihomo_yaml(text) {
	if (isEmpty(text) || type(text) !== 'string')
		return null;

	let in_proxies = false;
	let proxies = [];
	for (let line in split(text, '\n')) {
		line = trim(line);
		if (line === 'proxies:' || match(line, /^proxies:\s*$/)) {
			in_proxies = true;
			continue;
		}
		if (!in_proxies)
			continue;

		if (!line)
			continue;

		if (match(line, /^\w+:\s*$/) && line !== '-')
			break;

		const m = match(line, /^-\s*(\{.*\})\s*$/);
		if (!m)
			continue;

		let obj;
		try {
			obj = json(m[1]);
		} catch(e) {
			obj = null;
		}
		if (obj) {
			obj.nodetype = 'mihomo';
			push(proxies, obj);
		}
	}

	return length(proxies) ? proxies : null;
}

function main() {
	if (via_proxy !== '1') {
		log('Stopping service...');
		init_action('homeproxy', 'stop');
	}

	for (let url in subscription_urls) {
		url = replace(url, /#.*$/, '');
		const groupHash = md5(url);
		node_cache[groupHash] = {};

		const res = wGET(url, user_agent);
		if (isEmpty(res)) {
			log(sprintf('Failed to fetch resources from %s.', url));
			continue;
		}

		let nodes;
		try {
			nodes = json(res).servers || json(res);

			/* Shadowsocks SIP008 format */
			if (nodes[0].server && nodes[0].method)
				map(nodes, (_, i) => nodes[i].nodetype = 'sip008');
		} catch(e) {
			nodes = parse_mihomo_yaml(res);
			if (isEmpty(nodes)) {
				nodes = decodeBase64Str(res);
				const decoded_nodes = parse_mihomo_yaml(nodes);
				if (!isEmpty(decoded_nodes))
					nodes = decoded_nodes;
				else
					nodes = nodes ? split(trim(replace(nodes, / /g, '_')), '\n') : [];
			}
		}

		let count = 0;
		for (let node in nodes) {
			let config;
			if (!isEmpty(node))
				config = parse_uri(node);
			if (isEmpty(config))
				continue;

			const label = config.label;
			config.label = null;
			const confHash = md5(sprintf('%J', config)),
			      nameHash = md5(label);
			config.label = label;

			if (filter_check(config.label))
				log(sprintf('Skipping blacklist node: %s.', config.label));
			else if (node_cache[groupHash][confHash] || node_cache[groupHash][nameHash])
				log(sprintf('Skipping duplicate node: %s.', config.label));
			else {
				if (config.tls === '1' && allow_insecure === '1')
					config.tls_insecure = '1';
				if (config.type in ['vless', 'vmess'] && isEmpty(config.packet_encoding))
					config.packet_encoding = packet_encoding;

				config.grouphash = groupHash;
				push(node_result, []);
				push(node_result[length(node_result)-1], config);
				node_cache[groupHash][confHash] = config;
				node_cache[groupHash][nameHash] = config;

				count++;
			}
		}

		if (count == 0)
			log(sprintf('No valid node found in %s.', url));
		else
			log(sprintf('Successfully fetched %s nodes of total %s from %s.', count, length(nodes), url));
	}

	if (isEmpty(node_result)) {
		log('Failed to update subscriptions: no valid node found.');

		if (via_proxy !== '1') {
			log('Starting service...');
			init_action('homeproxy', 'start');
		}

		return false;
	}

	let added = 0, removed = 0;
	uci.foreach(uciconfig, ucinode, (cfg) => {
		/* Nodes created by the user */
		if (!cfg.grouphash)
			return null;

		/* Empty object - failed to fetch nodes */
		if (length(node_cache[cfg.grouphash]) === 0)
			return null;

		if (!node_cache[cfg.grouphash] || !node_cache[cfg.grouphash][cfg['.name']]) {
			uci.delete(uciconfig, cfg['.name']);
			removed++;

			log(sprintf('Removing node: %s.', cfg.label || cfg['name']));
		} else {
			map(keys(cfg), (v) => {
				if (v in node_cache[cfg.grouphash][cfg['.name']])
					uci.set(uciconfig, cfg['.name'], v, node_cache[cfg.grouphash][cfg['.name']][v]);
				else
					uci.delete(uciconfig, cfg['.name'], v);
			});
			node_cache[cfg.grouphash][cfg['.name']].isExisting = true;
		}
	});
	for (let nodes in node_result)
		map(nodes, (node) => {
			if (node.isExisting)
				return null;

			const nameHash = md5(node.label);
			uci.set(uciconfig, nameHash, 'node');
			map(keys(node), (v) => uci.set(uciconfig, nameHash, v, node[v]));

			added++;
			log(sprintf('Adding node: %s.', node.label));
		});
	uci.commit(uciconfig);

	let need_restart = (via_proxy !== '1');
	if (!isEmpty(main_node)) {
		const first_server = uci.get_first(uciconfig, ucinode);
		if (first_server) {
			let main_urltest_nodes;
			if (main_node === 'urltest') {
				main_urltest_nodes = filter(uci.get(uciconfig, ucimain, 'main_urltest_nodes'), (v) => {
					if (!uci.get(uciconfig, v)) {
						log(sprintf('Node %s is gone, removing from urltest list.', v));
						return false;
					}
					return true;
				});
			}

			if ((main_node === 'urltest') ? !length(main_urltest_nodes) : !uci.get(uciconfig, main_node)) {
				uci.set(uciconfig, ucimain, 'main_node', first_server);
				uci.commit(uciconfig);
				need_restart = true;

				log('Main node is gone, switching to the first node.');
			}

			if (!isEmpty(main_udp_node) && main_udp_node !== 'same') {
				let main_udp_urltest_nodes;
				if (main_udp_node === 'urltest') {
					main_udp_urltest_nodes = filter(uci.get(uciconfig, ucimain, 'main_udp_urltest_nodes'), (v) => {
						if (!uci.get(uciconfig, v)) {
							log(sprintf('Node %s is gone, removing from urltest list.', v));
							return false;
						}
						return true;
					});
				}

				if ((main_udp_node === 'urltest') ? !length(main_udp_urltest_nodes) : !uci.get(uciconfig, main_udp_node)) {
					uci.set(uciconfig, ucimain, 'main_udp_node', first_server);
					uci.commit(uciconfig);
					need_restart = true;

					log('Main UDP node is gone, switching to the first node.');
				}
			}
		} else {
			uci.set(uciconfig, ucimain, 'main_node', 'nil');
			uci.set(uciconfig, ucimain, 'main_udp_node', 'nil');
			uci.commit(uciconfig);
			need_restart = true;

			log('No available node, disable tproxy.');
		}
	}

	if (need_restart) {
		log('Restarting service...');
		init_action('homeproxy', 'stop');
		init_action('homeproxy', 'start');
	}

	log(sprintf('%s nodes added, %s removed.', added, removed));
	log('Successfully updated subscriptions.');
}

if (!isEmpty(subscription_urls))
	try {
		call(main);
	} catch(e) {
		log('[FATAL ERROR] An error occurred during updating subscriptions:');
		log(sprintf('%s: %s', e.type, e.message));
		log(e.stacktrace[0].context);

		log('Restarting service...');
		init_action('homeproxy', 'stop');
		init_action('homeproxy', 'start');
	}
