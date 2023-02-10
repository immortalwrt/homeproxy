#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023 ImmortalWrt.org
 */

'use strict';

import { open } from 'fs';
import { connect } from 'ubus';
import { cursor } from 'uci';

import { urldecode, urlencode, urldecode_params } from 'luci.http';
import { init_action } from 'luci.sys';

import { executeCommand, decodeBase64Str, isEmpty } from 'homeproxy';
import { HP_DIR, RUN_DIR } from 'homeproxy';

/* Utilities start */

/* Utilities end */

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
      via_proxy = uci.get(uciconfig, ucisubscription, 'update_via_proxy') || '0'

const routing_mode = uci.get(uciconfig, ucimain, 'routing_mode') || 'bypass_mainalnd_china';
let main_node, main_udp_node;
if (routing_mode !== 'custom') {
	main_node = uci.get(uciconfig, ucimain, 'main_node') || 'nil';
	main_udp_node = uci.get(uciconfig, ucimain, 'main_udp_node') || 'nil';
}
/* UCI config end */

/* String helper start */
function notEmpty(res) {
	return !isEmpty(res) && res
}

function filter_check(name) {
	if (isEmpty(name) || filter_mode === 'disabled' || isEmpty(filter_keywords))
		return false;

	let ret = false;
	for (let i in filter_keywords)
		if (match(name, i))
			ret = true;
	if (filter_mode === 'whitelist')
		ret = !ret

	return ret
}
/* String helper end */

/* Common var start */
let node_cache = [], node_result = [];

const ubus = connect();
const sing_features = ubus.call('luci.homeproxy', 'singbox_get_features', {}) || {};
/* Common var end */

/* Log */
system(`mkdir -p ${RUN_DIR}`);
function log(...args) {
	const logtime = trim(executeCommand('date "+%Y-%m-%d %H:%M:%S"').stdout);

	const logfile = open(`${RUN_DIR}/homeproxy.log`, 'a');
	logfile.write(`${logtime} [SUBSCRIBE] ${join(' ', args)}\n`);
	logfile.close();
}

function parse_uri(uri) {
	let config;

	if (type(uri) === 'object') {
		if (uri.nodetype === 'sip008') {
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
		uri = split(uri, '://');

		switch (uri[0]) {
		case 'hysteria':
			/* https://github.com/HyNetwork/hysteria/wiki/URI-Scheme */
			const url = urlparse('http://' + url[1]);
			const params = urldecode_params('http://' + url[1]);

			if (!sing_features.with_quic || (!isEmpty(params.protocol && params.protocol !== 'udp'))) {
				log(sprintf('Skipping unsupportedd %s node: %s.', 'hysteria', urldecode(url.hash) || url.hostname));
				if (!sing_features.with_quic)
					log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));

				return null;
			}

			config = {
				label: urldecode(url.hash),
				type: 'hysteria',
				address: url.hostname,
				port: url.port,
				hysteria_protocol: params.protocol || 'udp',
				hysteria_auth_type: params.auth ? 'string' : null,
				hysteria_auth_payload: params.auth,
				hysteria_obfs_password: params.obfsParam,
				hysteria_down_mbps: params.downmbps,
				hysteria_up_mbps = params.upmbps,
				tls: '1',
				tls_insecure = (params.insecure in ['true', '1']) ? '1' : '0',
				tls_sni: params.peer,
				tls_alpn: params.alpn
			};

			break;
		case 'ssr':
			/* https://coderschool.cn/2498.html */
			uri = split(decodeBase64Str(uri[1]), '/');
			if (!uri)
				return null;

			const userinfo = split(uri[0], ':'),
			      params = urldecode_params(uri[1]);

			if (!sing_features.with_shadowsocksr) {
				log(sprintf('Skipping unsupported %s node: %s.', 'ShadowsocksR', decodeBase64Str(params.remarks) || userinfo[1]));
				log(sprintf('Please rebuild sing-box with %s support!', 'ShadowsocksR'));

				return null;
			}

			config = {
				label: decodeBase64Str(params.remarks),
				type: 'shadowsocksr',
				address: userinfo[0],
				port: userinfo[1],
				shadowsocksr_encrypt_method: userinfo[3],
				password: decodeBase64Str(userinfo[5]),
				shadowsocksr_protocol: userinfo[2],
				shadowsocksr_protocol_param: decodeBase64Str(params.protoparam),
				shadowsocksr_obfs: userinfo[4],
				shadowsocksr_obfs_param: decodeBase64Str(params.obfsparam)
			};

			break;
		case 'vmess':
			/* "Lovely" shadowrocket format */
			if (match(uri, /&/)) {
				log(sprintf('Skipping unsupported %s format.', 'VMess'));
				return null;
			}

			/* https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2) */
			uri = json(decodeBase64Str(uri));
			if (isEmpty(uri))
				return null;
			else if (uri.v !== '2') {
				log(sprintf('Skipping unsupported %s format.', 'VMess'));
				return null;
			/* Unsupported protocols */
			} else if (uri.net === 'kcp') {
				log(sprintf('Skipping unsupported %s node: %s.', 'VMess', uri.ps || uri.add));
				return null;
			} else if (uri.net === 'quic' && ((url.type && url.type !== 'none') || url.path || !sing_features.with_quic)) {
				log(sprintf('Skipping unsupported %s node: %s.', 'VMess', uri.ps || uri.add));
				if (!sing_features.with_quic)
					log(sprintf('Please rebuild sing-box with %s support!', 'QUIC'));

				return null;
			}
			/*
			 * https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6
			 * else if (!isEmpty(uri.aid) && int(uri.aid) !== 0) {
			 * 	log(sprintf('Skipping unsupported %s node: %s.', 'VMess', uri.ps || uri.add));
			 * 	return null;
			 * }
			 */

			config = {
				label: uri.ps,
				type: 'vmess',
				address: uri.add,
				port: uri.port,
				uuid: uri.id,
				vmess_alterid: uri.aid,
				vmess_encrypt: uri.scy || 'auto',
				transport: (uri.net !== 'tcp') ? uri.net : null,
				tls: (uri.tls === 'tls') ? '1' : '0',
				tls_sni: uri.sni || uri.host,
				tls_alpn: uri.alpn ? split(uri.alpn, ',') : null
			};
			switch (uri.net) {
			case 'grpc':
				config.grpc_servicename = uri.path;
				break;
			case 'h2':
			case 'tcp':
				if (uri.net === 'h2' || uri.type === 'http') {
					config.transport = 'http';
					config.http_host = uri.host ? uri.host.split(',') : null;
					config.http_path = uri.path;
				}
				break;
			case 'ws':
				config.ws_host = (config.tls !== '1') ? uri.host : null;
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
}