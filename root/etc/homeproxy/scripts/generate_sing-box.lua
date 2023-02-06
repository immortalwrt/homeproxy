#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
--
-- Copyright (C) 2022-2023 ImmortalWrt.org

require "luci.i18n"
require "luci.jsonc"
require "luci.model.uci"
require "luci.sys"
require "luci.util"
require "nixio.fs"

-- String helper start
string.split = luci.util.split
string.trim = luci.util.trim

function string:startswith(str)
	return self:sub(1, #str) == str
end

table.clone = luci.util.clone
table.contains = luci.util.contains
table.dump = luci.util.dumptable

local function isEmpty(res)
	return res == nil or res == "" or res == "nil" or (type(res) == "table" and next(res) == nil)
end

local function notEmpty(res)
	return not isEmpty(res) and res
end
-- String helper end

-- String parser start
local JSON = { parse = luci.jsonc.parse, dump = luci.jsonc.stringify }
-- String parser end

-- UCI config start
local uci = luci.model.uci.cursor()

local uciconfig = "homeproxy"
local uciinfra = "infra"
local ucimain = "config"

local ucidnssetting = "dns"
local ucidnsserver = "dns_server"
local ucidnsrule = "dns_rule"

local uciroutingsetting = "routing"
local uciroutingnode = "routing_node"
local uciroutingrule = "routing_rule"

local ucinode = "node"
local uciserver = "server"

local routing_mode = uci:get(uciconfig, ucimain, "routing_mode") or "bypass_mainland_china"
local ipv6_support = uci:get(uciconfig, ucimain, "ipv6_support") or "0"

local wan_dns = luci.sys.exec("ifstatus wan | jsonfilter -e '@[\"dns-server\"][0]'"):trim()
if isEmpty(wan_dns) then
	wan_dns = table.contains({"proxy_mainland_china", "global"}, routing_mode) and "8.8.8.8" or "114.114.114.114"
end
local dns_server = uci:get(uciconfig, ucimain, "dns_server")
if isEmpty(dns_server) or dns_server == "wan" then
	dns_server = wan_dns
end
local dns_port = uci:get(uciconfig, uciinfra, "dns_port") or "5333"

local enable_server = uci:get(uciconfig, uciserver, "enabled") or "0"

local main_node, main_udp_node, default_outbound, default_interface
local dns_strategy, dns_default_server, dns_disable_cache, dns_disable_cache_expire
local redirect_port, tproxy_port, self_mark
local sniff_override, tun_name, tcpip_stack, endpoint_independent_nat
if routing_mode ~= "custom" then
	main_node = uci:get(uciconfig, ucimain, "main_node") or "nil"
	main_udp_node = uci:get(uciconfig, ucimain, "main_udp_node") or "nil"
	redirect_port = uci:get(uciconfig, uciinfra, "redirect_port") or "5331"
	tproxy_port = uci:get(uciconfig, uciinfra, "tproxy_port") or "5332"
	self_mark = uci:get(uciconfig, uciinfra, "self_mark") or "100"
else
	-- DNS settings
	dns_strategy = uci:get(uciconfig, ucidnssetting, "dns_strategy")
	dns_default_server = uci:get(uciconfig, ucidnssetting, "default_server")
	dns_disable_cache = uci:get(uciconfig, ucidnssetting, "disable_cache")
	dns_disable_cache_expire = uci:get(uciconfig, ucidnssetting, "disable_cache_expire")

	-- Routing settings
	default_outbound = uci:get(uciconfig, uciroutingsetting, "default_outbound") or "nil"
	default_interface = uci:get(uciconfig, uciroutingsetting, "default_interface")
	sniff_override = uci:get(uciconfig, uciroutingsetting, "sniff_override")
	tun_name = uci:get(uciconfig, uciinfra, "tun_name") or "singtun0"
	tcpip_stack = uci:get(uciconfig, uciroutingsetting, "tcpip_stack") or "gvisor"
	endpoint_independent_nat = uci:get(uciconfig, uciroutingsetting, "endpoint_independent_nat")
end
-- UCI config end

-- i18n start
local uci = luci.model.uci.cursor()
local syslang = uci:get("luci", "main", "lang") or "auto"
luci.i18n.setlanguage(syslang)
local translatef = luci.i18n.translatef
-- i18n end

-- Config helper start
local function generate_outbound(node)
	if type(node) ~= "table" or isEmpty(node) then
		return nil
	end

	local outbound = {
		type = node.type,
		tag = "cfg-" .. node[".name"] .. "-out",

		server = (node.type ~= "direct") and node.address or nil,
		server_port = (node.type ~= "direct") and tonumber(node.port) or nil,

		username = node.username,
		password = node.password,

		-- Direct
		override_address = (node.type == "direct") and node.address or nil,
		override_port = (node.type == "direct") and node.port or nil,
		proxy_protocol = notEmpty(node.proxy_protocol) or nil,
		-- Hysteria
		up_mbps = tonumber(node.hysteria_down_mbps),
		down_mbps = tonumber(node.hysteria_up_mbps),
		obfs = node.hysteria_obfs_password,
		auth = (node.hysteria_auth_type == "base64") and node.hysteria_auth_payload or nil,
		auth_str = (node.hysteria_auth_type == "string") and node.hysteria_auth_payload or nil,
		recv_window_conn = tonumber(node.hysteria_recv_window_conn),
		recv_window = tonumber(node.hysteria_revc_window),
		disable_mtu_discovery = (node.hysteria_disable_mtu_discovery == "1") or nil,
		-- Shadowsocks
		method = node.shadowsocks_encrypt_method or node.shadowsocksr_encrypt_method,
		plugin = node.shadowsocks_plugin,
		plugin_opts = node.shadowsocks_plugin_opts,
		-- ShadowsocksR
		protocol = node.shadowsocksr_protocol,
		protocol_param = node.shadowsocksr_protocol_param,
		obfs = node.shadowsocksr_obfs,
		obfs_param = node.shadowsocksr_obfs_param,
		-- ShadowTLS / Socks
		version = (node.type == "shadowtls") and tonumber(node.shadowtls_version) or (node.type == "socks") and node.socks_version or nil,
		-- VLESS / VMess
		uuid = node.uuid,
		alter_id = node.vmess_alterid,
		security = node.vmess_encrypt,
		global_padding = node.vmess_global_padding and (node.vmess_global_padding == "1") or nil,
		authenticated_length = node.vmess_authenticated_length and (node.vmess_authenticated_length == "1") or nil,
		packet_encoding = node.packet_encoding,
		-- WireGuard
		system_interface = (node.type == "wireguard") or nil,
		interface_name = (node.type == "wireguard") and "emortal-wg-cfg-" .. node[".name"] .. "-out" or nil,
		local_address = node.wireguard_local_address,
		private_key = node.wireguard_private_key,
		peer_public_key = node.wireguard_peer_public_key,
		pre_shared_key = node.wireguard_pre_shared_key,
		mtu = node.wireguard_mtu,

		multiplex = (node.multiplex == "1") and {
			enabled = true,
			protocol = node.multiplex_protocol,
			max_connections = node.multiplex_max_connections,
			min_streams = node.multiplex_min_streams,
			max_streams = node.multiplex_max_streams
		} or nil,
		tls = (node.tls == "1") and {
			enabled = true,
			server_name = node.tls_sni,
			insecure = (node.tls_insecure == "1"),
			alpn = node.tls_alpn,
			min_version = node.tls_min_version,
			max_version = node.tls_max_version,
			cipher_suites = node.tls_cipher_suites,
			certificate_path = node.tls_cert_path,
			ech = (node.enable_ech == "1") and {
				enabled = true,
				dynamic_record_sizing_disabled = (node.tls_ech_tls_disable_drs == "1"),
				pq_signature_schemes_enabled = (node.tls_ech_enable_pqss == "1"),
				config = node.tls_ech_config
			} or nil,
			utls = notEmpty(node.tls_utls) and {
				enabled = true,
				fingerprint = node.tls_utls
			} or nil
		} or nil,
		transport = notEmpty(node.transport) and {
			type = node.transport,
			host = node.http_host or node.ws_host,
			path = node.http_path or node.ws_path,
			method = node.http_method,
			max_early_data = node.websocket_early_data,
			early_data_header_name = node.websocket_early_data_header,
			service_name = node.grpc_servicename
		} or nil,
		udp_over_tcp = (node.udp_over_tcp == "1") or nil,
		tcp_fast_open = (node.tcp_fast_open == "1") or nil,
		udp_fragment = (node.udp_fragment == "1") or nil
	}
	return outbound
end

local function get_outbound(cfg)
	if isEmpty(cfg) then
		return nil
	end

	if table.contains({"direct-out", "block-out"}, cfg) then
		return cfg
	else
		local node = uci:get(uciconfig, cfg, "node")
		if isEmpty(node) then
			error(translatef("%s's node is missing, please check your configuration.", cfg))
		else
			return "cfg-" .. node .. "-out"
		end
	end
end

local function get_resolver(cfg)
	if isEmpty(cfg) then
		return nil
	end

	if table.contains({"default-dns", "block-dns"}, cfg) then
		return cfg
	else
		return "cfg-" .. cfg .. "-dns"
	end
end

local function parse_port(strport)
	if type(strport) ~= "table" or isEmpty(strport) then
		return nil
	end

	local ports = {}
	for i, v in ipairs(strport) do
		ports[i] = tonumber(v)
	end
	return ports
end
-- Config helper end

local config = {}

-- Log
config.log = {
	disabled = false,
	level = "warn",
	output = "/var/run/homeproxy/sing-box.log",
	timestamp = true
}

-- DNS start
-- Default settings
config.dns = {
	servers = {
		{
			tag = "default-dns",
			address = wan_dns,
			detour = "direct-out"
		},
		{
			tag = "block-dns",
			address = "rcode://name_error"
		},
	},
	strategy = dns_strategy,
	disable_cache = (dns_disable_cache == "1"),
	disable_expire = (dns_disable_cache_expire == "1")
}

if notEmpty(main_node) then
	local default_final_dns = "default-dns"
	-- Main DNS
	if dns_server ~= wan_dns then
		config.dns.servers[3] = {
			tag = "main-dns",
			address = dns_server,
			strategy = (ipv6_support ~= "1") and "ipv4_only" or nil,
			detour = "main-out"
		}
		default_final_dns = "main-dns"
	end

	config.dns.final = default_final_dns
elseif notEmpty(default_outbound) then
	-- DNS servers
	uci:foreach(uciconfig, ucidnsserver, function(cfg)
		if cfg.enabled == "1" then
			local index = #config.dns.servers + 1
			config.dns.servers[index] = {
				tag = "cfg-" .. cfg[".name"] .. "-dns",
				address = cfg.address,
				address_resolver = get_resolver(cfg.address_resolver),
				address_strategy = cfg.address_strategy,
				strategy = cfg.resolve_strategy,
				detour = get_outbound(cfg.outbound)
			}
		end
	end)

	-- DNS rules
	config.dns.rules = {}
	uci:foreach(uciconfig, ucidnsrule, function(cfg)
		if cfg.enabled == "1" then
			config.dns.rules[#config.dns.rules+1] = {
				invert = cfg.invert,
				network = cfg.network,
				protocol = cfg.protocol,
				domain = cfg.domain,
				domain_suffix = cfg.domain_suffix,
				domain_keyword = cfg.domain_keyword,
				domain_regex = cfg.domain_regex,
				geosite = cfg.geosite,
				source_geoip = cfg.source_geoip,
				source_ip_cidr = cfg.source_ip_cidr,
				source_port = parse_port(cfg.source_port),
				source_port_range = cfg.source_port_range,
				port = parse_port(cfg.port),
				port_range = cfg.port_range,
				process_name = cfg.process_name,
				user = cfg.user,
				invert = (cfg.invert == "1"),
				outbound = get_outbound(cfg.outbound),
				server = get_resolver(cfg.server),
				disable_cache = (cfg.disable_cache == "1")
			}
		end
	end)
	if isEmpty(config.dns.rules) then
		config.dns.rules = nil
	end

	config.dns.final = get_resolver(dns_default_server)
end
-- DNS end

-- Inbound start
config.inbounds = {}
if notEmpty(main_node) or notEmpty(default_outbound) then
	config.inbounds[#config.inbounds+1] = {
		type = "direct",
		tag = "dns-in",
		listen = "::",
		listen_port = tonumber(dns_port)
	}

	if (routing_mode ~= "custom") then
		config.inbounds[#config.inbounds+1] = {
			type = "redirect",
			tag = "redirect-in",

			listen = "::",
			listen_port = tonumber(redirect_port),
			sniff = true,
			sniff_override_destination = true
		}

		if notEmpty(main_udp_node) then
			config.inbounds[#config.inbounds+1] = {
				type = "tproxy",
				tag = "tproxy-in",

				listen = "::",
				listen_port = tonumber(tproxy_port),
				network = "udp",
				sniff = true,
				sniff_override_destination = true
			}
		end
	else
		config.inbounds[#config.inbounds+1] = {
			type = "tun",
			tag = "tun-in",

			interface_name = tun_name,
			inet4_address = "172.19.0.1/30",
			inet6_address = "fdfe:dcba:9876::1/126",
			mtu = 9000,
			auto_route = false,
			endpoint_independent_nat = (endpoint_independent_nat == "1") or nil,
			stack = tcpip_stack,
			sniff = true,
			sniff_override_destination = (sniff_override == "1"),
			domain_strategy = dns_strategy
		}
	end
end
if enable_server == "1" then
	uci:foreach(uciconfig, uciserver, function(cfg)
		if cfg.enabled == "1" then
			local index = #config.inbounds + 1
			config.inbounds[index] = {
				type = cfg.type,
				tag = cfg[".name"] .. "-in",

				listen = "::",
				listen_port = tonumber(cfg.port),
				tcp_fast_open = (cfg.tcp_fast_open == "1") or nil,
				udp_fragment = (cfg.udp_fragment == "1") or nil,
				sniff = true,
				sniff_override_destination = (cfg.sniff_override == "1"),
				domain_strategy = cfg.domain_strategy,
				proxy_protocol = (cfg.proxy_protocol == "1") or nil,
				proxy_protocol_accept_no_header = (cfg.proxy_protocol_accept_no_header == "1") or nil,
				network = cfg.network,

				-- Hysteria
				up_mbps = tonumber(cfg.hysteria_up_mbps),
				down_mbps = tonumber(cfg.hysteria_down_mbps),
				obfs = cfg.hysteria_obfs_password,
				auth = (cfg.hysteria_auth_type == "base64") and cfg.hysteria_auth_payload or nil,
				auth_str = (cfg.hysteria_auth_type == "string") and cfg.hysteria_auth_payload or nil,
				recv_window_conn = tonumber(cfg.hysteria_recv_window_conn),
				recv_window_client = tonumber(cfg.hysteria_revc_window_client),
				max_conn_client = tonumber(cfg.hysteria_max_conn_client),
				disable_mtu_discovery = (cfg.hysteria_disable_mtu_discovery == "1") or nil,

				-- Shadowsocks
				method = (cfg.type == "shadowsocks") and cfg.shadowsocks_encrypt_method or nil,
				password = table.contains({"shadowsocks", "shadowtls"}, cfg.type) and cfg.password or nil,

				-- ShadowTLS
				version = (cfg.type == "shadowtls") and tonumber(cfg.shadowtls_version) or nil,

				-- HTTP / Socks / Trojan / VMess
				users = (cfg.type ~= "shadowsocks") and {
					{
						name = table.contains({"trojan", "vmess"}, cfg.type) and "cfg-" .. cfg[".name"] .. "-server" or nil,
						username = cfg.username,
						password = cfg.password,
						uuid = cfg.uuid,
						alterId = tonumber(cfg.vmess_alterid)
					}
				} or nil,

				tls = (cfg.tls == "1") and {
					enabled = true,
					server_name = cfg.tls_sni,
					alpn = cfg.tls_alpn,
					min_version = cfg.tls_min_version,
					max_version = cfg.tls_max_version,
					cipher_suites = cfg.tls_cipher_suites,
					certificate_path = cfg.tls_cert_path,
					key_path = cfg.tls_key_path,
					acme = (cfg.tls_acme == "1") and {
						domain = cfg.tls_acme_domains,
						data_directory = "/etc/homeproxy/certs",
						default_server_name = cfg.tls_acme_dsn,
						email = cfg.tls_acme_email,
						provider = cfg.tls_acme_provider,
						disable_http_challenge = (cfg.tls_acme_dhc == "1"),
						disable_tls_alpn_challenge = (cfg.tls_acme_dtac == "1"),
						alternative_http_port = tonumber(cfg.tls_acme_ahp),
						alternative_tls_port = tonumber(cfg.tls_acme_atp),
						external_account = (cfg.tls_acme_external_account == "1") and {
							key_id = cfg.tls_acme_ea_keyid,
							mac_key = cfg.tls_acme_ea_mackey
						} or nil
					} or nil
				} or nil,

				transport = notEmpty(cfg.transport) and {
					type = cfg.transport,
					host = cfg.http_host or cfg.ws_host,
					path = cfg.http_path or cfg.ws_path,
					method = cfg.http_method,
					max_early_data = cfg.websocket_early_data,
					early_data_header_name = cfg.websocket_early_data_header,
					service_name = cfg.grpc_servicename
				} or nil,
			}
		end
	end)
end
-- Inbound end

-- Outbound start
-- Default outbounds
config.outbounds = {
	{
		type = "direct",
		tag = "direct-out"
	},
	{
		type = "block",
		tag = "block-out"
	},
	{
		type = "dns",
		tag = "dns-out"
	}
}

-- Main outbounds
if notEmpty(main_node) then
	config.outbounds[1].routing_mark = tonumber(self_mark)

	local main_node_cfg = uci:get_all(uciconfig, main_node) or {}
	config.outbounds[#config.outbounds+1] = generate_outbound(main_node_cfg)
	config.outbounds[#config.outbounds].routing_mark = tonumber(self_mark)
	config.outbounds[#config.outbounds].tag = "main-out"

	if notEmpty(main_udp_node) and main_udp_node ~= "same" and main_udp_node ~= main_node then
		local main_udp_node_cfg = uci:get_all(uciconfig, main_udp_node) or {}
		config.outbounds[#config.outbounds+1] = generate_outbound(main_udp_node_cfg)
		config.outbounds[#config.outbounds].routing_mark = tonumber(self_mark)
		config.outbounds[#config.outbounds].tag = "main-udp-out"
	end
end

if notEmpty(default_outbound) then
	uci:foreach(uciconfig, uciroutingnode, function(cfg)
		if cfg.enabled == "1" then
			local outbound = uci:get_all(uciconfig, cfg.node) or {}
			local index = #config.outbounds + 1
			config.outbounds[index] = generate_outbound(outbound)
			config.outbounds[index].domain_strategy = cfg.domain_strategy
			config.outbounds[index].bind_interface = cfg.bind_interface
			config.outbounds[index].detour = get_outbound(cfg.outbound)

		end
	end)
end
-- Outbond end

-- Routing rules start
-- Default settings
if notEmpty(main_node) or notEmpty(default_outbound) then
	config.route = {
		geoip = {
			path = "/etc/homeproxy/resources/geoip.db",
			download_url = "https://github.com/1715173329/sing-geoip/releases/latest/download/geoip.db",
			download_detour = get_outbound(default_outbound) or (routing_mode ~= "proxy_mainland_china" and notEmpty(main_node)) and "main-out" or "direct-out"
		},
		geosite = {
			path = "/etc/homeproxy/resources/geosite.db",
			download_url = "https://github.com/1715173329/sing-geosite/releases/latest/download/geosite.db",
			download_detour = get_outbound(default_outbound) or (routing_mode ~= "proxy_mainland_china" and notEmpty(main_node)) and "main-out" or "direct-out"
		},
		rules = {
			{
				inbound = "dns-in",
				outbound = "dns-out"
			},
			{
				protocol = "dns",
				outbound = "dns-out"
			}
		},
		auto_detect_interface = isEmpty(default_interface) and true or nil,
		default_interface = default_interface
	}
end

if notEmpty(main_node) then
	-- Routing rules
	local routing_geosite, routing_geosite, final_node
	if routing_mode == "gfwlist" then
		routing_geosite = { "gfw", "greatfire" }
		routing_geoip = { "telegram" }

		-- Main out
		config.route.rules[#config.route.rules+1] = {
			geosite = table.clone(routing_geosite),
			geoip = table.clone(routing_geoip),
			outbound = "main-out",
		}
		config.route.final = "direct-out"
	else
		-- Main out
		config.route.final = "main-out"
	end

	-- Main UDP out
	if notEmpty(main_udp_node) and main_udp_node ~= "same" and main_udp_node ~= main_node then
		if routing_mode == "gfwlist" then
			config.route.rules[#config.route.rules].network = "tcp"
		end
		config.route.rules[#config.route.rules+1] = {
			geosite = routing_geosite and table.clone(routing_geosite) or nil,
			geoip = routing_geoip and table.clone(routing_geoip) or nil,
			network = "udp",
			outbound = "main-udp-out",
		}
	end
elseif notEmpty(default_outbound) then
	uci:foreach(uciconfig, uciroutingrule, function(cfg)
		if cfg.enabled == "1" then
			config.route.rules[#config.route.rules+1] = {
				invert = cfg.invert,
				ip_version = cfg.ip_version,
				network = cfg.network,
				protocol = cfg.protocol,
				domain = cfg.domain,
				domain_suffix = cfg.domain_suffix,
				domain_keyword = cfg.domain_keyword,
				domain_regex = cfg.domain_regex,
				geosite = cfg.geosite,
				source_geoip = cfg.source_geoip,
				geoip = cfg.geoip,
				source_ip_cidr = cfg.source_ip_cidr,
				ip_cidr = cfg.ip_cidr,
				source_port = parse_port(cfg.source_port),
				source_port_range = cfg.source_port_range,
				port = parse_port(cfg.port),
				port_range = cfg.port_range,
				process_name = cfg.process_name,
				user = cfg.user,
				invert = (cfg.invert == "1"),
				outbound = get_outbound(cfg.outbound)
			}
		end
	end)

	config.route.final = get_outbound(default_outbound)
end
-- Routing rules end

nixio.fs.mkdirr("/var/run/homeproxy")
local conffile = io.open("/var/run/homeproxy/sing-box.json", "w")
conffile:write(JSON.dump(config, 1))
conffile:close()
