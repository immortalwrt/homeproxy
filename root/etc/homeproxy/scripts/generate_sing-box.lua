#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-3.0-only
--
-- Copyright (C) 2022 ImmortalWrt.org

require "luci.jsonc"
require "luci.model.uci"
require "luci.sys"
require "luci.util"

-- String helper start
string.split = luci.util.split
string.trim = luci.util.trim

table.clone = luci.util.clone
table.contains = luci.util.contains
table.dump = luci.util.dumptable

local function isEmpty(res)
	return res == nil or res == "" or (type(res) == "table" and next(res) == nil)
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
local ucimain = "config"

local ucidnssetting = "dns"
local ucidnsserver = "dns_server"
local ucidnsrule = "dns_rule"

local uciroutingsetting = "routing"
local uciroutingnode = "routing_node"
local uciroutingrule = "routing_rule"

local ucinode = "node"
local uciserver = "server"

local main_server = uci:get(uciconfig, ucimain, "main_server") or "nil"
local main_udp_server = uci:get(uciconfig, ucimain, "main_udp_server") or "nil"

local routing_mode = uci:get(uciconfig, ucimain, "routing_mode") or "bypass_mainland_china"
local routing_port = uci:get(uciconfig, ucimain, "routing_port") or "nil"

local dns_server = uci:get(uciconfig, ucimain, "dns_server") or "8.8.8.8"

local enable_server = uci:get(uciconfig, uciserver, "enabled") or "0"

local dns_strategy, dns_default_server, dns_disable_cache, dns_disable_cache_expire
local sniff_override, default_outbound, default_interface
if routing_mode == "custom" then
	-- DNS settings
	dns_strategy = uci:get(uciconfig, ucidnssetting, "dns_strategy") or "prefer_ipv4"
	dns_default_server = uci:get(uciconfig, ucidnssetting, "default_server") or "local-out"
	dns_disable_cache = uci:get(uciconfig, ucidnssetting, "disable_cache") or "0"
	dns_disable_cache_expire = uci:get(uciconfig, ucidnssetting, "disable_cache_expire") or "0"

	-- Routing settings
	sniff_override = uci:get(uciconfig, uciroutingsetting, "sniff_override") or "1"
	default_outbound = uci:get(uciconfig, uciroutingsetting, "default_outbound") or "nil"
	default_interface = uci:get(uciconfig, uciroutingsetting, "default_interface")
end

if routing_port == "common" then
	routing_port = { 22, 53, 80, 143, 443, 465, 587, 853, 995, 993, 8080, 8443, 9418 }
elseif table.contains({"all", "nil"}, routing_port) then
	routing_port = nil
else
	routing_port = routing_port:split(",")
end
local native_protocols = { "http", "shadowsocks", "socks", "trojan", "wireguard", "vmess" }
-- UCI config end

-- Config helper start
local function generate_outbound(server)
	if type(server) ~= "table" or isEmpty(server) then
		return nil
	end

	local outbound = {
		type = server.type,
		tag = server[".name"] .. "-out",

		server = server.address,
		server_port = tonumber(server.port),

		username = server.username,
		password = server.password,

		-- Shadowsocks
		method = server.shadowsocks_encrypt_method,
		-- Socks
		version = server.socks_version,
		-- VMess
		uuid = server.v2ray_uuid,
		security = server.v2ray_vmess_encrypt,
		global_padding = server.vmess_global_padding and (server.vmess_global_padding == "1"),
		authenticated_length = server.vmess_authenticated_length and (server.vmess_authenticated_length == "1"),
		-- WireGuard
		local_address = server.wireguard_local_address,
		private_key = server.wireguard_private_key,
		peer_public_key = server.wireguard_peer_public_key,
		pre_shared_key = server.wireguard_pre_shared_key,
		mtu = server.mkcp_mtu,

		multiplex = (server.multiplex == "1") and {
			enabled = true,
			protocol = server.multiplex_protocol,
			max_connections = server.multiplex_max_connections,
			min_streams = server.multiplex_min_streams,
			max_streams = server.multiplex_max_streams
		} or nil,
		tls = (server.tls == "1") and {
			enabled = true,
			server_name = server.tls_sni,
			insecure = server.tls_insecure,
			alpn = server.tls_alpn,
			min_version = server.tls_min_version,
			max_version = server.tls_max_version,
			cipher_suites = server.tls_cipher_suites,
			certificate_path = server.tls_cert_path
		} or nil,
		udp_over_tcp = server.udp_over_tcp,
		tcp_fast_open = server.tcp_fast_open
	}
	return outbound
end

local function generate_external_outbound(server)
	if type(server) ~= "table" or isEmpty(server) then
		return nil
	end
	-- todo
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

local function split_routing_rules(rules)
	if type(rules) ~= "table" or isEmpty(rules) then
		return nil
	end

	local splited = {}
	for i, v in pairs(rules) do
		splited[#splited+1] = {}
		splited[#splited][i] = v
	end
	return splited
end
-- Config helper end

local config = {}

-- Log
config.log = {
	disabled = false,
	level = "info",
	output = "/var/run/homeproxy/sing-box.log",
	timestamp = true
}

-- DNS start
-- Default settings
config.dns = {
	servers = {
		{
			tag = "local-dns",
			address = "local",
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

-- Main DNS
if routing_mode ~= "custom" then
	config.dns.servers[3] = {
		tag = "main-dns",
		address = dns_server,
		detour = "main-out"
	}
end

if table.contains({ "bypass_mainland_china", "gfwlist", "proxy_mainland_china" }, routing_mode) then
	local dns_geosite
	if routing_mode == "bypass_mainland_china" then
		dns_geosite = { "geolocation-!cn" }
	elseif routing_mode == "gfwlist" then
		dns_geosite = { "gfw" }
	elseif routing_mode == "proxy_mainland_china" then
		dns_geosite = { "cn" }
	end

	config.dns.rules = {
		{
			geosite = dns_geosite,
			port = parse_port(routing_port),
			server = "main-dns"
		}
	}
	config.dns.final = "local-dns"
elseif routing_mode == "custom" then
	-- DNS servers
	uci:foreach(uciconfig, ucidnsserver, function(cfg)
		if cfg.enabled == "1" then
			local index = #config.dns.servers + 1
			config.dns.servers[index] = {
				tag = cfg[".name"] .. "-dns",
				address = cfg.address,
				address_resolver = cfg.address_resolver or nil,
				address_strategy = cfg.address_strategy or nil,
				detour = cfg.outbound
			}
		end
	end)

	-- DNS rules
	config.dns.rules = {}
	uci:foreach(uciconfig, ucidnsrule, function(cfg)
		if cfg.enabled == "1" then
			local dns_rule
			dns_rule = {
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
				outbound = cfg.outbound,
				server = cfg.server,
				disable_cache = (cfg.disable_cache == "1")
			}

			local index = #config.dns.rules + 1
			if cfg.mode == "default" then
				config.dns.rules[index] = dns_rule
			else
				dns_rule.invert = nil
				dns_rule.server = nil
				dns_rule.disable_cache = nil

				config.dns.rules[index] = {
					type = "logical",
					mode = cfg.mode,
					rules = split_routing_rules(dns_rule),
					invert = (cfg.invert == "1"),
					server = cfg.server,
					disable_cache = (cfg.disable_cache == "1")
				}
			end
		end
	end)

	config.dns.final = dns_default_server
elseif routing_mode == "global" then
	config.dns.final = "main-dns"
end
-- DNS end

-- Inbound start
config.inbounds = {}
if (routing_mode == "custom" and default_outbound ~= "nil") or main_server ~= "nil" then
	config.inbounds[1] = {
		type = "tun",
		tag = "tun-in",

		interface_name = "emortal-singbox",
		inet4_address = "172.19.0.1/30",
		inet6_address = "fdfe:dcba:9876::1/128",
		mtu = 1500,
		auto_route = true,
		endpoint_independent_nat = true,
		stack = "gvisor",
		sniff = true,
		sniff_override_destination = (sniff_override == "1"),
		domain_strategy = dns_strategy
	}
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
				tcp_fast_open = (cfg.tcp_fast_open == "1"),
				sniff = true,
				sniff_override_destination = (cfg.sniff_override == "1"),
				domain_strategy = cfg.domain_strategy,
				network = cfg.network,

				-- Shadowsocks
				method = (cfg.type == "shadowsocks") and cfg.shadowsocks_encrypt_method or nil,
				password = (cfg.type == "shadowsocks") and cfg.password or nil,
				users = (cfg.type ~= "shadowsocks") and {
					{
						name = table.contains({"trojan", "vmess"}, cfg.type) and cfg[".name"] .. "-server" or nil,
						username = cfg.username,
						password = (cfg.type ~= "vmess") and cfg.password or nil,
						uuid = (cfg.type == "vmess") and cfg.password or nil
						
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
					key_path = cfg.tls_key_path
				} or nil
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
if routing_mode ~= "custom" and main_server ~= "nil" then
	local main_server_cfg = uci:get_all(uciconfig, main_server) or {}
	if table.contains(native_protocols, main_server_cfg.type) then
		local outbound = generate_outbound(main_server_cfg)
		outbound.tag = "main-out"
		config.outbounds[4] = outbound
	else
		config.outbounds[4] = generate_external_outbound(main_server_cfg)
	end

	if main_udp_server ~= "nil" and main_udp_server ~= "same" and main_udp_server ~= main_server then
		local main_udp_server_cfg = uci:get_all(uciconfig, main_udp_server) or {}
		if table.contains(native_protocols, main_udp_server_cfg.type) then
			local outbound = generate_outbound(main_udp_server_cfg)
			outbound.tag = "main-udp-out"
			config.outbounds[5] = outbound
		else
			config.outbounds[5] = generate_external_outbound(main_udp_server_cfg)
		end
	end
end

if routing_mode == "custom" then
	uci:foreach(uciconfig, uciroutingnode, function(cfg)
		if cfg.enabled == "1" then
			local outbound = uci:get_all(uciconfig, cfg.node:gsub("-out$", "")) or {}
			local index = #config.outbounds + 1
			config.outbounds[index] = generate_outbound(outbound)
			config.outbounds[index].domain_strategy = cfg.domain_strategy
			config.outbounds[index].bind_interface = cfg.bind_interface
			config.outbounds[index].detour = cfg.outbound
		end
	end)
end
-- Outbond end

-- Routing rules start
-- Default settings
config.route = {
	geoip = {
		path = "/etc/homeproxy/resources/geoip.db",
		download_url = "https://github.com/1715173329/sing-geoip/releases/latest/download/geoip.db",
		download_detour = (routing_mode == "custom") and default_outbound or (routing_mode ~= "proxy_mainland_china") and "main-out" or "direct-out"
	},
	geosite = {
		path = "/etc/homeproxy/resources/geosite.db",
		download_url = "https://github.com/1715173329/sing-geosite/releases/latest/download/geosite.db",
		download_detour = (routing_mode == "custom") and default_outbound or (routing_mode ~= "proxy_mainland_china") and "main-out" or "direct-out"
	},
	rules = {
		{
			protocol = "dns",
			outbound = "dns-out"
		}
	},
	auto_detect_interface = isEmpty(default_interface) and true or false,
	default_interface = default_interface
}

if table.contains({ "bypass_mainland_china", "gfwlist", "proxy_mainland_china" }, routing_mode) then
	-- Routing ports
	if parse_port(routing_port) then
		config.route.rules[2] = {
			port = parse_port(routing_port),
			outbound = "direct-out",
			invert = true
		}
	end

	-- Routing rules
	local routing_geosite, routing_geosite
	if routing_mode == "bypass_mainland_china" then
		routing_geosite = { "cn" }
		routing_geoip = { "cn", "private" }
	elseif routing_mode == "proxy_mainland_china" then
		routing_geosite = { "cn" }
		routing_geoip = { "cn" }
	elseif routing_mode == "gfwlist" then
		routing_geosite = { "gfw" }
		routing_geoip = { "telegram" }
	end

	-- Main out
	config.route.rules[#config.route.rules+1] = {
		geosite = table.clone(routing_geosite),
		geoip = table.clone(routing_geoip),
		outbound = (routing_mode == "bypass_mainland_china") and "direct-out" or "main-out"
	}

	-- Main UDP out
	if main_udp_server == "nil" then
		config.route.rules[#config.route.rules].network = (routing_mode ~= "bypass_mainland_china") and "tcp" or nil
		if routing_mode == "bypass_mainland_china" then
			config.route.rules[#config.route.rules+1] = {
				network = "udp",
				outbound = "direct-out"
			}
		end
	elseif main_udp_server ~= "same" and main_udp_server ~= main_server then
		config.route.rules[#config.route.rules].network = (routing_mode ~= "bypass_mainland_china") and "tcp" or nil
		config.route.rules[#config.route.rules+1] = {
			geosite = (routing_mode ~= "bypass_mainland_china") and routing_geosite or nil,
			geoip = (routing_mode ~= "bypass_mainland_china") and routing_geoip or nil,
			network = "udp",
			outbound = "main-udp-out"
		}
	end

	config.route.final = (routing_mode == "bypass_mainland_china") and "main-out" or "direct-out"
elseif routing_mode == "custom" then
	uci:foreach(uciconfig, uciroutingrule, function(cfg)
		if cfg.enabled == "1" then
			local routing_rule
			routing_rule = {
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
				outbound = cfg.outbound
			}

			local index = #config.route.rules + 1
			if cfg.mode == "default" then
				config.route.rules[index] = routing_rule
			else
				routing_rule.invert = nil
				routing_rule.outbound = nil

				config.route.rules[index] = {
					type = "logical",
					mode = cfg.mode,
					rules = split_routing_rules(routing_rule),
					invert = (cfg.invert == "1"),
					outbound = cfg.outbound
				}
			end
		end
	end)

	config.route.final = default_outbound
elseif routing_mode == "global" then
	config.route.final = "main-out"
end
-- Routing rules end

luci.sys.call("mkdir -p /var/run/homeproxy/")
local conffile = io.open("/var/run/homeproxy/sing-box.json", "w")
io.output(conffile)
io.write(JSON.dump(config, 1))
io.close(conffile)
