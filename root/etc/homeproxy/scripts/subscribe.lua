#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-3.0-only
--
-- Copyright (C) 2022 ImmortalWrt.org

require "luci.jsonc"
require "luci.model.uci"
require "luci.sys"
require "luci.util"
require "nixio"

-- String helper start
string.split = luci.util.split
string.trim = luci.util.trim

table.contains = luci.util.contains
table.dump = luci.util.dumptable
table.splice = function(tbl, start, length)
	length = length or 1
	start = start or 1
	local endd = start + length
	local spliced = {}
	local remainder = {}
	for i, elt in ipairs(tbl) do
		if i < start or i >= endd then
			table.insert(spliced, elt)
		else
			table.insert(remainder, elt)
		end
	end
	return spliced, remainder
end

local validation = require "luci.cbi.datatypes"

local function isEmpty(res)
	return res == nil or res == "" or (type(res) == "table" and next(res) == nil)
end

local function notEmpty(res)
	return not isEmpty(res) and res
end
-- String helper end

-- String parser start
local urldecode = luci.util.urldecode
local urlencode = luci.util.urlencode

local JSON = { parse = luci.jsonc.parse, dump = luci.jsonc.stringify }
local URL = require "url"

local function b64decode(str)
	if not str or #str == 0 then
		return nil
	end

	str = str:gsub("_", "/"):gsub("-", "+")

	local padding = #str % 4
	str = str .. string.sub("====", padding + 1)

	-- Sometimes it ends with "\0", only God knows why.
	str = nixio.bin.b64decode(str)
	return str and str:gsub("%z", "") or nil
end
-- String parser end

-- Utilities start
local sysinit = luci.sys.init

local function md5(str)
	local ret = luci.sys.exec("echo -n " .. luci.util.shellquote(urlencode(str)) .. " | md5sum | awk '{print $1}'")
	return ret:trim()
end

local function curl(url)
	if isEmpty(url) then
		return nil
	end

	local stdout = luci.sys.exec("curl -fsL --connect-timeout '10' --retry '3' " .. luci.util.shellquote(url))
	return stdout:trim()
end
-- Utilities end

-- Common var start
local node_cache = {}
local node_result = setmetatable({}, {__index = node_cache})

local shadowsocks_encrypt_methods = {
	-- plain
	"none",
	-- aead
	"aes-128-gcm",
	"aes-192-gcm",
	"aes-256-gcm",
	"chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305",
	-- aead 2022
	"2022-blake3-aes-128-gcm",
	"2022-blake3-aes-256-gcm",
	"2022-blake3-chacha20-poly1305"
}
-- Common var end

-- UCI config start
local uci = luci.model.uci.cursor()

local uciname = "homeproxy"
local ucisection = "node"

local allow_insecure = uci:get(uciname, "subscription", "allow_insecure_in_subs", "0")
local filter_mode = uci:get(uciname, "subscription", "filter_nodes", "disabled")
local filter_keywords = uci:get(uciname, "subscription", "filter_words", {})
local packet_encoding = uci:get(uciname, "subscription", "default_packet_encoding", "xudp")
local subscription_urls = uci:get(uciname, "subscription", "subscription_url", {})
local via_proxy = uci:get(uciname, "subscription", "update_via_proxy", "0")

-- Log start
luci.sys.call("mkdir -p /var/run/homeproxy/")

local logfile = io.open("/var/run/homeproxy/homeproxy.log", "a")
io.output(logfile)

local function log(...)
	io.write(os.date("%Y-%m-%d %H:%M:%S [SUBSCRIBE UPDATE] ") .. table.concat({...}, " ") .. "\n")
end
-- Log end

local function filter_check(res)
	if isEmpty(res) or filter_mode == "disabled" then
		return false
	end

	local ret
	for _, keyword in ipairs(filter_keywords) do
		if res:find(keyword, nil, false) then
			ret = true
		end
	end
	if filter_mode == "whitelist" then
		ret = not ret
	end

	return ret
end
-- UCI config end

local function parse_uri(uri)
	local config

	if type(uri) == "table" then
		if uri.nodetype == "ss" then
			-- SIP008 format https://shadowsocks.org/guide/sip008.html
			if not table.contains(shadowsocks_encrypt_methods, uri.method) then
				log("Skipping legacy Shadowsocks node:", b64decode(uri.remarks) or url.server)
				return nil
			end

			config = {
				alias = uri.remarks,
				type = notEmpty(uri.plugin) and "v2ray" or "shadowsocks",
				v2ray_protocol = notEmpty(uri.plugin) and "shadowsocks" or nil,
				address = uri.server,
				port = uri.server_port,
				shadowsocks_encrypt_method = uri.method,
				password = uri.password,
				shadowsocks_plugin = uri.plugin,
				shadowsocks_plugin_opts = uri.plugin_opts
			}
		end
	elseif type(uri) == "string" then
		uri = uri:split("://")
		if uri[1] == "hysteria" then
			-- https://github.com/HyNetwork/hysteria/wiki/URI-Scheme
			local url = URL.parse("http://" .. uri[2])
			local params = url.query

			config = {
				alias = urldecode(url.fragment, true),
				type = "hysteria",
				address = url.hostname,
				port = url.port,
				hysteria_protocol = params.protocol or "udp",
				hysteria_auth_type = params.auth and "string" or nil,
				hysteria_auth_payload = params.auth,
				hysteria_password = params.obfsParam,
				mkcp_downlink_capacity = params.downmbps,
				mkcp_uplink_capacity = params.upmbps,
				tls = "1",
				tls_insecure = allow_insecure,
				tls_sni = params.peer,
				tls_alpn = params.alpn,
				tls_insecure = params.insecure or "0"
			}
		elseif uri[1] == "ss" then
			-- "Lovely" Shadowrocket format
			local suri = uri[2]:split("#")
			local salias = ""
			local is_srt = false
			if #suri <= 2 then
				if #suri == 2 then
					salias = "#" .. urlencode(suri[2], true)
				end
				if b64decode(suri[1]) then
					uri[2] = b64decode(suri[1]) .. salias
					is_srt = true
				end
			end

			-- SIP002 format https://shadowsocks.org/guide/sip002.html
			local url = URL.parse("http://" .. uri[2])

			local userinfo = {}
			if url.user and url.password then
				-- User info encoded with URIComponent
				userinfo = { url.user, is_srt and url.password or b64decode(url.password) }
			elseif url.user then
				-- User info encoded with base64
				userinfo = b64decode(url.user):split(":")
			end

			if not table.contains(shadowsocks_encrypt_methods, userinfo[1]) then
				log("Skipping legacy Shadowsocks node:", urldecode(url.fragment, true) or url.host or "NULL")
				return nil
			end

			local plugin, plugin_opts
			if notEmpty(url.query) and url.query.plugin then
				local plugin_info = url.query.plugin:split(";")
				plugin = plugin_info[1]
				if #plugin_info >= 2 then
					plugin_opts = table.concat(table.splice(plugin_info, 1, 1), ";")
				end
			end

			config = {
				alias = urldecode(url.fragment, true),
				type = plugin and "v2ray" or "shadowsocks",
				v2ray_protocol = plugin and "shadowsocks" or nil,
				address = url.host,
				port = url.port,
				shadowsocks_encrypt_method = userinfo[1],
				password = userinfo[2],
				shadowsocks_plugin = plugin,
				shadowsocks_plugin_opts = plugin_opts
			}
		elseif uri[1] == "ssr" then
			-- https://coderschool.cn/2498.html
			uri = b64decode(uri[2]):split("/")
			local userinfo = uri[1]:split(":")
			local params = URL.parseQuery(uri[2]:gsub("^\?", ""))

			config = {
				alias = b64decode(params.remarks),
				type = "v2ray",
				v2ray_protocol = "shadowsocksr",
				address = userinfo[1],
				port = userinfo[2],
				shadowsocksr_encrypt_method = userinfo[4],
				password = b64decode(userinfo[6]),
				shadowsocksr_protocol = userinfo[3],
				shadowsocksr_protocol_param = b64decode(params.protoparam),
				shadowsocksr_obfs = userinfo[5],
				shadowsocksr_obfs_param = b64decode(params.obfsparam)
			}
		elseif uri[1] == "trojan" then
			-- https://p4gefau1t.github.io/trojan-go/developer/url/
			local url = URL.parse("http://" .. uri[2])

			config = {
				alias = urldecode(url.fragment, true),
				type = "trojan",
				address = url.host,
				port = url.port,
				password = urldecode(url.user, true),
				tls = "1",
				tls_insecure = allow_insecure,
				tls_sni = notEmpty(url.query) and url.query.sni or nil
			}
		elseif uri[1] == "vless" then
			-- https://github.com/XTLS/Xray-core/discussions/716
			local url = URL.parse("http://" .. uri[2])
			local params = url.query

			config = {
				alias = urldecode(url.fragment, true),
				type = "v2ray",
				v2ray_protocol = "vless",
				address = url.host,
				port = url.port,
				v2ray_uuid = url.user,
				v2ray_vless_encrypt = params.encryption or "none",
				v2ray_transport = params.type or "tcp",
				tls = (params.security == "tls") and "1" or "0",
				tls_insecure = allow_insecure,
				tls_sni = params.sni,
				tls_alpn = params.alpn and urldecode(params.alpn, true):split(",") or nil,
				v2ray_xtls = (params.security == "xtls") and "1" or "0",
				v2ray_xtls_flow = params.flow,
				v2ray_packet_encoding = packet_encoding
			}

			if config.v2ray_transport == "grpc" then
				config["grpc_servicename"] = params.serviceName
				config["grpc_mode"] = params.mode or "gun"
			elseif config.v2ray_transport == "http" then
				config["v2ray_transport"] = "h2"
				config["h2_host"] = notEmpty(params.host) and urldecode(params.host, true):split(",")
				config["h2_path"] = urldecode(params.path, true)
			elseif config.v2ray_transport == "kcp" then
				config["v2ray_transport"] = "mkcp"
				config["mkcp_seed"] = params.seed
				config["mkcp_header"] = params.headerType or "none"
				-- Default settings from v2rayN
				config["mkcp_downlink_capacity"] = "100"
				config["mkcp_uplink_capacity"] = "12"
				config["mkcp_read_buffer_size"] = "2"
				config["mkcp_write_buffer_size"] = "2"
				config["mkcp_mtu"] = "1350"
				config["mkcp_tti"] = "50"
			elseif config.v2ray_transport == "quic" then
				config["quic_security"] = params.quicSecurity or "none"
				config["quic_key"] = params.key
				config["mkcp_header"] = params.headerType or "none"
			elseif config.v2ray_transport == "tcp" then
				config["tcp_header"] = notEmpty(params.headerType) or "none"
				if config.tcp_header == "http" then
					config["tcp_host"] = notEmpty(params.host) and urldecode(params.host, true):split(",") or nil
					config["tcp_path"] = notEmpty(params.path) and urldecode(params.path, true):split(",") or nil
				end
			elseif config.v2ray_transport == "ws" then
				config["ws_host"] = (config.tls ~= "1") and urldecode(params.host, true) or nil
				config["ws_path"] = urldecode(params.path, true)
				if config.ws_path and config.ws_path:match("\?ed=") then
					config["websocket_early_data_header"] = "Sec-WebSocket-Protocol"
					config["websocket_early_data"] = config.ws_path:split("?ed=")[2]
					config["ws_path"] = config.ws_path:split("?ed=")[1]
				end
			end
		elseif uri[1] == "vmess" then
			if uri[2]:find("&") then
				return nil
			end

			-- https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
			uri = JSON.parse(b64decode(uri[2]))

			if uri.v ~= "2" then
				return nil
			-- https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6
			elseif notEmpty(uri.aid) and tonumber(uri.aid) ~= 0 then
				log("Skipping outdated VMess node:", uri.ps or uri.add)
				return nil
			end

			config = {
				alias = uri.ps,
				type = "v2ray",
				v2ray_protocol = "vmess",
				address = uri.add,
				port = uri.port,
				v2ray_uuid = uri.id,
				v2ray_vmess_encrypt = notEmpty(uri.scy) or "auto",
				v2ray_transport = uri.net,
				tls = (uri.tls == "tls") and "1" or "0",
				tls_insecure = allow_insecure,
				tls_sni = notEmpty(uri.sni) or uri.host,
				tls_alpn = notEmpty(uri.alpn) and uri.alpn:split(",") or nil,
				v2ray_packet_encoding = packet_encoding
			}
			if config.v2ray_transport == "grpc" then
				config["grpc_servicename"] = uri.path
				config["grpc_mode"] = "gun"
			elseif config.v2ray_transport == "h2" then
				config["h2_host"] = notEmpty(uri.host) and uri.host:split(",") or nil
				config["h2_path"] = uri.path
			elseif config.v2ray_transport == "kcp" then
				config["v2ray_transport"] = "mkcp"
				config["mkcp_seed"] = uri.path
				config["mkcp_header"] = notEmpty(uri.type) or "none"
				-- Default settings from v2rayN
				config["mkcp_downlink_capacity"] = "100"
				config["mkcp_uplink_capacity"] = "12"
				config["mkcp_read_buffer_size"] = "2"
				config["mkcp_write_buffer_size"] = "2"
				config["mkcp_mtu"] = "1350"
				config["mkcp_tti"] = "50"
			elseif config.v2ray_transport == "quic" then
				config["quic_security"] = notEmpty(uri.host) or "none"
				config["quic_key"] = uri.path
				config["mkcp_header"] = notEmpty(uri.type) or "none"
			elseif config.v2ray_transport == "tcp" then
				config["tcp_header"] = (uri.type == "http") and "http" or "none"
				if config.tcp_header == "http" then
					config["tcp_header"] = uri.type
					config["tcp_host"] = notEmpty(uri.host) and uri.host:split(",") or nil
					config["tcp_path"] = notEmpty(uri.path) and uri.path:split(",") or nil
				else
					conifg["type"] = "vmess"
					config["v2ray_protocol"] = nil
					config["v2ray_transport"] = nil
					config["v2ray_packet_encoding"] = nil
				end
			elseif config.v2ray_transport == "ws" then
				config["ws_host"] = (config.tls ~= "1") and uri.host or nil
				config["ws_path"] = uri.path
				if notEmpty(config.ws_host) and config.ws_host:match("\?ed=") then
					config["websocket_early_data_header"] = "Sec-WebSocket-Protocol"
					config["websocket_early_data"] = config.ws_host:split("?ed=")[2]
					config["ws_host"] = config.ws_host:split("?ed=")[1]
				end
			end
		end
	end

	if notEmpty(config) then
		if not (validation.host(config.address) and validation.port(config.port)) then
			log("Skipping invalid", config.type, "node:", config.alias or "NULL")
			return nil
		elseif isEmpty(config.alias) then
			config["alias"] = config.address .. ":" .. config.port
		end
	end

	return config
end

-- Thanks to luci-app-ssr-plus
local function main()
	if via_proxy ~= "1" then
		log("Stopping service...")
		sysinit.stop(uciname)
	end

	for _, url in ipairs(subscription_urls) do
		local res = curl(url)
		if notEmpty(res) then
			local groupHash = md5(url)
			node_cache[groupHash] = {}

			table.insert(node_result, {})
			local index = #node_result

			local nodes
			if JSON.parse(res) then
				nodes = JSON.parse(res).servers or JSON.parse(res)
				if nodes[1].server and nodes[1].method then
					for index, node in ipairs(nodes) do
						nodes[index].nodetype = "ss"
					end
				end
			else
				nodes = b64decode(res)
				nodes = nodes and nodes:gsub(" ", "_"):split("\n") or {}
			end

			local count = 0
			for _, node in ipairs(nodes) do
				local config
				if notEmpty(node) then
					config = parse_uri(node)
				end
				if notEmpty(config) then
					local alias = config.alias
					config.alias = nil
					config.hashKey = md5(JSON.dump(config))
					config.alias = alias

					if filter_check(config.alias) then
						log("Skipping blacklist node:", config.alias)
					elseif node_cache[groupHash][config.hashKey] then
						log("Skipping duplicate node:", config.alias)
					else
						count = count + 1
						config.group_hashKey = groupHash
						table.insert(node_result[index], config)
						node_cache[groupHash][config.hashKey] = node_result[index][#node_result[index]]
					end
				end
			end

			log("Successfully fetched", count, "nodes of total", #nodes - 1, ".", "From:", url)
		else
			log("Failed to fetch resources from", url)
		end
	end

	if isEmpty(node_result) then
		log("Failed to update subscriptions: no valid node found.")
		io.close(logfile)

		if via_proxy ~= "1" then
			sysinit.start(uciname)
		end

		return false
	end

	local added, removed = 0, 0
	uci:foreach(uciname, ucisection, function(cfg)
		if cfg.group_hashKey or cfg.hashKey then
			if not node_result[cfg.group_hashKey] or not node_result[cfg.group_hashKey][cfg.hashKey] then
				uci:delete(uciname, cfg[".name"])
				removed = removed + 1
			else
				uci:tset(uciname, cfg[".name"], node_result[cfg.group_hashKey][cfg.hashKey])
				setmetatable(node_result[cfg.group_hashKey][cfg.hashKey], {__index = {isExisting = true}})
			end
		end
	end)
	for _, nodes in ipairs(node_result) do
		for _, node in ipairs(nodes) do
			if not node.isExisting then
				local cfgvalue = uci:add(uciname, ucisection)
				uci:tset(uciname, cfgvalue, node)
				added = added + 1
			end
		end
	end
	uci:commit(uciname)

	local main_server = uci:get(uciname, "config", "main_server")
	if main_server ~= "nil" then
		local need_restart = false
		local first_server = uci:get_first(uciname, ucisection)
		if first_server then
			if not uci:get(uciname, main_server) then
				uci:set(uciname, "config", "main_server", first_server)
				need_restart = true
				log("Main node is gone, switching to first node.")
			end

			local udp_server = uci:get(uciname, "config", "main_udp_server", "null")
			if udp_server ~= "nil" and udp_server ~= "null" then
				if not uci:get(uciname, udp_server) then
					uci:set(uciname, "config", "main_udp_server", first_server)
					need_restart = true
					log("UDP node is gone, switching to main node.")
				end
			end

			if via_proxy ~= "1" or need_restart then
				log("Reloading service...")
				uci:commit(uciname)
				sysinit.stop(uciname)
				sysinit.start(uciname)
			end
		else
			log("No node available, stopping service...")
			sysinit.stop(uciname)
		end
	end

	log(added, "nodes added,", removed, "removed.")
	log("Successfully updated subscriptions.")
	io.close(logfile)
end

if notEmpty(subscription_urls) then
	xpcall(main, function(e)
		log("An error occurred during updating subscriptions:")
		log(e)
		log(debug.traceback())

		sysinit.stop(uciname)
		local main_server = uci:get(uciname, "config", "main_server", "nil")
		if main_server ~= "nil" then
			if notEmpty(uci:get(uciname, main_server)) then
				log("Reloading service...")
				sysinit.start(uciname)
			else
				log("No node available. Stopping...")
			end
		end
		io.close(logfile)
	end)
end
