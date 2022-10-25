#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-3.0-only
--
-- Copyright (C) 2022 ImmortalWrt.org

require "luci.i18n"
require "luci.jsonc"
require "luci.model.uci"
require "luci.sys"
require "luci.util"
require "nixio"

-- UCI config start
local uci = luci.model.uci.cursor()

local uciconfig = "homeproxy"
local ucimain = "config"
local ucinode = "node"
local ucisubscription = "subscription"

local allow_insecure = uci:get(uciconfig, ucisubscription, "allow_insecure")
local filter_mode = uci:get(uciconfig, ucisubscription, "filter_nodes") or "disabled"
local filter_keywords = uci:get(uciconfig, ucisubscription, "filter_keywords") or {}
local packet_encoding = uci:get(uciconfig, ucisubscription, "packet_encoding")
local subscription_urls = uci:get(uciconfig, ucisubscription, "subscription_url") or {}
local via_proxy = uci:get(uciconfig, ucisubscription, "update_via_proxy")

local routing_mode = uci:get(uciconfig, ucimain, "routing_mode") or "bypass_mainland_china"
local main_node, main_udp_node
if routing_mode ~= "custom" then
	main_node = uci:get(uciconfig, ucimain, "main_node") or "nil"
	main_udp_node = uci:get(uciconfig, ucimain, "main_udp_node") or "nil"
end
-- UCI config end

-- i18n start
local syslang = uci:get("luci", "main", "lang") or "auto"
luci.i18n.setlanguage(syslang)
local translate = luci.i18n.translate
local translatef = luci.i18n.translatef
-- i18n end

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
	return res == nil or res == "" or res == "nil" or (type(res) == "table" and next(res) == nil)
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
	if isEmpty(str) then
		return nil
	end

	str = str:gsub("_", "/"):gsub("-", "+")

	local padding = #str % 4
	str = str .. string.sub("====", padding + 1)

	str = nixio.bin.b64decode(str)
	-- Sometimes it ends with "\0", only God knows why.
	return str and str:gsub("%z", "") or nil
end
-- String parser end

-- Utilities start
local sysinit = luci.sys.init

local function md5(str)
	if isEmpty(str) then
		return nil
	end

	local stdout = luci.sys.exec("echo -n " .. luci.util.shellquote(urlencode(str)) .. " | md5sum | awk '{print $1}'")
	return stdout:trim()
end

local function curl(url)
	if isEmpty(url) then
		return nil
	end

	local stdout = luci.sys.exec("curl -fsL --connect-timeout '10' --retry '3' " .. luci.util.shellquote(url))
	return stdout:trim()
end

local function filter_check(res)
	if isEmpty(res) or filter_mode == "disabled" or isEmpty(filter_keywords) then
		return false
	end

	local ret
	for _, keyword in ipairs(filter_keywords) do
		if res:match(keyword) then
			ret = true
		end
	end
	if filter_mode == "whitelist" then
		ret = not ret
	end

	return ret
end
-- Utilities end

-- Common var start
local node_cache = {}
local node_result = setmetatable({}, { __index = node_cache })

local sing_features = {}
local sing_features_stdout = luci.sys.exec("/usr/bin/sing-box version"):trim()
if notEmpty(sing_features_stdout) and sing_features_stdout:match("Tags: ([a-z,_]+)") then
	for _, v in ipairs(sing_features_stdout:match("Tags: ([a-z,_]+)"):split(',')) do
		sing_features[v] = true
	end
end
-- Common var end

-- Log start
nixio.fs.mkdirr("/var/run/homeproxy")

local logfile = io.open("/var/run/homeproxy/homeproxy.log", "a")
local function log(...)
	logfile:write(os.date("%Y-%m-%d %H:%M:%S [SUBSCRIBE] ") .. table.concat({...}, " ") .. "\n")
end
-- Log end

local function parse_uri(uri)
	local config

	if type(uri) == "table" then
		if uri.nodetype == "sip008" then
			-- https://shadowsocks.org/guide/sip008.html
			config = {
				label = uri.remarks,
				type = "shadowsocks",
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

			if (not sing_features.with_quic) or (notEmpty(params.protocol) and params.protocol ~= "udp") then
				log(translatef("Skipping unsupported %s node: %s.", "hysteria", urldecode(url.fragment, true) or url.host))
				if (not sing_features.with_quic) then
					log(translatef("Please rebuild sing-box with %s support!", "QUIC"))
				end
				return nil
			end

			config = {
				label = urldecode(url.fragment, true),
				type = "hysteria",
				address = url.hostname,
				port = url.port,
				hysteria_protocol = params.protocol or "udp",
				hysteria_auth_type = params.auth and "string" or nil,
				hysteria_auth_payload = params.auth,
				hysteria_obfs_password = params.obfsParam,
				hysteria_down_mbps = params.downmbps,
				hysteria_up_mbps = params.upmbps,
				tls = "1",
				tls_insecure = table.contains({"true", "1"}, params.insecure) and "1" or "0",
				tls_sni = params.peer,
				tls_alpn = params.alpn
			}
		elseif uri[1] == "ss" then
			-- "Lovely" Shadowrocket format
			local suri = uri[2]:split("#")
			local slabel = ""
			if #suri <= 2 then
				if #suri == 2 then
					slabel = "#" .. urlencode(suri[2], true)
				end
				if b64decode(suri[1]) then
					uri[2] = b64decode(suri[1]) .. slabel
				end
			end

			-- https://shadowsocks.org/guide/sip002.html
			local url = URL.parse("http://" .. uri[2])

			local userinfo = {}
			if url.user and url.password then
				-- User info encoded with URIComponent
				userinfo = { url.user, urldecode(url.password) }
			elseif url.user then
				-- User info encoded with base64
				userinfo = b64decode(url.user):split(":")
			end

			local plugin, plugin_opts
			if notEmpty(url.query) and url.query.plugin then
				local plugin_info = url.query.plugin:split(";")
				plugin = plugin_info[1]
				if plugin == "simple-obfs" then
					-- Fix non-standard plugin name
					plugin = "obfs-local"
				end
				if #plugin_info >= 2 then
					plugin_opts = table.concat(table.splice(plugin_info, 1, 1), ";")
				end
			end

			config = {
				label = urldecode(url.fragment, true),
				type = "shadowsocks",
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

			if not sing_features.with_shadowsocksr then
				log(translatef("Skipping unsupported %s node: %s.", "ShadowsocksR", b64decode(params.remarks) or userinfo[1]))
				log(translatef("Please rebuild sing-box with %s support!", "ShadowsocksR"))
				return nil
			end

			config = {
				label = b64decode(params.remarks),
				type = "shadowsocksr",
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
				label = urldecode(url.fragment, true),
				type = "trojan",
				address = url.host,
				port = url.port,
				password = urldecode(url.user, true),
				tls = "1",
				tls_sni = notEmpty(url.query) and url.query.sni or nil
			}
		elseif uri[1] == "vless" then
			-- https://github.com/XTLS/Xray-core/discussions/716
			local url = URL.parse("http://" .. uri[2])
			local params = url.query

			-- Unsupported protocol
			if params.type == "kcp" or (params.type == "quic" and (not sing_features.with_quic or params.quicSecurity or params.key)) then
				log(translatef("Skipping unsupported %s node: %s.", "VLESS", urldecode(url.fragment, true) or url.host))
				if params.type == "quic" and not sing_features.with_quic then
					log(translatef("Please rebuild sing-box with %s support!", "QUIC"))
				end
				return nil
			end

			config = {
				label = urldecode(url.fragment, true),
				type = "vless",
				address = url.host,
				port = url.port,
				uuid = url.user,
				transport = (params.type ~= "tcp") and params.type or nil,
				tls = notEmpty(params.security) and "1" or "0",
				tls_sni = params.sni,
				tls_alpn = params.alpn and urldecode(params.alpn, true):split(",") or nil
			}
			if config.transport == "grpc" then
				config.grpc_servicename = params.serviceName
			elseif config.transport == "http" or params.headerType == "http" then
				config.http_host = notEmpty(params.host) and urldecode(params.host, true):split(",") or nil
				config.http_path = urldecode(params.path, true)
			elseif config.transport == "ws" then
				config.ws_host = (config.tls ~= "1") and urldecode(params.host, true) or nil
				config.ws_path = urldecode(params.path, true)
				if config.ws_path and config.ws_path:match("\?ed=") then
					config.websocket_early_data_header = "Sec-WebSocket-Protocol"
					config.websocket_early_data = config.ws_path:split("?ed=")[2]
					config.ws_path = config.ws_path:split("?ed=")[1]
				end
			end
		elseif uri[1] == "vmess" then
			if uri[2]:find("&") then
				-- "Lovely" shadowrocket format
				log(translatef("Skipping unsupported %s format.", "vmess"))
				return nil
			end

			-- https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
			uri = JSON.parse(b64decode(uri[2]))

			if uri.v ~= "2" then
				log(translatef("Skipping unsupported %s format.", "vmess"))
				return nil
			-- Unsupported protocols
			elseif params.net == "kcp" or (params.net == "quic" and (not sing_features.with_quic or notEmpty(params.type) or notEmpty(params.path))) then
				log(translatef("Skipping unsupported %s node: %s.", "VMess", notEmpty(uri.ps) or uri.add))
				if params.net == "quic" and not sing_features.with_quic then
					log(translatef("Please rebuild sing-box with %s support!", "QUIC"))
				end
				return nil
			--[[ https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6
			elseif notEmpty(uri.aid) and tonumber(uri.aid) ~= 0 then
				log(translatef("Skipping unsupported %s node: %s.", "VMess", notEmpty(uri.ps) or uri.add))
				return nil ]]
			end

			config = {
				label = uri.ps,
				type = "vmess",
				address = uri.add,
				port = uri.port,
				uuid = uri.id,
				vmess_alterid = uri.aid,
				vmess_encrypt = notEmpty(uri.scy) or "auto",
				transport = (uri.net ~= "tcp") and uri.net or nil,
				tls = (uri.tls == "tls") and "1" or "0",
				tls_sni = notEmpty(uri.sni) or uri.host,
				tls_alpn = notEmpty(uri.alpn) and uri.alpn:split(",") or nil
			}
			if config.transport == "grpc" then
				config.grpc_servicename = uri.path
			elseif config.transport == "h2" or uri.type == "http" then
				config.transport == "http"
				config.http_host = notEmpty(uri.host) and uri.host:split(",") or nil
				config.http_path = uri.path
			elseif config.transport == "ws" then
				config.ws_host = (config.tls ~= "1") and uri.host or nil
				config.ws_path = uri.path
				if notEmpty(config.ws_host) and config.ws_host:match("\?ed=") then
					config.websocket_early_data_header = "Sec-WebSocket-Protocol"
					config.websocket_early_data = config.ws_host:split("?ed=")[2]
					config.ws_host = config.ws_host:split("?ed=")[1]
				end
			end
		end
	end

	if notEmpty(config) then
		if not (validation.host(config.address) and validation.port(config.port)) then
			log(translatef("Skipping invalid %s node: %s.", config.type, config.label or "NULL"))
			return nil
		elseif isEmpty(config.label) then
			config.label = config.address .. ":" .. config.port
		end
	end

	return config
end

-- Thanks to luci-app-ssr-plus
local function main()
	if via_proxy ~= "1" then
		log(translate("Stopping service..."))
		sysinit.stop(uciconfig)
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
					for i, _ in ipairs(nodes) do
						setmetatable(nodes[i], { __index = {nodetype = "sip008"} })
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
					local label = config.label
					config.label = nil
					setmetatable(config, { __index = {confHash = md5(JSON.dump(config)), nameHash = md5(label)} })
					config.label = label

					if filter_check(config.label) then
						log(translatef("Skipping blacklist node: %s.", config.label))
					elseif node_cache[groupHash][config.confHash] or node_cache[groupHash][config.nameHash] then
						log(translatef("Skipping duplicate node: %s.", config.label))
					else
						if config.tls == "1" and allow_insecure == "1" then
							config.tls_insecure = "1"
						end
						if table.contains({"vless", "vmess"}, config.type) then
							config.packet_encoding = packet_encoding
						end

						config.grouphash = groupHash
						table.insert(node_result[index], config)
						node_cache[groupHash][config.confHash] = node_result[index][#node_result[index]]
						node_cache[groupHash][config.nameHash] = node_result[index][#node_result[index]]

						count = count + 1
					end
				end
			end

			log(translatef("Successfully fetched %s nodes of total %s from %s.", count, #nodes, url))
		else
			log(translatef("Failed to fetch resources from: %s.", url))
		end
	end

	if isEmpty(node_result) then
		log(translate("Failed to update subscriptions: no valid node found."))

		if via_proxy ~= "1" then
			log(translate("Starting service..."))
			sysinit.start(uciconfig)
		end

		logfile:close()
		return false
	end

	local added, removed = 0, 0
	uci:foreach(uciconfig, ucinode, function(cfg)
		if cfg.grouphash then
			if not node_result[cfg.grouphash] or not node_result[cfg.grouphash][cfg[".name"]] then
				uci:delete(uciconfig, cfg[".name"])
				removed = removed + 1
			else
				uci:tset(uciconfig, cfg[".name"], node_result[cfg.grouphash][cfg[".name"]])
				setmetatable(node_result[cfg.grouphash][cfg[".name"]], { __index = {isExisting = true} })
			end
		end
	end)
	for _, nodes in ipairs(node_result) do
		for _, node in ipairs(nodes) do
			if not node.isExisting then
				uci:section(uciconfig, ucinode, node.nameHash, node)
				added = added + 1
			end
		end
	end
	uci:commit(uciconfig)

	local need_restart = (via_proxy ~= "1")
	if notEmpty(main_node) then
		local first_server = uci:get_first(uciconfig, ucinode)
		if first_server then
			if not uci:get(uciconfig, main_node) then
				uci:set(uciconfig, ucimain, "main_node", first_server)
				uci:commit(uciconfig)
				need_restart = true
				log(translate("Main node is gone, switching to the first node."))
			end

			if notEmpty(main_udp_node) and main_udp_node ~= "same" then
				if not uci:get(uciconfig, main_udp_node) then
					uci:set(uciconfig, ucimain, "main_udp_node", first_server)
					uci:commit(uciconfig)
					need_restart = true
					log(translate("Main UDP node is gone, switching to the first node."))
				end
			end
		else
			uci:set(uciconfig, ucimain, "main_node", "nil")
			uci:set(uciconfig, ucimain, "main_udp_node", "nil")
			uci:commit(uciconfig)
			need_restart = true
			log(translate("No node available, disable tproxy."))
		end
	end

	if need_restart then
		log(translate("Reloading service..."))
		sysinit.stop(uciconfig)
		sysinit.start(uciconfig)
	end

	log(translatef("%s nodes added, %s removed.", added, removed))
	log(translate("Successfully updated subscriptions."))
	logfile:close()
end

if notEmpty(subscription_urls) then
	xpcall(main, function(e)
		log(translate("An error occurred during updating subscriptions:"))
		log(e)
		log(debug.traceback())

		log(translate("Reloading service..."))
		sysinit.stop(uciconfig)
		sysinit.start(uciconfig)

		logfile:close()
	end)
end
