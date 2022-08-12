#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-3.0-only
--
-- Copyright (C) 2022 ImmortalWrt.org

require "luci.jsonc"
require "luci.model.uci"
require "luci.sys"
require "luci.util"
require "nixio"

-- Common var start
local shadowsocks_encrypt_method = {
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

	return nixio.bin.b64decode(str)
end
-- String parser end

-- String helper start
string.split = luci.util.split
string.trim = luci.util.trim

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

-- https://www.04007.cn/article/135.html
local function checkTabValue(tab)
	local revtab = {}

	for k,v in pairs(tab) do
		revtab[v] = true
	end

	return revtab
end

local function isEmpty(res)
	return res == nil or res == "" or (type(res) == "table" and next(res) == nil)
end

local function notEmpty(res)
	return not isEmpty(res) and res
end
-- String helper end

-- Utilities start
local md5 = require "md5"
-- Utilities end

local function log(...)
	-- TODO: write to log file directly
	print(os.date("%Y-%m-%d %H:%M:%S [SUBSCRIBE UPDATE] ") .. table.concat({...}, " "))
end

local function parse_uri(uri)
	local config

	if type(uri) == "table" then
		if uri.type == "ss" then
			-- SIP008 format https://shadowsocks.org/guide/sip008.html
			if not checkTabValue(shadowsocks_encrypt_method)[uri.method] then
				log("Skipping unsupported Shadowsocks node:", b64decode(uri.remarks) or url.server)
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
				tls_sni = params.peer,
				tls_alpn = params.alpn,
				tls_insecure = params.insecure or "0"
			}
		elseif uri[1] == "ss" then
			-- "Lovely" Shadowrocket format
			local suri = uri[2]:split("#")
			local salias = ""
			if table.getn(suri) <= 2 then
				if table.getn(suri) == 2 then
					salias = "#" .. suri[2]
				end
				if b64decode(suri[1]) then
					uri = { "ss", b64decode(suri[1]) .. salias }
				end
			end

			-- SIP002 format https://shadowsocks.org/guide/sip002.html
			local url = URL.parse("http://" .. uri[2])

			local userinfo
			if url.user and url.password then
				-- User info encoded with URIComponent, mostly for ss2022
				userinfo = { url.user, b64decode(url.password) }
			elseif url.user then
				-- User info encoded with base64
				userinfo = b64decode(url.user):split(":")
			end

			if not checkTabValue(shadowsocks_encrypt_method)[userinfo[1]] then
				log("Skipping unsupported Shadowsocks node:", b64decode(alias) or url.host)
				return nil
			end

			local plugin, plugin_opts
			if notEmpty(url.query) and url.query.plugin then
				local plugin_info = url.query.plugin:split(";")
				plugin = plugin_info[1]
				if table.getn(plugin_info) >= 2 then
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
				tpye = "v2ray",
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
			local url = URL.parse("http://" .. uri)

			config = {
				alias = urldecode(url.fragment, true),
				type = "trojan",
				address = url.host,
				port = url.port,
				password = urldecode(url.user, true),
				tls = "1",
				tls_sni = notEmpty(url.query) and url.query.sni or nil
			}
		elseif uri[1] == "vless" then
			-- https://github.com/XTLS/Xray-core/discussions/716
			local url = URL.parse("http://" .. uri)
			local params = url.query

			config = {
				alias = urldecode(url.fragment, true),
				type = "v2ray",
				v2ray_protocol = "vless",
				address = url.host,
				port = url.port,
				v2ray_uuid = url.user,
				v2ray_vless_encrypt = params.encryption or "none",
				v2ray_transport = params.type,
				tls = (params.security == "tls") and "1" or "0",
				tls_sni = params.sni,
				tls_alpn = params.alpn and urldecode(params.alpn, true):split(",") or nil,
				v2ray_xtls = (params.security == "xtls") and "1" or "0",
				v2ray_xtls_flow = params.flow
			}
			if config.v2ray_transport == "grpc" then
				config["grpc_servicename"] = params.serviceName
				config["grpc_mode"] = params.mode or "gun"
			elseif config.v2ray_transport == "h2" then
				config["h2_host"] = notEmpty(params.host) and urldecode(params.host, true):split(",")
				config["h2_path"] = urldecode(params.path, true)
			elseif config.v2ray_transport == "mkcp" then
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
				if config.tcp_header ~= "none" then
					config["tcp_header"] = uri.type
					config["tcp_host"] = notEmpty(params.host) and urldecode(params.host, true):split(',') or nil
					config["tcp_path"] = notEmpty(params.path) and urldecode(params.path, true):split(',') or nil
				end
			elseif config.v2ray_transport == "ws" then
				config["ws_host"] = urldecode(params.host, true)
				config["ws_path"] = urldecode(params.path, true)
				if config.ws_path and config.ws_path:match("\?ed=") then
					config["websocket_early_data_header"] = "Sec-WebSocket-Protocol"
					config["websocket_early_data"] = config.ws_path:split("?ed=")[2]
					config["ws_path"] = config.ws_path:split("?ed=")[1]
				end
			end
		elseif uri[1] == "vmess" then
			-- https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
			uri = JSON.parse(b64decode(uri[2]))

			if not uri or uri.v ~= "2" then
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
				tls_sni = notEmpty(uri.sni) or uri.host,
				tls_alpn = notEmpty(uri.alpn) and uri.alpn:split(",") or nil
			}
			if config.v2ray_transport == "grpc" then
				config["grpc_servicename"] = uri.path
				config["grpc_mode"] = "gun"
			elseif config.v2ray_transport == "h2" then
				config["h2_host"] = notEmpty(uri.host) and uri.host:split(',') or nil
				config["h2_path"] = uri.path
			elseif config.v2ray_transport == "mkcp" then
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
				config["tcp_header"] = notEmpty(uri.type) or "none"
				if config.tcp_header ~= "none" then
					config["tcp_header"] = uri.type
					config["tcp_host"] = notEmpty(uri.host) and uri.host:split(',') or nil
					config["tcp_path"] = notEmpty(uri.path) and uri.path:split(',') or nil
				end
			elseif config.v2ray_transport == "ws" then
				config["ws_host"] = uri.host
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
