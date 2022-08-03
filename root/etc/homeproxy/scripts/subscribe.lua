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

local JSON = { parse = luci.jsonc.parse, dump = luci.jsonc.stringify }
local URL = require "url"

local function b64decode(str)
	if not str or #str == 0 then
		return nil
	end

	str = str:gsub("_", "/"):gsub("-", "+")

	local padding = #str % 4
	str = str .. string.sub('====', padding + 1)

	return nixio.bin.b64decode(str)
end

local function urldecode(str)
	if not str or #str == 0 then
		return nil
	end

	str = str:gsub('+', ' '):gsub('%%(%x%x)', function(h)
		return string.char(tonumber(h, 16))
	end)

	return str
end
-- String parser end

-- String helper start
local function isEmpty(res)
	return res == nil or res == "" or (type(res) == "table" and next(res) == nil)
end

local function notEmpty(res)
	return not isEmpty(res) and res
end

-- https://www.04007.cn/article/135.html
local function checkTabValue(tab)
	local revtab = {}

	for k,v in pairs(tab) do
		revtab[v] = true
	end

	return revtab
end
-- String helper end

local function log(...)
	-- TODO: write to log file directly
	print(os.date("%Y-%m-%d %H:%M:%S [SUBSCRIBE UPDATE] ") .. table.concat({...}, " "))
end

local function parse_uri(uri)
	local config

	uri = uri:split("://")
	if uri[1] == "ss" then
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
		local url = URL.parse('http://' .. uri[2])
		local alias = urldecode(url.fragment)

		local userinfo
		if url.user and url.password then
			-- User info encoded with URIComponent, mostly for ss2022
			userinfo = { url.user, b64decode(url.password) }
		elseif url.user then
			-- User info encoded with base64
			userinfo = b64decode(url.user):split(":")
		end

		local plugin, plugin_opts
		if notEmpty(url.query) and url.query.plugin then
			local plugin_info = url.query.plugin:split(";")
			plugin = plugin_info[1]
			if table.getn(plugin_info) >= 2 then
				plugin_opts = table.concat(table.splice(plugin_info, 1, 1), ";")
			end
		end

		-- Check if address, method and password exist
		if not (url.host and table.getn(userinfo) == 2 and checkTabValue(shadowsocks_encrypt_method)[userinfo[1]]) then
			log('Skipping invalid Shadowsocks node:', b64decode(alias) or url.host)
			return nil
		end

		config = {
			alias = alias,
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
		local params = URL.parseQuery(uri[2]:gsub('^\?', ''))

		-- Check if address, method and password exist
		if isEmpty(userinfo[1]) or isEmpty(userinfo[4]) or isEmpty(userinfo[6]) then
			log("Skipping invalid ShadowsocksR node:", b64decode(params.remarks) or userinfo[0])
			return nil
		end

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
		local url = URL.parse('http://' .. uri)

		-- Check if address and password exist
		if not (url.host and url.user) then
			log("Skipping invalid Trojan node:", urldecode(url.fragment) or url.host)
			return nil
		end

		config = {
			alias = urldecode(url.fragment),
			type = "v2ray",
			v2ray_protocol = "trojan",
			address = url.host,
			port = url.port,
			password = urldecode(url.user),
			tls = "1",
			tls_sni = notEmpty(url.query) and url.query.sni or nil
		}
	elseif uri[1] == "vless" then
		-- https://github.com/XTLS/Xray-core/discussions/716
		local url = URL.parse('http://' .. uri)

		-- Check if address, uuid and type exist
		if not (url.host and url.user and notEmpty(url.query) and url.query.type) then
			log("Skipping invalid VLESS node:", urldecode(url.fragment) or url.host)
			return nil
		end

		config = {
			alias = urldecode(url.fragment),
			type = "v2ray",
			v2ray_protocol = "vless",
			address = url.host,
			port = url.port,
			v2ray_uuid = url.user,
			v2ray_vless_encrypt = url.query.encryption or "none",
			v2ray_transport = url.query.type,
			tls = (url.query.security == "tls") and "1" or "0",
			tls_sni = url.query.sni,
			tls_alpn = url.query.alpn and urldecode(url.query.alpn):split(",") or nil,
			v2ray_xtls = (url.query.security == "xtls") and "1" or "0",
			v2ray_xtls_flow = url.query.flow
		}
		if config.v2ray_transport == "grpc" then
			config["grpc_servicename"] = url.query.serviceName
			config["grpc_mode"] = url.query.mode or "gun"
		elseif string.match("h2,tcp,ws", config.v2ray_transport) then
			config["http_header"] = (config.v2ray_transport == "tcp") and (url.query.headerType or "none") or nil
			config["h2_host"] = url.query.host and urldecode(url.query.host) or nil
			config["h2_path"] = url.query.path and urldecode(url.query.path) or nil
			if config.h2_path and config.h2_path:match("\?ed=") then
				config["websocket_early_data_header"] = "Sec-WebSocket-Protocol"
				config["websocket_early_data"] = config.h2_path:split('?ed=')[2]
				config["h2_path"] = config.h2_path:split("?ed=")[1]
			end
		elseif config.v2ray_transport == "mkcp" then
			config["mkcp_seed"] = url.query.seed
			config["mkcp_header"] = url.query.headerType or "none"
			-- Default settings from v2rayN
			config["mkcp_downlink_capacity"] = "100"
			config["mkcp_uplink_capacity"] = "12"
			config["mkcp_read_buffer_size"] = "2"
			config["mkcp_write_buffer_size"] = "2"
			config["mkcp_mtu"] = "1350"
			config["mkcp_tti"] = "50"
		elseif config.v2ray_transport == "quic" then
			config["quic_security"] = url.query.quicSecurity or "none"
			config["quic_key"] = url.query.key
			config["mkcp_header"] = url.query.headerType or "none"
		end
	elseif uri[1] == "vmess" then
		-- https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
		uri = JSON.parse(b64decode(uri[2]))
		if uri.v == "2" then
			-- Check if address, uuid, type, and alterId exist
			-- https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6
			if isEmpty(uri) or isEmpty(uri.add) or isEmpty(uri.id) or isEmpty(uri.net) or (notEmpty(uri.aid) and tonumber(uri.aid) ~= 0) then
				log("Skipping invalid VMess node:", uri.alias or uri.add)
				return nil
			end

			config = {
				alias = uri.ps,
				type = "v2ray",
				v2ray_protocol = "vmess",
				address = uri.add,
				port = uri.port,
				v2ray_uuid = uri.id,
				v2ray_vmess_encrypt = uri.scy or "auto",
				v2ray_transport = uri.net,
				tls = (uri.tls == "tls") and "1" or "0",
				tls_sni = uri.sni or uri.host,
				tls_alpn = notEmpty(uri.alpn) and uri.alpn:split(',') or nil
			}
			if config.v2ray_transport == "grpc" then
				config["grpc_servicename"] = uri.path
				config["grpc_mode"] = "gun"
			elseif string.match("h2,tcp,ws", config.v2ray_transport) then
				config["http_header"] = (config.v2ray_transport == "tcp") and (notEmpty(uri.type) or "none") or nil
				config["h2_host"] = uri.host
				config["h2_path"] = uri.path
				if notEmpty(config.h2_path) and config.h2_path:match("\?ed=") then
					config["websocket_early_data_header"] = "Sec-WebSocket-Protocol"
					config["websocket_early_data"] = config.h2_path:split('?ed=')[2]
					config["h2_path"] = config.h2_path:split("?ed=")[1]
				end
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
			end
		else
			return nil
		end
	end

	return config
end
