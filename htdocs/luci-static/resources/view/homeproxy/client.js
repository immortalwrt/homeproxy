/* SPDX-License-Identifier: GPL-3.0-only
 *
 * Copyright (C) 2022 ImmortalWrt.org
 */

'use strict';
'require form';
'require poll';
'require rpc';
'require uci';
'require view';

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});

function getServiceStatus() {
	return L.resolveDefault(callServiceList('homeproxy'), {}).then(function (res) {
		var isRunning = false;
		try {
			isRunning = res['homeproxy']['instances']['sing_box']['running'];
		} catch (e) { }
		return isRunning;
	});
}

function renderStatus(isRunning) {
	var spanTemp = '<em><span style="color:%s"><strong>%s %s</strong></span></em>';
	var renderHTML;
	if (isRunning) {
		renderHTML = String.format(spanTemp, 'green', _('HomeProxy'), _('RUNNING'));
	} else {
		renderHTML = String.format(spanTemp, 'red', _('HomeProxy'), _('NOT RUNNING'));
	}

	return renderHTML;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy')
		]);
	},

	render: function(data) {
		var m, s, o;

		m = new form.Map('homeproxy', _('HomeProxy'),
			_('The modern ImmortalWrt proxy platform for ARM64/AMD64.'));

		s = m.section(form.TypedSection);
		s.anonymous = true;
		s.render = function () {
			poll.add(function () {
				return L.resolveDefault(getServiceStatus()).then(function (res) {
					var view = document.getElementById("service_status");
					view.innerHTML = renderStatus(res);
				});
			});

			return E('div', { class: 'cbi-section', id: 'status_bar' }, [
					E('p', { id: 'service_status' }, _('Collecting data ...'))
			]);
		}

		/* Cache all configured proxy nodes, they will be called multiple times. */
		var proxy_nodes = {}
		for (var i of uci.sections(data[0], 'node')) {
			proxy_nodes[i['.name']] = String.format('[%s] %s', i.type, i.alias || i.server + ':' + i.server_port);
		}

		s = m.section(form.NamedSection, 'config', 'homeproxy');

		s.tab('general', _('General Settings'));

		o = s.taboption('general', form.ListValue, 'main_server', _('Main server'));
		o.value('nil', _('disabled'));
		for (var i in proxy_nodes)
			o.value(i, proxy_nodes[i]);
		o.default = 'nil';
		o.rmempty = false;

		o = s.taboption('general', form.ListValue, 'main_udp_server', _('Main UDP server'));
		o.value('nil', _('disabled'));
		o.value('same', _('Same as main server'));
		for (var i in proxy_nodes)
			o.value(i, proxy_nodes[i]);
		o.default = 'nil';
		o.depends({'routing': '4', '!reverse': true});

		o = s.taboption('general', form.ListValue, 'routing', _('Routing settings'));
		o.value('0', _('disabled'));
		o.value('1', _('GFWList'));
		o.value('2', _('Bypass mainland China'));
		o.value('3', _('Only proxy mainland China'));
		o.value('4', _('Custom routing'));
		o.value('5', _('Global'));
		o.default = '2';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'routing_port', _('Routing ports'),
			_('Specify target port(s) that get proxied. Multiple ports must be separated by commas.'));
		o.value('all', _('All ports'));
		o.value('common', _('Common ports only (bypass P2P traffic)'));
		o.default = 'common';
		o.depends({'routing': '4', '!reverse': true});
		o.validate = function(section_id, value) {
			if (section_id && value !== 'all' && value !== 'common') {
				if (value == null || value == '')
					return String.format(_('Expecting: %s'), _('valid port value'));

				var ports = [];
				for (var i of value.split(',')) {
					var port = parseInt(i);
					if (port.toString() == 'NaN' || port.toString() !== i || port < 1 || port > 65535)
						return String.format(_('Expecting: %s'), _('valid port value'));
					if (ports.includes(i))
						return String.format(_('Port %s alrealy exists, please enter other ones.'), port);
					ports = ports.concat(i);
				}
			}
			return true;
		}

		o = s.taboption('general', form.ListValue, 'dns_mode', _('DNS resolve mode'));
		o.value('0', _('Follow system settings'));
		o.value('1', _('Hijack DNS only'));
		o.value('2', _('Sniff only'));
		o.value('3', _('Hijack DNS + Sniff'));
		o.default = '3';
		o.depends({'routing': '4', '!reverse': true});

		o = s.taboption('general', form.Value, 'dns_server', _('DNS server'),
			_('You can only have one server set. Custom DNS server format as IP:PORT.'));
		o.value('wan', _('Use DNS server from WAN'));
		o.value('1.1.1.1:53', _('CloudFlare Public DNS (1.1.1.1:53)'));
		o.value('208.67.222.222:53', _('Cisco Public DNS (208.67.222.222:53)'));
		o.value('8.8.8.8:53', _('Google Public DNS (8.8.8.8:53)'));
		o.value('', _('---'));
		o.value('223.5.5.5:53', _('Aliyun Public DNS (223.5.5.5:53)'));
		o.value('119.29.29.29:53', _('Tencent Public DNS (119.29.29.29:53)'));
		o.value('114.114.114.114:53', _('Xinfeng Public DNS (114.114.114.114:53)'));
		o.default = '8.8.8.8:53';
		o.depends('dns_mode', '1');
		o.depends('dns_mode', '3');
		o.validate = function(section_id, value) {
			/* TODO: find a proper way to validate DNS server */
			if (section_id && (value == null || value == ''))
				return _('Expecting: non-empty value');

			return true;
		}

		o = s.taboption('general', form.ListValue, 'dns_strategy', _('DNS strategy'),
			_('The DNS strategy for resolving the domain name in the address.'));
		o.value('prefer_ipv4', _('Prefer IPv4'));
		o.value('prefer_ipv6', _('Prefer IPv6'));
		o.value('ipv4_only', _('IPv4 only'));
		o.value('ipv6_only', _('IPv6 only'));
		o.default = 'prefer_ipv4';
		o.depends('dns_mode', '1');
		o.depends('dns_mode', '3');

		/* FIXME: only show up with "Custom routing" enabled */
		s.tab('routing', _('Custom routing'),
			_('Advanced routing settings. Only apply when "Custom rouing" is enabled.'));

		o = s.taboption('routing', form.SectionValue, '_outbound', form.GridSection, 'outbound', _('Outbound settings'));
		var ss = o.subsection;
		ss.addremove = true;
		ss.anonymous = true;
		ss.sortable = true;

		ss.modaltitle = function(section_id) {
			var tag = uci.get(data[0], section_id, 'tag');
			return tag ? _('Outbound') + ' » ' + tag : _('Add an outbound');
		}

		o = ss.option(form.Value, 'tag', _('Tag'));
		o.rmempty = false;

		o = ss.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = ss.option(form.ListValue, 'server', _('Server'));
		o.value('direct', _('Direct'));
		o.value('block', _('Block'));
		o.value('dns', _('DNS'));
		o.value('urltest', _('URLTest'));
		for (var i in proxy_nodes)
			o.value(i, proxy_nodes[i]);
		o.default = 'direct';
		o.rmempty = false;

		o = ss.option(form.ListValue, 'network', _('Network'));
		o.value('tcp', _('TCP'));
		o.value('udp', _('UDP'));
		o.value('both', _('Both'));
		o.default = 'both';
		o.depends({'server': 'urltest', '!reverse': true});

		/* TODO: use MultiValue */
		o = ss.option(form.DynamicList, 'outbounds', _('Outbounds'),
			_('List of outbound tags to test.'));
		o.depends('server', 'urltest');

		o = ss.option(form.Value, 'url', _('URL'),
			_('The URL to test. http://www.gstatic.com/generate_204 will be used if empty.'));
		o.default = 'http://www.gstatic.com/generate_204';
		o.depends('server', 'urltest');
		o.modalonly = true;

		o = ss.option(form.Value, 'interval', _('Interval'),
			_('The test interval. 1m will be used if empty.'));
		o.default = '1m';
		o.depends('server', 'urltest');
		o.modalonly = true;

		o = ss.option(form.Value, 'tolerance', _('Tolerance'),
			_('The test tolerance in milliseconds. 50 will be used if empty.'));
		o.default = '50';
		o.depends('server', 'urltest');
		o.modalonly = true;

		o = s.taboption('routing', form.SectionValue, '_routing', form.GridSection, 'routing', _('Routing settings'));
		var ss = o.subsection;
		ss.addremove = true;
		ss.anonymous = true;
		ss.sortable = true;

		ss.modaltitle = function(section_id) {
			var label = uci.get(data[0], section_id, 'label');
			return label ? _('Routing rule') + ' » ' + label : _('Add routing rule');
		}

		o = ss.option(form.Value, 'label', _('Label'));
		o.rmempty = false;

		o = ss.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = ss.option(form.ListValue, 'mode', _('Mode'));
		o.value('and', _('And'));
		o.value('or', _('Or'));
		o.default = 'or';
		o.rmempty = false;

		o = ss.option(form.Flag, 'invert', _('Invert'));
		o.default = o.disabled;
		o.modalonly = true;

		o = ss.option(form.ListValue, 'network', _('Network'));
		o.value('tcp', _('TCP'));
		o.value('udp', _('UDP'));
		o.value('both', _('Both'));
		o.default = 'both';
		o.rmempty = false;

		o = ss.option(form.MultiValue, 'protocol', _('Protocol'),
			_('Sniffed protocol, see <a target="_blank" href="https://sing-box.sagernet.org/configuration/route/sniff/">Sniff</a> for details.'));
		o.value('http', _('HTTP'));
		o.value('tls', _('TLS'));
		o.value('quic', _('QUIC'));
		o.value('dns', _('DNS'));

		o = ss.option(form.DynamicList, 'domain', _('Domain name'),
			_('Match full domain.'));
		o.datatype = 'hostname';
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'domain_suffix', _('Domain suffix'),
			_('Match domain suffix.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'domain_keyword', _('Domain keyword'),
			_('Match domain using keyword.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'domain_regex', _('Domain regex'),
			_('Match domain using regular expression.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'geosite', _('Geosite'),
			_('Match geosite.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'source_geoip', _('Source GeoIP'),
			_('Match source geoip.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'geoip', _('GeoIP'),
			_('Match geoip.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'source_ip_cidr', _('Source IP CIDR'),
			_('Match source ip cidr.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'ip_cidr', _('IP CIDR'),
			_('Match ip cidr.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'source_port', _('Source port'),
			_('Match source port.'));
		o.datatype = 'port';
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'source_port_range', _('Source port range'),
			_('Match source port range. Format as START:END.'));
		o.validate = function(section_id, value) {
			if (section_id && value) {
				var start_port = parseInt(value.split(':')[0]);
				var end_port = parseInt(value.split(':')[1]);
				var error_message = String.format(_('Expecting: %s'), _('valid port range (port1:port2)'));
				if (start_port.toString() == 'NaN' || end_port.toString() == 'NaN')
					return error_message;
				else if (start_port.toString() !== value.split(':')[0] || end_port.toString() !== value.split(':')[1])
					return error_message;
				else if (start_port < 1 || start_port > 65535 || end_port < 1 || end_port > 65535 || start_port > end_port)
					return error_message;
			}
			return true;
		}
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'port', _('Port'),
			_('Match port.'));
		o.datatype = 'port';
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'port_range', _('Port range'),
			_('Match port range. Format as START:END.'));
		o.validate = function(section_id, value) {
			if (section_id && value) {
				var start_port = parseInt(value.split(':')[0]);
				var end_port = parseInt(value.split(':')[1]);
				var error_message = String.format(_('Expecting: %s'), _('valid port range (port1:port2)'));
				if (start_port.toString() == 'NaN' || end_port.toString() == 'NaN')
					return error_message;
				else if (start_port.toString() !== value.split(':')[0] || end_port.toString() !== value.split(':')[1])
					return error_message;
				else if (start_port < 1 || start_port > 65535 || end_port < 1 || end_port > 65535 || start_port > end_port)
					return error_message;
			}
			return true;
		}
		o.modalonly = true;

		o = ss.option(form.Value, 'outbound', _('Outbound'),
			_('Tag of the target outbound.'));
		o.rmempty = false;

		/* TODO: use ListValue */
		o = s.taboption('routing', form.Value, 'default_outbound', _('Default outbound tag'),
			_('The first outbound will be used if empty.'));

		o = s.taboption('routing', form.SectionValue, '_dns_server', form.GridSection, 'dns_server', _('DNS servers'));
		var ss = o.subsection;
		ss.addremove = true;
		ss.anonymous = true;
		ss.sortable = true;

		ss.modaltitle = function(section_id) {
			var tag = uci.get(data[0], section_id, 'tag');
			return tag ? _('DNS server') + ' » ' + tag : _('Add a DNS server');
		}

		o = ss.option(form.Value, 'tag', _('Tag'));
		o.rmempty = false;

		o = ss.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = ss.option(form.Value, 'address', _('Address'),
			_('The address of the dns server. Support UDP, TCP, DoT and DoH.'));
		o.value('local', _('Local'));
		o.rmempty = false;

		o = ss.option(form.Value, 'address_resolver', _('Address resolver'),
			_('Tag of a another server to resolve the domain name in the address. Required if address contains domain.'));
		o.modalonly = true;

		o = ss.option(form.ListValue, 'address_strategy', _('Address strategy'),
			_('The domain strategy for resolving the domain name in the address. dns.strategy will be used if empty.'));
		o.value('', _('Default'));
		o.value('prefer_ipv4', _('Prefer IPv4'));
		o.value('prefer_ipv6', _('Prefer IPv6'));
		o.value('ipv4_only', _('IPv4 only'));
		o.value('ipv6_only', _('IPv6 only'));
		o.modalonly = true;

		/* TODO: use ListValue */
		o = ss.option(form.Value, 'detour', _('Detour'),
			_('Tag of an outbound for connecting to the dns server. Default outbound will be used if empty.'));

		/* TODO: use ListValue */
		o = s.taboption('routing', form.Value, 'default_dns', _('Default dns server tag'),
			_('The first server will be used if empty.'));

		o = s.taboption('routing', form.SectionValue, '_dns_rule', form.GridSection, 'dns_rule', _('DNS rules'));
		var ss = o.subsection;
		ss.addremove = true;
		ss.anonymous = true;
		ss.sortable = true;

		ss.modaltitle = function(section_id) {
			var label = uci.get(data[0], section_id, 'label');
			return label ? _('DNS rule') + ' » ' + label : _('Add a DNS rule');
		}

		o = ss.option(form.Value, 'label', _('Label'));
		o.rmempty = false;

		o = ss.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = ss.option(form.ListValue, 'mode', _('Mode'));
		o.value('and', _('And'));
		o.value('or', _('Or'));
		o.default = 'or';
		o.rmempty = false;

		o = ss.option(form.Flag, 'invert', _('Invert'));
		o.default = o.disabled;
		o.modalonly = true;

		o = ss.option(form.ListValue, 'network', _('Network'));
		o.value('tcp', _('TCP'));
		o.value('udp', _('UDP'));
		o.value('both', _('Both'));
		o.default = 'both';
		o.rmempty = false;

		o = ss.option(form.MultiValue, 'protocol', _('Protocol'),
			_('Sniffed protocol, see <a target="_blank" href="https://sing-box.sagernet.org/configuration/route/sniff/">Sniff</a> for details.'));
		o.value('http', _('HTTP'));
		o.value('tls', _('TLS'));
		o.value('quic', _('QUIC'));
		o.value('dns', _('DNS'));

		o = ss.option(form.DynamicList, 'domain', _('Domain name'),
			_('Match full domain.'));
		o.datatype = 'hostname';
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'domain_suffix', _('Domain suffix'),
			_('Match domain suffix.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'domain_keyword', _('Domain keyword'),
			_('Match domain using keyword.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'domain_regex', _('Domain regex'),
			_('Match domain using regular expression.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'geosite', _('Geosite'),
			_('Match geosite.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'source_geoip', _('Source GeoIP'),
			_('Match source geoip.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'geoip', _('GeoIP'),
			_('Match geoip.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'source_ip_cidr', _('Source IP CIDR'),
			_('Match source ip cidr.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'ip_cidr', _('IP CIDR'),
			_('Match ip cidr.'));
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'source_port', _('Source port'),
			_('Match source port.'));
		o.datatype = 'port';
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'source_port_range', _('Source port range'),
			_('Match source port range. Format as START:END.'));
		o.validate = function(section_id, value) {
			if (section_id && value) {
				var start_port = parseInt(value.split(':')[0]);
				var end_port = parseInt(value.split(':')[1]);
				var error_message = String.format(_('Expecting: %s'), _('valid port range (port1:port2)'));
				if (start_port.toString() == 'NaN' || end_port.toString() == 'NaN')
					return error_message;
				else if (start_port.toString() !== value.split(':')[0] || end_port.toString() !== value.split(':')[1])
					return error_message;
				else if (start_port < 1 || start_port > 65535 || end_port < 1 || end_port > 65535 || start_port > end_port)
					return error_message;
			}
			return true;
		}
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'port', _('Port'),
			_('Match port.'));
		o.datatype = 'port';
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'port_range', _('Port range'),
			_('Match port range. Format as START:END.'));
		o.validate = function(section_id, value) {
			if (section_id && value) {
				var start_port = parseInt(value.split(':')[0]);
				var end_port = parseInt(value.split(':')[1]);
				var error_message = String.format(_('Expecting: %s'), _('valid port range (port1:port2)'));
				if (start_port.toString() == 'NaN' || end_port.toString() == 'NaN')
					return error_message;
				else if (start_port.toString() !== value.split(':')[0] || end_port.toString() !== value.split(':')[1])
					return error_message;
				else if (start_port < 1 || start_port > 65535 || end_port < 1 || end_port > 65535 || start_port > end_port)
					return error_message;
			}
			return true;
		}
		o.modalonly = true;

		/* TODO: use MultiValue */
		o = ss.option(form.DynamicList, 'outbound', _('Outbound'),
			_('Match outbound.'));
		o.modalonly = true;

		/* TODO: use ListValue */
		o = ss.option(form.Value, 'server', _('Server'),
			_('Tag of the target dns server.'));
		o.rmempty = false;

		o = s.taboption('routing', form.ListValue, 'default_dns_strategy', _('Default domain strategy'),
			_('Default domain strategy for resolving the domain names.'));
		o.value('prefer_ipv4', _('Prefer IPv4'));
		o.value('prefer_ipv6', _('Prefer IPv6'));
		o.value('ipv4_only', _('IPv4 only'));
		o.value('ipv6_only', _('IPv6 only'));
		o.rmempty = false;

		o = s.taboption('routing', form.Flag, 'sniff_override', _('Enable sniff'),
			_('Override the connection destination address with the sniffed domain.'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('routing', form.Flag, 'disable_cache', _('Disable dns cache'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.taboption('routing', form.Flag, 'disable_expire', _('Disable dns cache expire'));
		o.default = o.disabled;
		o.rmempty = false;

		return m.render();
	}
});
