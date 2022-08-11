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

function validatePortRange (section_id, value) {
	if (section_id && value) {
		var start_port = parseInt(value.split(':')[0]);
		var end_port = parseInt(value.split(':')[1]);
		var error_message = _('Expecting: %s').format(_('valid port range'));

		if (value.split(':').length !== 2 || (!start_port && !end_port))
			return error_message;
		else if (value.split(':')[0] && (start_port.toString() === 'NaN' || start_port.toString() !== value.split(':')[0]))
			return error_message;
		else if (value.split(':')[1] && (end_port.toString() === 'NaN' || end_port.toString() !== value.split(':')[1]))
			return error_message;
		else if (start_port && (start_port < 1 || start_port > 65535))
			return error_message;
		else if (end_port && (end_port < 1 || end_port > 65535))
			return error_message;
		else if (start_port && end_port && start_port >= end_port)
			return error_message;
	}

	return true;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy')
		]);
	},

	render: function(data) {
		var m, s, o, ss;

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
		var proxy_nodes = {};
		for (var i of uci.sections(data[0], 'node'))
			proxy_nodes[i['.name']] = [ i.type,
				String.format('[%s] %s',
					i.type === 'v2ray' ? i.v2ray_protocol : i.type,
					i.alias || i.server + ':' + i.server_port) ];

		s = m.section(form.NamedSection, 'config', 'homeproxy');

		s.tab('general', _('General Settings'));

		o = s.taboption('general', form.ListValue, 'main_server', _('Main server'));
		o.value('nil', _('Disable'));
		for (var i in proxy_nodes)
			o.value(i, proxy_nodes[i][1]);
		o.default = 'nil';
		o.rmempty = false;

		o = s.taboption('general', form.ListValue, 'main_udp_server', _('Main UDP server'));
		o.value('nil', _('Disable'));
		o.value('same', _('Same as main server'));
		for (var i in proxy_nodes)
			o.value(i, proxy_nodes[i][1]);
		o.default = 'nil';
		o.depends({'routing': 'custom', '!reverse': true});
		o.rmempty = false;

		o = s.taboption('general', form.ListValue, 'routing', _('Routing settings'));
		o.value('disabled', _('Disable'));
		o.value('gfwlist', _('GFWList'));
		o.value('bypass_mainland_china', _('Bypass mainland China'));
		o.value('proxy_mainland_china', _('Only proxy mainland China'));
		o.value('custom', _('Custom routing'));
		o.value('global', _('Global'));
		o.default = '2';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'routing_port', _('Routing ports'),
			_('Specify target port(s) that get proxied. Multiple ports must be separated by commas.'));
		o.value('all', _('All ports'));
		o.value('common', _('Common ports only (bypass P2P traffic)'));
		o.default = 'common';
		o.depends({'routing': 'custom', '!reverse': true});
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (section_id && value !== 'all' && value !== 'common') {
				if (value === null || value === '')
					return _('Expecting: %s').format(_('valid port value'));

				var ports = [];
				for (var i of value.split(',')) {
					var port = parseInt(i);
					if (port.toString() == 'NaN' || port.toString() !== i || port < 1 || port > 65535)
						return _('Expecting: %s').format(_('valid port value'));
					if (ports.includes(i))
						return _('Port %s alrealy exists, please enter other ones.').format(port);
					ports = ports.concat(i);
				}
			}

			return true;
		}

		o = s.taboption('general', form.Value, 'dns_server', _('DNS server'),
			_('You can only have one server set. Custom DNS server format as IP:PORT.'));
		o.value('local', _('Follow system'));
		o.value('wan', _('Use DNS server from WAN'));
		o.value('1.1.1.1:53', _('CloudFlare Public DNS (1.1.1.1:53)'));
		o.value('208.67.222.222:53', _('Cisco Public DNS (208.67.222.222:53)'));
		o.value('8.8.8.8:53', _('Google Public DNS (8.8.8.8:53)'));
		o.value('', _('---'));
		o.value('223.5.5.5:53', _('Aliyun Public DNS (223.5.5.5:53)'));
		o.value('119.29.29.29:53', _('Tencent Public DNS (119.29.29.29:53)'));
		o.value('114.114.114.114:53', _('Xinfeng Public DNS (114.114.114.114:53)'));
		o.default = '8.8.8.8:53';
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
		o.rmempty = false;

		o = s.taboption('general', form.Flag, 'disable_cache', _('Disable dns cache'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.taboption('general', form.Flag, 'sniff', _('Enable sniffing'),
			_('See <a target="_blank" href="https://sing-box.sagernet.org/configuration/route/sniff/">Sniff</a> for details.'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('general', form.Flag, 'sniff_override', _('Override destination'),
			_('Override the connection destination address with the sniffed domain.'));
		o.default = o.enabled;
		o.depends('sniff', '1');
		o.rmempty = false;

		/* FIXME: only show up with "Custom routing" enabled */
		s.tab('routing', _('Custom routing'),
			_('<h4>Advanced routing settings. Only apply when "Custom rouing" is enabled.</h4>'));

		o = s.taboption('routing', form.SectionValue, '_routing', form.GridSection, 'routing', _('Routing settings'));
		ss = o.subsection;
		ss.addremove = true;
		ss.anonymous = true;
		ss.nodescriptions = true;
		ss.sortable = true;
		ss.modaltitle = function(section_id) {
			var label = uci.get(data[0], section_id, 'label');
			return label ? _('Routing rule') + ' » ' + label : _('Add routing rule');
		}

		o = ss.option(form.Value, 'label', _('Label'));
		o.rmempty = false;

		o = ss.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = ss.option(form.ListValue, 'mode', _('Mode'));
		o.value('and', _('And'));
		o.value('or', _('Or'));
		o.default = 'or';
		o.rmempty = false;

		o = ss.option(form.Flag, 'invert', _('Invert'),
			_('Invert match result.'));
		o.default = o.disabled;
		o.rmempty = false;
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
			_('Match source port range. Format as START:/:END/START:END.'));
		o.validate = validatePortRange;
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'port', _('Port'),
			_('Match port.'));
		o.datatype = 'port';
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'port_range', _('Port range'),
			_('Match port range. Format as START:/:END/START:END.'));
		o.validate = validatePortRange;
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'process_name', _('Process name'),
			_('Match process name.'));
		o.modalonly = true;

		o = ss.option(form.ListValue, 'outbound', _('Outbound'),
			_('Tag of the target outbound.'));
		o.value('direct', _('Direct'));
		o.value('block', _('Block'));
		o.value('main', _('Main server'));
		for (var i in proxy_nodes)
			o.value(i, proxy_nodes[i][1]);
		o.rmempty = false;

		o = s.taboption('routing', form.SectionValue, '_dns_server', form.GridSection, 'dns_server', _('DNS servers'));
		ss = o.subsection;
		ss.addremove = true;
		ss.anonymous = true;
		ss.nodescriptions = true;
		ss.sortable = true;
		ss.modaltitle = function(section_id) {
			var tag = uci.get(data[0], section_id, 'tag');
			return tag ? _('DNS server') + ' » ' + tag : _('Add a DNS server');
		}

		o = ss.option(form.Value, 'tag', _('Tag'));
		o.validate = function(section_id, value) {
			if (section_id) {				
				if (value === null || value === '')
					return _('Expecting: non-empty value');
				else if (value === 'main')
					return _('Expecting: %s').format(_('non-preset tag'));
				else if (value.match('[a-zA-Z0-9\-\_]+').toString() !== value)
					return _('Expecting: %s').format(_('letters, numbers, hyphens and underscores only'));
				else if (value.endsWith('-') || value.endsWith('_'))
					return _('Expecting: %s').format(_('end with letters or numbers'));
				else {
					var repeating = false;
					uci.sections(data[0], 'dns_server').forEach(function(res) {
						if (res['.name'] !== section_id && res.tag === value)
							repeating = true;
					});

					if (repeating)
						return _('Expecting: %s').format(_('non-repeating tag'));
				}
			}

			return true;
		}

		o = ss.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = ss.option(form.Value, 'address', _('Address'),
			_('The address of the dns server. Support UDP, TCP, DoT, DoH and RCode.'));
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

		o = ss.option(form.ListValue, 'outbound', _('Outbound'),
			_('Tag of an outbound for connecting to the dns server. Default outbound will be used if empty.'));
		o.value('', _('None'));
		o.value('direct', _('Direct'));
		o.value('main', _('Main server'));
		for (var i in proxy_nodes)
				o.value(i, proxy_nodes[i][1]);

		o = s.taboption('routing', form.SectionValue, '_dns_rule', form.GridSection, 'dns_rule', _('DNS rules'));
		ss = o.subsection;
		ss.addremove = true;
		ss.anonymous = true;
		ss.nodescriptions = true;
		ss.sortable = true;
		ss.modaltitle = function(section_id) {
			var label = uci.get(data[0], section_id, 'label');
			return label ? _('DNS rule') + ' » ' + label : _('Add a DNS rule');
		}

		o = ss.option(form.Value, 'label', _('Label'));
		o.rmempty = false;

		o = ss.option(form.Flag, 'enabled', _('Enable'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = ss.option(form.ListValue, 'mode', _('Mode'));
		o.value('and', _('And'));
		o.value('or', _('Or'));
		o.default = 'or';
		o.rmempty = false;

		o = ss.option(form.Flag, 'invert', _('Invert'),
			_('Invert match result.'));
		o.default = o.disabled;
		o.rmempty = false;
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
			_('Match source port range. Format as START:/:END/START:END.'));
		o.validate = validatePortRange;
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'port', _('Port'),
			_('Match port.'));
		o.datatype = 'port';
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'port_range', _('Port range'),
			_('Match port range. Format as START:/:END/START:END.'));
		o.validate = validatePortRange;
		o.modalonly = true;

		o = ss.option(form.DynamicList, 'process_name', _('Process name'),
			_('Match process name.'));
		o.modalonly = true;

		o = ss.option(form.MultiValue, 'outbound', _('Outbound'),
			_('Match outbound.'));
		o.value('main', _('Main server'));
		for (var i in proxy_nodes)
			o.value(i, proxy_nodes[i][1]);
		o.modalonly = true;

		o = ss.option(form.ListValue, 'server', _('Server'),
			_('Tag of the target dns server.'));
		o.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			for (var i of uci.sections(data[0], 'dns_server'))
				this.value(i.tag);

			return this.super('load', section_id);
		}
		o.rmempty = false;

		o = ss.option(form.Flag, 'disable_cache', _('Disable dns cache'),
			_('Disable cache and save cache in this query.'));
		o.default = o.disabled;
		o.rmempty = false;
		o.modalonly = true;
		
		return m.render();
	}
});
