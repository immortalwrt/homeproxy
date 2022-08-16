/* SPDX-License-Identifier: GPL-3.0-only
 *
 * Copyright (C) 2022 ImmortalWrt.org
 */

'use strict';
'require form';
'require poll';
'require rpc';
'require uci';
'require validation';
'require view';
'require tools.widgets as widgets';

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
		value = value.match(/^(\d+)?\:(\d+)?$/);
		if (value && (value[1] || value[2])) {
			if (!value[1])
				value[1] = 0;
			else if (!value[2])
				value[2] = 65535;

			if (value[1] < value[2] && value[2] <= 65535)
				return true;
		}

		return _('Expecting: %s').format( _('valid port range (port1:port2)'));
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
		var m, s, o, ss, so;

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
		uci.sections(data[0], 'node', function(res) {
			proxy_nodes[res['.name']] = [ res.type,
				String.format('[%s] %s',
					res.type === 'v2ray' ? res.v2ray_protocol : res.type,
					res.label || res.server + ':' + res.server_port) ];
		});

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
		o.depends({'routing_mode': 'custom', '!reverse': true});
		o.rmempty = false;

		o = s.taboption('general', form.ListValue, 'routing_mode', _('Routing settings'));
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
		o.depends({'routing_mode': 'custom', '!reverse': true});
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
			_('You can only have one server set. Custom DNS server format as plain IPv4/IPv6.'));
		o.value('local', _('Follow system'));
		o.value('wan', _('Use DNS server from WAN'));
		o.value('1.1.1.1', _('CloudFlare Public DNS (1.1.1.1)'));
		o.value('208.67.222.222', _('Cisco Public DNS (208.67.222.222)'));
		o.value('8.8.8.8', _('Google Public DNS (8.8.8.8)'));
		o.value('', _('---'));
		o.value('223.5.5.5', _('Aliyun Public DNS (223.5.5.5)'));
		o.value('119.29.29.29', _('Tencent Public DNS (119.29.29.29)'));
		o.value('114.114.114.114', _('Xinfeng Public DNS (114.114.114.114)'));
		o.default = '8.8.8.8';
		o.validate = function(section_id, value) {
			if (!['local', 'wan'].includes(value)
					&& !(validation.parseIPv4(value) || validation.parseIPv6(value)))
				return _('Expecting: %s').format(_('valid IP address'));

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

		o = s.taboption('general', form.Flag, 'sniff_override', _('Override destination'),
			_('Override the connection destination address with the sniffed domain.'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('general', widgets.DeviceSelect, 'default_interface', _('Default interface'),
			_('Bind outbound connections to the specified NIC by default. Auto detect if leave empty.'));
		o.multiple = false;
		o.noaliases = true;
		o.nobridges = true;

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

		so = ss.option(form.Value, 'label', _('Label'));
		so.rmempty = false;

		so = ss.option(form.Flag, 'enabled', _('Enable'));
		so.default = so.disabled;
		so.rmempty = false;
		so.editable = true;

		so = ss.option(form.ListValue, 'mode', _('Mode'),
			_('The default rule uses the following matching logic:<br/>' +
			'<code>(domain || domain_suffix || domain_keyword || domain_regex || geosite || geoip || ip_cidr)</code> &&<br/>' +
			'<code>(source_geoip || source_ip_cidr)</code> &&<br/>' +
			'<code>other fields</code>.'));
		so.value('default', _('Default'));
		so.value('and', _('And'));
		so.value('or', _('Or'));
		so.default = 'default';
		so.rmempty = false;

		so = ss.option(form.Flag, 'invert', _('Invert'),
			_('Invert match result.'));
		so.default = so.disabled;
		so.rmempty = false;
		so.modalonly = true;

		so = ss.option(form.ListValue, 'network', _('Network'));
		so.value('tcp', _('TCP'));
		so.value('udp', _('UDP'));
		so.value('both', _('Both'));
		so.default = 'both';
		so.rmempty = false;

		so = ss.option(form.MultiValue, 'protocol', _('Protocol'),
			_('Sniffed protocol, see <a target="_blank" href="https://sing-box.sagernet.org/configuration/route/sniff/">Sniff</a> for details.'));
		so.value('http', _('HTTP'));
		so.value('tls', _('TLS'));
		so.value('quic', _('QUIC'));
		so.value('dns', _('DNS'));

		so = ss.option(form.DynamicList, 'domain', _('Domain name'),
			_('Match full domain.'));
		so.datatype = 'hostname';
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'domain_suffix', _('Domain suffix'),
			_('Match domain suffix.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'domain_keyword', _('Domain keyword'),
			_('Match domain using keyword.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'domain_regex', _('Domain regex'),
			_('Match domain using regular expression.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'geosite', _('Geosite'),
			_('Match geosite.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'source_geoip', _('Source GeoIP'),
			_('Match source geoip.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'geoip', _('GeoIP'),
			_('Match geoip.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'source_ip_cidr', _('Source IP CIDR'),
			_('Match source ip cidr.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'ip_cidr', _('IP CIDR'),
			_('Match ip cidr.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'source_port', _('Source port'),
			_('Match source port.'));
		so.datatype = 'port';
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'source_port_range', _('Source port range'),
			_('Match source port range. Format as START:/:END/START:END.'));
		so.validate = validatePortRange;
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'port', _('Port'),
			_('Match port.'));
		so.datatype = 'port';
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'port_range', _('Port range'),
			_('Match port range. Format as START:/:END/START:END.'));
		so.validate = validatePortRange;
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'process_name', _('Process name'),
			_('Match process name.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'user', _('User'),
			_('Match user name.'));
		so.modalonly = true;

		so = ss.option(form.ListValue, 'outbound', _('Outbound'),
			_('Tag of the target outbound.'));
		so.value('direct', _('Direct'));
		so.value('block', _('Block'));
		so.value('main', _('Main server'));
		for (var i in proxy_nodes)
			so.value(i, proxy_nodes[i][1]);
		so.rmempty = false;

		o = s.taboption('routing', form.SectionValue, '_dns_server', form.GridSection, 'dns_server', _('DNS servers'));
		ss = o.subsection;
		ss.addremove = true;
		ss.anonymous = true;
		ss.nodescriptions = true;
		ss.sortable = true;
		ss.modaltitle = function(section_id) {
			var label = uci.get(data[0], section_id, 'label');
			return label ? _('DNS server') + ' » ' + label : _('Add a DNS server');
		}

		so = ss.option(form.Value, 'label', _('Label'));
		so.rmempty = false;

		so = ss.option(form.Flag, 'enabled', _('Enable'));
		so.default = o.disabled;
		so.rmempty = false;
		so.editable = true;

		so = ss.option(form.Value, 'address', _('Address'),
			_('The address of the dns server. Support UDP, TCP, DoT, DoH and RCode.'));
		so.value('local', _('Local'));
		so.rmempty = false;

		so = ss.option(form.ListValue, 'address_resolver', _('Address resolver'),
			_('Tag of a another server to resolve the domain name in the address. Required if address contains domain.'));
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			var _this = this;
			_this.value('', _('None'));
			_this.value('main', _('Main DNS server'));
			uci.sections(data[0], 'dns_server', function(res) {
				if (res['.name'] !== section_id)
					_this.value(res['.name'], res.label);
			});

			return this.super('load', section_id);
		}
		so.modalonly = true;

		so = ss.option(form.ListValue, 'address_strategy', _('Address strategy'),
			_('The domain strategy for resolving the domain name in the address. dns.strategy will be used if empty.'));
		so.value('', _('Default'));
		so.value('prefer_ipv4', _('Prefer IPv4'));
		so.value('prefer_ipv6', _('Prefer IPv6'));
		so.value('ipv4_only', _('IPv4 only'));
		so.value('ipv6_only', _('IPv6 only'));
		so.modalonly = true;

		so = ss.option(form.ListValue, 'outbound', _('Outbound'),
			_('Tag of an outbound for connecting to the dns server. Default outbound will be used if empty.'));
		so.value('', _('None'));
		so.value('direct', _('Direct'));
		so.value('main', _('Main server'));
		for (var i in proxy_nodes)
			so.value(i, proxy_nodes[i][1]);

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

		so = ss.option(form.Value, 'label', _('Label'));
		so.rmempty = false;

		so = ss.option(form.Flag, 'enabled', _('Enable'));
		so.default = so.disabled;
		so.rmempty = false;
		so.editable = true;

		so = ss.option(form.ListValue, 'mode', _('Mode'),
			_('The default rule uses the following matching logic:<br/>' +
			'<code>(domain || domain_suffix || domain_keyword || domain_regex || geosite || geoip || ip_cidr)</code> &&<br/>' +
			'<code>(source_geoip || source_ip_cidr)</code> &&<br/>' +
			'<code>other fields</code>.'));
		so.value('default', _('Default'));
		so.value('and', _('And'));
		so.value('or', _('Or'));
		so.default = 'default';
		so.rmempty = false;

		so = ss.option(form.Flag, 'invert', _('Invert'),
			_('Invert match result.'));
		so.default = so.disabled;
		so.rmempty = false;
		so.modalonly = true;

		so = ss.option(form.ListValue, 'network', _('Network'));
		so.value('tcp', _('TCP'));
		so.value('udp', _('UDP'));
		so.value('both', _('Both'));
		so.default = 'both';
		so.rmempty = false;

		so = ss.option(form.MultiValue, 'protocol', _('Protocol'),
			_('Sniffed protocol, see <a target="_blank" href="https://sing-box.sagernet.org/configuration/route/sniff/">Sniff</a> for details.'));
		so.value('http', _('HTTP'));
		so.value('tls', _('TLS'));
		so.value('quic', _('QUIC'));
		so.value('dns', _('DNS'));

		so = ss.option(form.DynamicList, 'domain', _('Domain name'),
			_('Match full domain.'));
		so.datatype = 'hostname';
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'domain_suffix', _('Domain suffix'),
			_('Match domain suffix.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'domain_keyword', _('Domain keyword'),
			_('Match domain using keyword.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'domain_regex', _('Domain regex'),
			_('Match domain using regular expression.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'geosite', _('Geosite'),
			_('Match geosite.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'source_geoip', _('Source GeoIP'),
			_('Match source geoip.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'geoip', _('GeoIP'),
			_('Match geoip.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'source_ip_cidr', _('Source IP CIDR'),
			_('Match source ip cidr.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'ip_cidr', _('IP CIDR'),
			_('Match ip cidr.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'source_port', _('Source port'),
			_('Match source port.'));
		so.datatype = 'port';
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'source_port_range', _('Source port range'),
			_('Match source port range. Format as START:/:END/START:END.'));
		so.validate = validatePortRange;
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'port', _('Port'),
			_('Match port.'));
		so.datatype = 'port';
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'port_range', _('Port range'),
			_('Match port range. Format as START:/:END/START:END.'));
		so.validate = validatePortRange;
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'process_name', _('Process name'),
			_('Match process name.'));
		so.modalonly = true;

		so = ss.option(form.DynamicList, 'user', _('User'),
			_('Match user name.'));
		so.modalonly = true;

		so = ss.option(form.MultiValue, 'outbound', _('Outbound'),
			_('Match outbound.'));
		so.value('main', _('Main server'));
		for (var i in proxy_nodes)
			so.value(i, proxy_nodes[i][1]);
		so.modalonly = true;

		so = ss.option(form.ListValue, 'server', _('Server'),
			_('Tag of the target dns server.'));
		so.load = function(section_id) {
			delete this.keylist;
			delete this.vallist;

			var _this = this;
			_this.value('main', _('Main DNS server'));
			_this.value('block', _('Block DNS queries'));
			uci.sections(data[0], 'dns_server', function(res) {
				_this.value(res['.name'], res.label);
			});

			return this.super('load', section_id);
		}
		so.rmempty = false;

		so = ss.option(form.Flag, 'dns_disable_cache', _('Disable dns cache'),
			_('Disable cache and save cache in this query.'));
		so.default = so.disabled;
		so.rmempty = false;
		so.modalonly = true;
		
		return m.render();
	}
});
