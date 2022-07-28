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
			isRunning = res['homeproxy']['instances']['sing_box_server']['running'];
		} catch (e) { }
		return isRunning;
	});
}

function renderStatus(isRunning) {
	var spanTemp = '<em><span style="color:%s"><strong>%s %s</strong></span></em>';
	var renderHTML;
	if (isRunning) {
		renderHTML = String.format(spanTemp, 'green', _('HomeProxy Server'), _('RUNNING'));
	} else {
		renderHTML = String.format(spanTemp, 'red', _('HomeProxy Server'), _('NOT RUNNING'));
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

		m = new form.Map('homeproxy', _('HomeProxy Server'),
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

		s = m.section(form.NamedSection, 'server', 'homeproxy', _('Global settings'));

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.disabled;
		o.rmempty = false;

		s = m.section(form.GridSection, 'server');
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;
		s.modaltitle = function(section_id) {
			var alias = uci.get(data[0], section_id, 'alias');
			return alias ? _('Server') + ' » ' + alias : _('Add a server');
		}

		o = s.option(form.Value, 'alias', _('Alias'));
		o.rmempty = false;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.disabled;
		o.rmempty = false;
		o.editable = true;

		o = s.option(form.ListValue, 'type', _('Type'));
		o.value('http', _('HTTP'));
		o.value('shadowsocks', _('Shadowsocks'));
		o.value('socks', _('Socks'));
		o.rmempty = false;

		o = s.option(form.Value, 'port', _('Port'),
			_('The port must be unique.'));
		o.datatype = 'port';
		o.rmempty = false;

		o = s.option(form.DynamicList, 'username_password', _('Username / Password'),
			_('Format as user:pass.'));
		o.depends('type', 'http');
		o.depends('type', 'socks');
		o.validate = function(section_id, value) {
			if (section_id && value !== null && value !== '') {
				var user = value.split(':')[0], pass = value.split(':')[1];
				if (value.split(':').length > 2 || !user || !pass)
					return _('Expecting: %s').format('valid user:pass pair');
			}

			return true;
		}
		o.modalonly = true;

		o = s.option(form.Value, 'shadowsocks_password', _('Password'));
		o.password = true;
		o.depends('type', 'shadowsocks');
		o.validate = function(section_id, value) {
			if (section_id && (value === null || value === '')) {
				return _('Expecting: non-empty value');
			}

			return true;
		}
		o.modalonly = true;

		o = s.option(form.ListValue, 'shadowsocks_encrypt_method', _('Encrypt method'));
		o.value('none');
		o.value('plain');
		o.value('aes-128-gcm');
		o.value('aes-192-gcm');
		o.value('aes-256-gcm');
		o.value('chacha20-ietf-poly1305');
		o.value('xchacha20-ietf-poly1305');
		o.value('2022-blake3-aes-128-gcm');
		o.value('2022-blake3-aes-256-gcm');
		o.value('2022-blake3-chacha20-poly1305');
		o.default = 'aes-128-gcm';
		o.depends('type', 'shadowsocks');
		o.depends({'type': 'v2ray', 'v2ray_protocol': 'shadowsocks'});
		o.modalonly = true;

		o = s.option(form.Flag, 'sniff_override', _('Enable sniff'),
			_('Override the connection destination address with the sniffed domain.'));
		o.default = o.enabled;
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.ListValue, 'network', _('Network'));
		o.value('tcp', _('TCP'));
		o.value('udp', _('UDP'));
		o.value('both', _('Both'));
		o.default = 'both';
		o.depends('type', 'shadowsocks');
		o.modalonly = true;

		return m.render();
	}
});