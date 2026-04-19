/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';
'require form';
'require view';
'require uci';
'require poll';
'require rpc';
'require ui';
'require tools.homeproxy as hp';

function renderStatus(running) {
	return updateStatus(E('input', { id: 'core_status', style: 'border: unset; font-style: italic; font-weight: bold;', readonly: '' }), running);
}

function updateStatus(element, running) {
	if (element) {
		element.style.color = running ? 'green' : 'red';
		element.value = running ? _('Running') : _('Not Running');
	}
	return element;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('homeproxy'),
			hp.getBuiltinFeatures(),
			hp.status()
		]);
	},

	render: function(data) {
		const features = data[1];
		const running = data[2];

		let m, s, o;

		m = new form.Map('homeproxy', _('HomeProxy Dashboard'), _('Control panel for HomeProxy service'));

		s = m.section(form.TableSection, 'placeholder', _('Status'));
		s.anonymous = true;

		o = s.option(form.Value, '_core_version', _('Core Version'));
		o.readonly = true;
		o.load = function() {
			return features.version || _('Unknown');
		};
		o.write = function() {};

		o = s.option(form.DummyValue, '_core_status', _('Core Status'));
		o.cfgvalue = function() {
			return renderStatus(running);
		};
		poll.add(function() {
			return L.resolveDefault(hp.status()).then(function(running) {
				updateStatus(document.getElementById('core_status'), running);
			});
		});

		o = s.option(form.Button, 'reload');
		o.inputstyle = 'action';
		o.inputtitle = _('Reload Service');
		o.onclick = function() {
			return hp.reload();
		};

		o = s.option(form.Button, 'restart');
		o.inputstyle = 'negative';
		o.inputtitle = _('Restart Service');
		o.onclick = function() {
			return hp.restart();
		};

		o = s.option(form.Button, 'update_dashboard');
		o.inputstyle = 'positive';
		o.inputtitle = _('Update Dashboard');
		o.onclick = function() {
			return hp.updateDashboard();
		};

		o = s.option(form.Button, 'open_dashboard');
		o.inputtitle = _('Open Dashboard');
		o.onclick = function() {
			return hp.openDashboard();
		};

		s = m.section(form.NamedSection, 'config', 'homeproxy', _('Dashboard Config'));

		o = s.option(form.Flag, 'dashboard_enabled', _('Enable Dashboard'));
		o.rmempty = false;
		o.default = o.disabled;

		o = s.option(form.ListValue, 'dashboard_type', _('Dashboard Type'));
		o.value('zashboard', 'Zashboard');
		o.value('metacubexd', 'MetaCubeXD');
		o.value('yacd', 'YACD');
		o.value('razord', 'Razord');
		o.default = 'zashboard';
		o.depends('dashboard_enabled', '1');

		o = s.option(form.Value, 'dashboard_port', _('Dashboard Port'));
		o.datatype = 'port';
		o.placeholder = '9090';
		o.depends('dashboard_enabled', '1');

		o = s.option(form.Value, 'dashboard_secret', _('Dashboard Secret'));
		o.password = true;
		o.placeholder = _('Auto generated');
		o.depends('dashboard_enabled', '1');

		o = s.option(form.Value, 'dashboard_ui_path', _('UI Path'));
		o.placeholder = '/etc/homeproxy/ui';
		o.depends('dashboard_enabled', '1');

		o = s.option(form.Value, 'dashboard_ui_download_url', _('UI Download URL'));
		o.placeholder = 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip';
		o.value('https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip', 'Zashboard (CDN Fonts)');
		o.value('https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip', 'Zashboard');
		o.value('https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip', 'MetaCubeXD');
		o.value('https://github.com/MetaCubeX/Yacd-meta/archive/refs/heads/gh-pages.zip', 'YACD');
		o.value('https://github.com/MetaCubeX/Razord-meta/archive/refs/heads/gh-pages.zip', 'Razord');
		o.depends('dashboard_enabled', '1');

		return m.render();
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
