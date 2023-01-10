/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2023 ImmortalWrt.org
 */

'use strict';
'require dom';
'require form';
'require fs';
'require poll';
'require ui';
'require view';

/* Thanks to luci-app-aria2 */
var css = '				\
#log_textarea {				\
	padding: 10px;			\
	text-align: left;		\
}					\
#log_textarea pre {			\
	padding: .5rem;			\
	word-break: break-all;		\
	margin: 0;			\
}					\
.description {				\
	background-color: #33ccff;	\
}';

var hp_dir = '/var/run/homeproxy',
    hp_geoupdater = '/etc/homeproxy/scripts/update_geodata.sh';

return view.extend({
	load: function() {
		return Promise.all([
			fs.read(hp_dir + '/homeproxy.log', 'text') .then((res) => {
				return res.trim() || _('Log is clean.');
			}).catch((err) => {
				var log;
				if (err.toString().includes('NotFoundError'))
					log = _('Log file does not exist.');
				else
					log = _('Unknown error: %s').format(err);
				return log;
			})
		])
	},

	render: function(data) {
		var m, s, o;

		m = new form.Map('homeproxy');

		s = m.section(form.NamedSection, 'config', 'homeproxy', _('Resources management'));
		s.anonymous = true;

		o = s.option(form.DummyValue, '_geodata_version', _('GeoData version'));
		o.cfgvalue = function() {
			var errSpanTemp = '<div style="margin-top:5px"><strong style="color:red">%s<strong></div>';
			return fs.exec(hp_geoupdater, [ 'get_version' ]).then((res) => {
				var spanTemp = '<div style="margin-top:5px;">%s</div>';
				if (res.stdout.trim())
					this.default = spanTemp.format(res.stdout.trim());
				else {
					ui.addNotification(null, E('p', [ _('Unknown error: %s').format(res) ]));
					this.default = errSpanTemp.format(_('unknown error'));
				}

				return null;
			}).catch((err) => {
				ui.addNotification(null, E('p', [ _('Unknown error: %s').format(err) ]));
				this.default = errSpanTemp.format(_('unknown error'));

				return null;
			});
		}
		o.rawhtml = true;

		o = s.option(form.Button, '_update_geodata', _('Update GeoData'));
		o.inputstyle = 'action';
		o.onclick = function() {
			return fs.exec(hp_geoupdater, [ 'update_version' ]).then((res) => {
					if (res.code === 0)
						this.description = _('Successfully updated');
					else if (res.code === 1)
						this.description = _('Update failed');
					else if (res.code === 2)
						this.description = _('Already in updating');
					else if (res.code === 3)
						this.description = _('Already at the latest version');

				return this.map.reset();
			}).catch((err) => {
				ui.addNotification(null, E('p', [ _('Unknown error: %s').format(err) ]));
				this.description = _('Update failed');
				return this.map.reset();
			});
		}

		o = s.option(form.DummyValue, '_homeproxy_logview');
		o.render = function() {
			return E([
				E('style', [ css ]),
				E('div', {'class': 'cbi-map'}, [
					E('h3', {'name': 'content'}, _('HomeProxy log')),
					E('div', {'class': 'cbi-section'}, [
						E('div', { 'id': 'log_textarea' },
							E('pre', { 'wrap': 'pre' }, [ data[0] ])
						)
					])
				])
			]);
		}

		o = s.option(form.DummyValue, '_sing-box_logview');
		o.render = function() {
			var log_textarea = E('div', { 'id': 'log_textarea' },
				E('img', {
					'src': L.resource(['icons/loading.gif']),
					'alt': _('Loading'),
					'style': 'vertical-align:middle'
				}, _('Collecting data...'))
			);

			var log;
			poll.add(L.bind(function() {
				return fs.read_direct(hp_dir + '/sing-box.log', 'text')
				.then(function(res) {
					log = E('pre', { 'wrap': 'pre' }, [
						res.trim() || _('Log is clean.')
					]);

					dom.content(log_textarea, log);
				}).catch(function(err) {
					if (err.toString().includes('NotFoundError'))
						log = E('pre', { 'wrap': 'pre' }, [
							_('Log file does not exist.')
						]);
					else
						log = E('pre', { 'wrap': 'pre' }, [
							_('Unknown error: %s').format(err)
						]);

					dom.content(log_textarea, log);
				});
			}));

			return E([
				E('style', [ css ]),
				E('div', {'class': 'cbi-map'}, [
					E('h3', {'name': 'content'}, _('Sing-box log')),
					E('div', {'class': 'cbi-section'}, [
						log_textarea,
						E('div', {'style': 'text-align:right'},
							E('small', {}, _('Refresh every %s seconds.').format(L.env.pollinterval))
						)
					])
				])
			]);
		}

		return m.render();
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
