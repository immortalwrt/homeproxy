/* SPDX-License-Identifier: GPL-2.0-only */

'use strict';

import { popen, readfile, stat, writefile } from 'fs';

const binary = '/usr/bin/sing-box';
const cache = '/etc/homeproxy/sing-box-features.json';

function binaryIdentity() {
	const st = stat(binary);
	return st ? sprintf('%J', [st.dev, st.inode, st.size, st.mtime, st.ctime]) : null;
}

export function getSingBoxFeatures() {
	const identity = binaryIdentity();
	if (!identity)
		return {};

	/* Keep the large Go executable off the page load path, even after reboot. */
	try {
		const saved = json(readfile(cache));
		if (saved?.identity === identity && type(saved.features) === 'object' &&
		    type(saved.features.version) === 'string' && length(saved.features.version))
			return saved.features;
	} catch (e) {}

	let features = {};
	const fd = popen(`${binary} version`);
	if (!fd)
		return features;

	for (let line = fd.read('line'); length(line); line = fd.read('line')) {
		const version = match(trim(line), /^sing-box version (.+)/);
		if (version)
			features.version = version[1];

		const tags = match(trim(line), /^Tags: (.*)/);
		if (tags)
			for (let tag in split(tags[1], ','))
				features[tag] = true;
	}

	/* Never persist failed probes or results from a binary replaced mid-probe. */
	if (fd.close() === 0 && features.version && identity === binaryIdentity())
		writefile(cache, sprintf('%J\n', { identity, features }));

	return features;
};
