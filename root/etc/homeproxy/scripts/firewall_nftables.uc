#!/usr/bin/utpl -S
#!/usr/sbin/nft -f

{%
	/* Common var start */
	const tunname = 'singtun0';
	const proxy_mark = '0x64';
	/* Common var end */

	/* UCI config start */
	import { cursor } from 'uci';

	const cfgname = 'homeproxy';
	const uci = cursor();
	uci.load(cfgname);

	/* Client config start */
	let routing_mode = uci.get(cfgname, 'config', 'routing_mode') || 'bypass_mainland_china';
	let outbound_node;
	if (routing_mode !== 'custom')
		outbound_node = uci.get(cfgname, 'config', 'main_node') || 'nil';
	else
		outbound_node = uci.get(cfgname, 'routing', 'default_outbound') || 'nil';
	/* Client config end */

	/* Server config start */
	const server_enabled = uci.get(cfgname, 'server', 'enabled');
	let auto_firewall = '0';
	if (server_enabled === '1')
		auto_firewall = uci.get(cfgname, 'server', 'auto_firewall');
	/* Server config end */
	/* UCI config end */
%}

{% if (outbound_node !== 'nil'): %}
set homeproxy_localaddr_v4 {
	type ipv4_addr
	flags interval
	auto-merge
	elements = {
		0.0.0.0/8,
		10.0.0.0/8,
		100.64.0.0/10,
		127.0.0.0/8,
		169.254.0.0/16,
		172.16.0.0/12,
		192.0.0.0/24,
		192.0.2.0/24,
		192.31.196.0/24,
		192.52.193.0/24,
		192.88.99.0/24,
		192.168.0.0/16,
		192.175.48.0/24,
		198.18.0.0/15,
		198.51.100.0/24,
		203.0.113.0/24,
		224.0.0.0/4,
		240.0.0.0/4
	}
}
set homeproxy_localaddr_v6 {
	type ipv6_addr
	flags interval
	auto-merge
	elements = {
		::/128,
		::1/128,
		::ffff:0:0/96,
		100::/64,
		64:ff9b::/96,
		2001::/32,
		2001:10::/28,
		2001:20::/28,
		2001:db8::/28,
		2002::/16,
		fc00::/7,
		fe80::/10,
		ff00::/8
	}
}
{% endif %}

{%
if (auto_firewall === '1') {
	print('chain input_wan {', '\n');

	uci.foreach(cfgname, 'server', (s) => {
		if (s.enabled !== '1')
			return;

		let proto = s.network || '{ tcp, udp }';
		printf('	meta l4proto %s th dport %s counter accept comment "Allow-access-%s-%s-at-%s"\n',
			proto, s.port, cfgname, s['.name'], s.port);
	});

	print('}', '\n');
}
%}

{% if (outbound_node !== 'nil'): %}
chain forward {
	meta l4proto { tcp, udp } oifname {{ tunname }} counter accept comment "Forward HomeProxy TUN"
}

chain homeproxy_mangle_output {
	meta l4proto { tcp, udp } iifname {{ tunname }} counter return
	ip daddr @homeproxy_localaddr_v4 counter return
	ip6 daddr @homeproxy_localaddr_v6 counter return
	meta l4proto { tcp, udp } th dport { 0-65535 } mark set {{ proxy_mark }}
}

chain mangle_prerouting {
	meta nfproto { ipv4, ipv6 } jump homeproxy_mangle_output
}

chain mangle_output {
	meta nfproto { ipv4, ipv6 } jump homeproxy_mangle_output
}
{% endif %}
