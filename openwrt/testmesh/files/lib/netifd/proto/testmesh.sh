#!/bin/sh

. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"

proto_testmesh_init_config() {
#	available=1
#	no_device=1
	proto_config_add_string "master"
}

proto_testmesh_setup() {
	local config="$1"
	local iface="$2"
	local master

	json_get_vars master

	if [ -n "$iface" -a "$master" ]; then
		local enabled=$(uci_get testmesh.$master.enabled)
		local control=$(uci_get testmesh.$master.control)

		if [ "$enabled" = "1" ]; then
			testmesh-ctl ${control:+-c $control} interface-add "$iface"

			# add interface to configuration (try to remove first)
			uci del_list testmesh.$master.interface="$iface"
			uci add_list testmesh.$master.interface="$iface"
		fi
	fi

	proto_init_update "$iface" 1
	proto_send_update "$config"
}

proto_testmesh_teardown() {
	local config="$1"
	local iface="$2"
	local master

	json_get_vars master

	if [ -n "$iface" ]; then
		local enabled=$(uci_get testmesh.$master.enabled)
		local control=$(uci_get testmesh.$master.control)

		if [ "$enabled" = "1" ]; then
			testmesh-ctl ${control:+-c $control} interface-del "$iface"

			# remove entry from configuration
			uci del_list testmesh.$master.interface="$iface"
		fi
	fi
}

add_protocol testmesh
