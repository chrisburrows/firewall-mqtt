# firewall-mqtt

This is a simple Python script to provide MQTT control over a small
aspect of my home firewall.

The firewall is based on Linux Netfilter and supports multiple VLANs
that are used to segment home automation devices. Each VLAN rules
chain include a final call out to a specific chain that determines
if Internet access is permitted. This daemon allows this final 
rule to be managed thus providing remote control.

