# Configuring DAWN

## Making Configuraton Changes
Edit settings under

    /etc/config/dawn


After changes, restart daemon

    /etc/init.d/dawn restart

The updated configuration can be shared with other DAWN instances via ubus:

    ubus call dawn reload_config

## What Can Be Configured?
The parameters that control DAWN are listed alphabetically below.  This section describes how they are grouped to provide various features.

### Client 'Kicking'
DAWN's primary purpose is to move (aka "kick") client devices to the best AP.  This is enabled via the `kicking` parameter.  If it is zero you will see no devices being moved, but can use the log messages to see what would happen.

See also "Note 1: Legacy Clients"

### Client Connection Scoring
DAWN calculates a "score" for the actual or potential connection between an AP and a client device.  These values ar ehten compared to decide whether to move a client.  The score includes several factors:
- The radio connection quality, see "Note 2: RSSI Scoring"
- Support for 802.11 features that improve throughput, see `ht_support`, `no_ht_support`, `vht_support` and `no_vht_support`
- How heavily the relevant radio is being used across all clients, see `chan_util`, `chan_util_val`, `max_chan_util` and `max_chan_util_val`
- How busy the current cliet-AP connection is, see `bandwidth_threshold`
- How many clients are connected to the AP, see `use_station_count` and `max_station_diff`
- Whether sufficiently better APs for the client have been consistently found (rather than for example as a one-off due to walking past a wall), see `kicking_threshold` and `min_number_to_kick`

### Other Features
The following are less likely to need attention:
- The way 802.11v Neighbor Reports are generated can be adjusted.
    - `disassoc_nr_length` controls the number of entries in the list.
    - `set_hostapd_nr` controls the mechanism used to build the AP NR
        - "Static" will be sufficient for a small network, and contain all the AP entries
        - "Dynamic" will allow a large network to automatically determine the optimal set for each AP, and contain a set of nearby APs
- 802.11k has a number of methods for gathering BEACON reports.  The preference for Passive, Active or Table can be set via `rrm_mode`

## Configuration Notes
### Note 1: Legacy Clients
802.11v introduced the capability for clients to be "politely" asked to move to a different AP, and DAWN uses this capability for clients that appear to support it.

By definition, there is no way to do this for clients that don't implement 802.11v.  For these "legacy clients" DAWN can attempt to steer them away during the PROBE / ASSOCIATE / AUTHENTICATE process by returning status codes that indicate errors or unwillingness to accept.  It can also force disconnection of a connected client by "tearing down" the connection, however this is quite brutal as the client then has to start a search for a new AP, and it may just want to come back to the same AP.  If DAWN continues to try to not accept the client it is effectively denied wifi access.

If you enable this legacy client behaviour via parameters indicated then you may hit challenges as it is less tested and reliable than the 802.11v supported steering.  Reports on its success or otherwise are welcomed so it can be refined if necessary and possible (within the constriants of 802.11).

See: `eval_probe_req`, `eval_auth_req`, `eval_assoc_req`, `deny_auth_reason`, `deny_assoc_reason`, `min_probe_count` and `kicking`

### Note 2: RSSI Scoring
As a part of the scoring mechanism DAWN provides two mechanisms for evaluating the client-AP RSSI (radio signal) quality.  Although DAWN does not prevent both mechanisms being enabled at the same time (via the relevant increment parameters) it may be difficult to obtain desired behaviour.

Mechanism 1 is "stepped".  If the RSSI value is better than the `rssi_val` value (or worse than the `low_rssi_val` value) then the AP score has the `rssi` (or `low_rssi`) increment values applied.  This effective creates three "zones" of RSSI score, which may be sufficient for many cases.  To disable this mode set both increment values to zero.

Mechanism 2 is "graduated".  For each dB that the RSSI signal differs from the `rssi_centre` value the increment `rssi_weight` is applied.  This can provide a more refined score, but may require more effort to get the parameters optimised.  To disable this mode set the increment value to zero.

## Feature Parameters
These parameters go in the following section:

    config metric 'global'

And if marked with '+' are specified / repeated in each of these band specific sections (but not the 'global' section):

    config metric '802_11a'
    config metric '802_11g'

<!-- Use the following shell command to auto-generate the table rows from DAWN source code:
grep 'CONFIG-[FS]:' `find . -type f -name "*.[ch]"`|sed 's/^.*CONFIG-.: *\(.*\)$/|\1|/'|sort
-->
|Parameter|Purpose|Notes|
|---------|-------|-----|
|bandwidth_threshold|Maximum reported AP-client bandwidth permitted when kicking|Default = 6 (Mbits/s)|
|chan_util_avg_period|Number of sampling periods to average channel utilization values over|Default = 3|
|chan_util+|Score increment if channel utilization is below chan_util_val|Default = 0|
|chan_util_val+|Threshold for good channel utilization|Default = 140|
|deny_assoc_reason|802.11 code used when ASSOCIATION is denied|17 = AP_UNABLE_TO_HANDLE_NEW_STA.  See Note 1.|
|deny_auth_reason|802.11 code used when AUTHENTICATION is denied|1 = UNSPECIFIED_FAILURE.  See Note 1.|
|disassoc_nr_length|Number of entries to include in a 802.11v DISASSOCIATE Neighbor Report|Default = 6, as documented for use by iOS|
|duration|802.11k BEACON request DURATION parameter|Default = 0|
|eval_assoc_req|Control whether ASSOCIATION frames are evaluated for rejection|0 = No evaluation; 1 = Evaluated.  See Note 1.|
|eval_auth_req|Control whether AUTHENTICATION frames are evaluated for rejection|0 = No evaluation; 1 = Evaluated.  See Note 1.|
|eval_probe_req|Control whether PROBE frames are evaluated for rejection|0 = No evaluation; 1 = Evaluated.  See Note 1.|
|ht_support+|Score increment if HT is supported|Default = 10|
|initial_score+|Base score for AP based on operating band|2.4GHz = 0; 5Ghz = 100|
|kicking|Actively move clients to the best AP|0 = Disabled; 1 = Enabled for 802.11v clients; 2 = Also enabled for pre-802.11v clients.  See note 1.|
|kicking_threshold|Minimum score difference to consider kicking to alternate AP|Default = 20|
|low_rssi+|Score addition when signal is below threshold|Default = -500. See note 2.|
|low_rssi_val+|Threshold for bad RSSI|Default = -80. See note 2.|
|max_chan_util+|Score increment if channel utilization is above max_chan_util_val|Default = -500|
|max_chan_util_val+|Threshold for bad channel utilization|Default = 170|
|max_station_diff|Number of connected stations to consider "better" for use_station_count|Default = 1|
|min_number_to_kick|Number of consecutive times a client should be evaluated as ready to kick before actually doing it|Default = 3|
|min_probe_count|Number of times a client should retry PROBE before acceptance| Default of 3. See Note 1.|
|neighbors+|Space seperated list of MACS to use in "static" AP Neighbor Report| None|
|no_ht_support+|Score incrment if HT is not supported|Default = 0 (Deprecated)|
|no_vht_support+|Score incrment if VHT is not supported|Default = 0 (Deprecated)|
|rrm_mode|Preferred order for using Passive, Active or Table 802.11k BEACON information|String of 'P', 'A' and / or 'T'|
|rssi_center+|Midpoint for weighted RSSI evaluation|Default = -70. See note 2.|
|rssi+|Score addition when signal exceeds threshold|Default = 10. See note 2.|
|rssi_val+|Threshold for an good RSSI|Default = -60. See note 2.|
|rssi_weight+|Per dB increment for weighted RSSI evaluation|Default = 0. See note 2.|
|set_hostapd_nr|Method used to set Neighbor Report on AP|0 = Disabled; 1 = "Static" based on all APs in network (plus set from configuration); 2 = "Dynamic" based on next nearest AP seen by current clients|
|use_station_count|Compare connected station counts when considering kicking|0 = Disabled; 1 = Enabled|
|vht_support+|Score increment if VHT is supported|Default = 100|


## Networking Parameters
TCP networking with UMDNS and without encryption is the most tested and stable configuration.

Encryption has been reported to be broken, so use it with caution.

Other parameters have fallen out of use, but remain in the code.  A tidy up of them is due.

These parameters go in the following section:

    config network
<!-- Use the following shell command to auto-generate the table rows from DAWN source code:
grep 'CONFIG-N:' `find . -type f -name "*.[ch]"`|sed 's/^.*CONFIG-.: *\(.*\)$/|\1|/'|sort
-->
|Parameter|Purpose|Notes [Default is bracketed]|
|---------|-------|-----|
|bandwidth|Unused|N/A|
|broadcast_ip|IP address for broadcast and multicast|No default|
|broadcast_port|IP port for broadcast and multicast|[1026]|
|collision_domain|Unused|N/A|
|iv|Unused|N/A|
|network_option|Method of networking between DAWN instances|0 = Broadcast; 2 = Multicast; [2 = TCP with UMDNS discovery]; 3 = TCP w/out UMDNS discovery|
|server_ip|IP address when not using UMDNS|No default|
|shared_key|Unused|N/A|
|tcp_port|Port for TCP networking|[1025]|
|use_symm_enc|Enable encryption of network traffic|[0 = Disabled]; 1 = Enabled|

## Local Parameters
Local parameters are not shared with other DAWN instances.

These parameters go in the following section:

    config local
<!-- Use the following shell command to auto-generate the table rows from DAWN source code:
grep 'CONFIG-L:' `find . -type f -name "*.[ch]"`|sed 's/^.*CONFIG-.: *\(.*\)$/|\1|/'|sort
-->
|Parameter|Purpose|Notes [Default is bracketed]|
|---------|-------|-----|
|loglevel|Verbosity of messages in syslog|[0 = Important only - very few messages]; 1 = Show what DAWN is processing in a user friendly way; 2 = Trace certain operations - for debugging; 3 = Broad low level tracing - for debugging|

## Timing / Scheduling Parameters
All timer values are in secinds.  They are the main mechanism for DAWN collecting and managing much of the data that it relies on.

These parameters go in the following section:

    config times
<!-- Use the following shell command to auto-generate the table rows from DAWN source code:
grep 'CONFIG-T:' `find . -type f -name "*.[ch]"`|sed 's/^.*CONFIG-.: *\(.*\)$/|\1|/'|sort
-->
|Parameter|Purpose|Notes [Default is bracketed]|
|---------|-------|-----|
|remove_ap|Timer to remove expired AP entries from core data set|[460]|
|remove_client|Timer to remove expired client entries from core data set|[15]|
|remove_probe|Timer to remove expired PROBE and BEACON entries from core data set|[30]|
|update_beacon_reports|Timer to ask all connected clients for a new BEACON REPORT|[20]|
|update_chan_util|Timer to get recent channel utilisation figure for each local BSSID|[5]|
|update_client|Timer to send revised NEIGHBOR REPORT to all clients|[10]|
|update_hostapd|Timer to (re-)register for hostapd messages for each local BSSID|[10]|
|update_tcp_con|Timer to refresh / remove the TCP connections to other DAWN instances found via uMDNS|[10]|


## hostapd Parameters
These parameters go in the following section:

    config hostapd
<!-- Use the following shell command to auto-generate the table rows from DAWN source code:
grep 'CONFIG-H:' `find . -type f -name "*.[ch]"`|sed 's/^.*CONFIG-.: *\(.*\)$/|\1|/'|sort
-->
|Parameter|Purpose|Notes [Default is bracketed]|
|---------|-------|-----|
|hostapd_dir|Path to hostapd runtime information|[/var/run/hostapd]|