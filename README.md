# DAWN
Decentralized WiFi Controller

## Related

|Repro             |Content                   |
|------------------|--------------------------|
|[patches-pending](https://github.com/berlin-open-wireless-lab/patches-pending)|Pending OpenWrt Patches DAWN is depending on|
|[bowl-feed](https://github.com/berlin-open-wireless-lab/bowl-feed)|Feed for DAWN|

## Installation

See [installation](INSTALL.md).

## Setting up Routers

You can find a good guide to configure your router is [here](https://gist.github.com/braian87b/bba9da3a7ac23c35b7f1eecafecdd47d).
I setup the OpenWRT Router as dump APs.

## Configuration


|Option             |Standard | Meaning |
|-------------------|---------|---------|
|ht_support         |  '10'   |         |
|vht_support        |  '100'  |         |
|no_ht_support      |  '0'    |         |
|no_vht_support     |  '0'    |         |
|rssi               |  '10'   |         |
|low_rssi           |  '-500' |         |
|freq               |  '100'  |         |
|chan_util          |  '0'    |         |
|max_chan_util      |  '-500' |         |
|rssi_val           |  '-60'  |         |
|low_rssi_val       |  '-80'  |         |
|chan_util_val      |  '140'  |         |
|max_chan_util_val  |  '170'  |         |
|min_probe_count    |  '2'    |         |
|bandwith_threshold |  '6'    |         |
|use_station_count  |  '1'    |         |
|max_station_diff   |  '1'    |         |
|eval_probe_req     |  '1'    |         |
|eval_auth_req      |  '1'    |         |
|eval_assoc_req     |  '1'    |         |
|deny_auth_reason   |  '1'    |         |
|deny_assoc_reason  |  '17'   |         |
|use_driver_recog   |  '1'    |         |


## ubus interface
To get an overview of all connected Clients sorted by the SSID.

    root@OpenWrt:~# ubus call dawn get_network
    {
	    "Free-Cookies": {
		    "00:27:19:XX:XX:XX": {
			    "78:02:F8:XX:XX:XX": {
				    "freq": 2452,
				    "ht": 1,
				    "vht": 0,
				    "collision_count": 4
			    }
		    },
		    "A4:2B:B0:XX:XX:XX": {
			    "48:27:EA:XX:XX:XX: {
				    "freq": 2412,
				    "ht": 1,
				    "vht": 0,
				    "collision_count": 4
			    },
		    }
	    },
	    "Free-Cookies_5G": {
    		
	    }
    }
To get the hearing map you can use:

    root@OpenWrt:~# ubus call dawn get_hearing_map
    {
	    "Free-Cookies": {
		    "0E:5B:DB:XX:XX:XX": {
			    "00:27:19:XX:XX:XX": {
				    "signal": -64,
				    "freq": 2452,
				    "ht_support": true,
				    "vht_support": false,
				    "channel_utilization": 12,
				    "num_sta": 1,
				    "ht": 1,
				    "vht": 0,
				    "score": 10
			    },
			    "A4:2B:B0:XX:XX:XX": {
				    "signal": -70,
				    "freq": 2412,
				    "ht_support": true,
				    "vht_support": false,
				    "channel_utilization": 71,
				    "num_sta": 3,
				    "ht": 1,
				    "vht": 0,
				    "score": 10
			    }
		    }
	    }
    }
