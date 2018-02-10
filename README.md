# DAWN
Decentralized WiFi Controller

## Related

|Repro             |Content                   |
|------------------|--------------------------|
|[patches-pending](https://github.com/berlin-open-wireless-lab/patches-pending)|Pending OpenWrt Patches DAWN is depending on|
|[bowl-feed](https://github.com/berlin-open-wireless-lab/bowl-feed)|Feed for DAWN|

## Installation

See [installation](INSTALL.md)-

## Setting up Routers

You can find a good guide to configure your router is [here](https://gist.github.com/braian87b/bba9da3a7ac23c35b7f1eecafecdd47d).
I setup the OpenWRT Router as dump APs.

## ubus interface

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
