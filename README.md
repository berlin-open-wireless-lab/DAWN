# DAWN
Decentralized WiFi Controller

## Related

|Repro             |Content                   |
|------------------|--------------------------|
|[patches-pending](https://github.com/berlin-open-wireless-lab/patches-pending)|Pending OpenWrt Patches DAWN is depending on|
|[bowl-feed](https://github.com/berlin-open-wireless-lab/bowl-feed)|Feed for DAWN|

## Installation

### Compiling OpenWRT with patch

Create Folder

    mkdir patched_openwrt

Enter folder

    cd patched_openwrt

Clone OpenWRT source code

    git clone https://github.com/openwrt/openwrt.git source
   
Clone patch

    git clone https://github.com/berlin-open-wireless-lab/patches-pending.git patches
    
Apply patches

    quilt apply
    
Updating feeds

    ./scripts/feeds update -a && ./scripts/feeds/install -a

Configure image

    make menuconfig

Compile image

    make -j $(nproc)

### Compiling DAWN

Add [bowlfeed](https://github.com/berlin-open-wireless-lab/bowl-feed.git) to feeds.conf  
    
    src-git bowlfeed git@github.com:berlin-open-wireless-lab/bowl-feed.git
    
Select dawn under

    make menuconfig
    
Compile

    make package/dawn/compile
    
### Configure Dawn

Edit settings under

    /etc/config/dawn
    
Restart daemon
    /etc/init.d/dawn restart

## Setting up Routers

You can find a good guide to configure your router is [here](https://gist.github.com/braian87b/bba9da3a7ac23c35b7f1eecafecdd47d).
I setup the OpenWRT Router as dump APs.
