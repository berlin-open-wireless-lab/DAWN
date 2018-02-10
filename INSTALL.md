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