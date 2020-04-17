## Installation

### Compiling DAWN

Update Feeds

    ./scripts/feeds update -a

Install DAWN

    ./scripts/feeds install dawn

Select dawn under

    make menuconfig

Compile

    make package/dawn/compile

## Compile Latest DAWN

Clone Openwrt

    https://git.openwrt.org/openwrt/openwrt.git

Update feeds

    ./scripts/feeds update packages

install dawn

    ./scripts/feeds install dawn

Now do

    make menuconfig

Select `Advanced Configuration -> Enable package source-tree override`.

Further, select dawn under `Network -> dawn`.

Now you need to clone DAWN, e.g. into your home directory

    git clone https://github.com/berlin-open-wireless-lab/DAWN.git ~/DAWN

You have to add now a symlink. In the openwrt branch do something like

    ln -s ~/DAWN/.git/ feeds/packages/net/dawn/git-src

Now compile dawn

    make package/dawn/clean && make package/dawn/compile

### Configure Dawn

Edit settings under

    /etc/config/dawn

Restart daemon
    /etc/init.d/dawn restart