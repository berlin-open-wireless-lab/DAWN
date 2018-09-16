## Installation

### Compiling DAWN

Add [bowlfeed](https://github.com/berlin-open-wireless-lab/bowl-feed.git) to feeds.conf

    src-git bowlfeed git@github.com:berlin-open-wireless-lab/bowl-feed.git
    
Update Feeds

    ./scripts/feeds update -a
    
Install DAWN

    ./scripts/feeds install dawn


Select dawn under

    make menuconfig

Compile

    make package/dawn/compile

### Configure Dawn

Edit settings under

    /etc/config/dawn

Restart daemon
    /etc/init.d/dawn restart