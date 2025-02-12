# Building and Packaging Testmesh on OpenWrt

These are instructions to create an [OpenWrt](https://openwrt.org) image with a complete Testmesh setup.

For building OpenWrt on Debian Linux, you need to install these packages:
```
apt install git subversion g++ libncurses5-dev gawk zlib1g-dev build-essential
```

Now build OpenWrt:
```
git clone https://github.com/openwrt/openwrt
cd openwrt

./scripts/feeds update -a
./scripts/feeds install -a

# copy Testmesh packages and source
cp -r ~/testmesh/openwrt/testmesh* package/
mkdir package/testmesh/src
cp -r ~/testmesh/Makefile ~/testmesh/src package/testmesh/src

make menuconfig
```

At this point select the appropiate "Target System" and "Target Profile" depending on what target chipset/router you want to build for.
Packages `testmesh` (the routing protocol) and `testmesh-firmware` (for WLAN/LAN configuration) are selected by default.

Now compile/build everything:

```
make -j8
```

The images and packages are now inside the `bin/` folder. Flash the `bin/<target>/<subtarget>/*-factory.bin` image for a complete setup.
