# Building and Packaging TesMesh on OpenWrt

To inlcude TestMesh into your [OpenWrt](https://openwrt.org) image or to create an .ipk package (equivalent to Debian Linux .deb files), you have to build a firmware image.
These steps were tested using OpenWrt:

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

# copy GeoMesh package and source
cp -r ~/geomesh/openwrt/geomesh package/geomesh
mkdir package/geomesh/src
cp -r ~/geomesh/Makefile ~/geomesh/src package/geomesh/src

make menuconfig
```

At this point select the appropiate "Target System" and "Target Profile" depending on what target chipset/router you want to build for.
And mark the GeoMesh package under "Network" => "Routing and Redirection", of course.

Now compile/build everything:

```
make
```

The images and all \*.ipk packages are now inside the bin/ folder.
You can install the geomesh-1.0.0.ipk using "opkg install \<ipkg-file\>" on the router or just use the entire image to flash OpenWrt with the package already installed.

## Setup Mesh Interface

To mesh, you need to configure a WiFi mesh interface in `/etc/conifg/wireless`.
