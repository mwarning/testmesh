include $(TOPDIR)/rules.mk

PKG_NAME:=geomesh-firmware
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/geomesh-firmware

include $(INCLUDE_DIR)/package.mk

define Package/geomesh-firmware
	SECTION:=base
	CATEGORY:=Geomesh
	DEFAULT:=y
	TITLE:= Geomesh Example Firwmare
	DEPENDS:=+geomesh +tcpdump-mini
endef

define Package/geomesh-firmware/config
	source "$(SOURCE)/Config.in"
endef

ifeq ($(CONFIG_GEOMESH_FIRMWARE_GATEWAY),y)
	$(SED) -i "s/is_gateway=0/is_gateway=1/" ./files/etc/uci-defaults/zzz_geomesh-setup
else
	$(SED) -i "s/is_gateway=1/is_gateway=0/" ./files/etc/uci-defaults/zzz_geomesh-setup
endif

# dummy makefile
define Build/Prepare
	echo "all: " > $(PKG_BUILD_DIR)/Makefile
endef

define Package/geomesh-firmware/install
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,geomesh-firmware))
