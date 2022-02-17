include $(TOPDIR)/rules.mk

PKG_NAME:=geomesh-firmware
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/geomesh-firmware

include $(INCLUDE_DIR)/package.mk

define Package/geomesh-firmware
	TITLE:= Geomesh Example Firmware
	SECTION:=base
	CATEGORY:=Geomesh
	MENU:=1
	DEFAULT:=y
	DEPENDS:=+geomesh +tcpdump-mini
endef

define Package/geomesh-firmware/config
	source "$(SOURCE)/Config.in"
endef

# dummy makefile
define Build/Prepare
	echo "all: " > $(PKG_BUILD_DIR)/Makefile
endef

PKG_CONFIG_DEPENDS:= \
	CONFIG_GEOMESH_FIRMWARE_GATEWAY \
	CONFIG_GEOMESH_FIRMWARE_ALGORITHM \

define Package/geomesh-firmware/install
	$(CP) ./files/* $(1)/
	$(SED) "s/protocol=.*/protocol=$(CONFIG_GEOMESH_FIRMWARE_ALGORITHM)/" $(1)/etc/uci-defaults/zzz_geomesh-setup
	$(SED) "s/is_gateway=.*/is_gateway=$(if $(CONFIG_GEOMESH_FIRMWARE_GATEWAY),y,n)/" $(1)/etc/uci-defaults/zzz_geomesh-setup
endef

$(eval $(call BuildPackage,geomesh-firmware))
