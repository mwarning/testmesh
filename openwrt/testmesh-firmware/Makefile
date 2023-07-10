include $(TOPDIR)/rules.mk

PKG_NAME:=testmesh-firmware
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/testmesh-firmware

include $(INCLUDE_DIR)/package.mk

define Package/testmesh-firmware
	TITLE:= Firmware for Testmesh
	SECTION:=base
	CATEGORY:=Testmesh
	MENU:=1
	DEFAULT:=y
	DEPENDS:=+testmesh +tcpdump-mini
endef

define Package/testmesh-firmware/description
	Environment setup for Testmesh
endef

define Package/testmesh-firmware/config
	source "$(SOURCE)/Config.in"
endef

# dummy makefile
define Build/Prepare
	echo "all: " > $(PKG_BUILD_DIR)/Makefile
endef

PKG_CONFIG_DEPENDS:= \
	CONFIG_TESTMESH_FIRMWARE_GATEWAY \
	CONFIG_TESTMESH_FIRMWARE_ALGORITHM \

define Package/testmesh-firmware/install
	$(CP) ./files/* $(1)/
	$(SED) "s/^protocol=.*/protocol=$(CONFIG_TESTMESH_FIRMWARE_ALGORITHM)/" $(1)/etc/uci-defaults/zzz_testmesh-setup
	$(SED) "s/^is_gateway=.*/is_gateway=$(if $(CONFIG_TESTMESH_FIRMWARE_GATEWAY),y,n)/" $(1)/etc/uci-defaults/zzz_testmesh-setup
endef

$(eval $(call BuildPackage,testmesh-firmware))
