include $(TOPDIR)/rules.mk

PKG_NAME:=testmesh
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Moritz Warning <moritzwarning@web.de>
PKG_LICENSE:=CC0-1.0

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/testmesh
	TITLE:=Testmesh
	SECTION:=base
	CATEGORY:=Testmesh
	MENU:=1
	DEPENDS:=+kmod-tun
endef

define Package/testmesh/description
	A mesh network protocol daemon
endef

# Make binary smaller
TARGET_CFLAGS += -ffunction-sections -fdata-sections
TARGET_LDFLAGS += -Wl,--gc-sections

define Package/testmesh/config
	source "$(SOURCE)/Config.in"
endef

ifeq ($(CONFIG_TESTMESH_ENABLE_DEBUG),y)
	MAKE_FLAGS += DEBUG=1
endif

# clean beforehand, since this is a package for in
# development software and might contain artifacts
define Build/Compile
	$(call Build/Compile/Default,clean all)
endef

define Package/testmesh/install
	$(CP) ./files/* $(1)/

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/testmesh $(1)/usr/bin/
	$(LN) /usr/bin/testmesh $(1)/usr/bin/testmesh-ctl
endef

$(eval $(call BuildPackage,testmesh))
