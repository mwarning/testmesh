include $(TOPDIR)/rules.mk

PKG_NAME:=geomesh
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=John Doe <john.doe@example.com>
PKG_LICENSE:=CC0-1.0

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/geomesh
	TITLE:=Geomesh
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Routing and Redirection
	MENU:=1
	DEPENDS:=+kmod-tun @IPV6
endef

define Package/geomesh/description
	A mesh network protocol daemon
endef

# Make binary smaller
TARGET_CFLAGS += -ffunction-sections -fdata-sections
TARGET_LDFLAGS += -Wl,--gc-sections

define Package/geomesh/config
	source "$(SOURCE)/Config.in"
endef

ifeq ($(CONFIG_GEOMESH_ENABLE_DEBUG),y)
	MAKE_FLAGS += DEBUG=1
endif

# clean beforehand, since this is a package for in
# development software and might contain artifacts
define Build/Compile
	$(call Build/Compile/Default,clean all)
endef

define Package/geomesh/install
	$(CP) ./files/* $(1)/

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/geomesh $(1)/usr/bin/
	$(LN) /usr/bin/geomesh $(1)/usr/bin/geomesh-ctl
endef

$(eval $(call BuildPackage,geomesh))
