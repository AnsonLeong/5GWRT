#
# Copyright (C) 2022 LOK IN LIANG <20888191+AnsonLeong@users.noreply.github.com>
#
# This is free software, licensed under the GNU General Public License v2.
# 
#

include $(TOPDIR)/rules.mk

PKG_NAME:=quectel-CM
PKG_RELEASE:=1
PKG_VERSION:=1.6.4

include $(INCLUDE_DIR)/package.mk

define Package/quectel-CM
  SECTION:=utils
  CATEGORY:=Network
  TITLE:=Quectel Connection Manager
  MAINTAINER:=LOK IN LIANG <20888191+AnsonLeong@users.noreply.github.com>
  DEPENDS:=+libpthread
endef

define Package/quectel-CM/description
Quectel Connection Manager tool for testing cellular connection 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall"
endef

define Package/quectel-CM/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/quectel-CM $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,quectel-CM))
