#
# Copyright (C) 2022 LOK IN LIANG <20888191+AnsonLeong@users.noreply.github.com>
#
# This is free software, licensed under the GNU General Public License v2.
# 
#

include $(TOPDIR)/rules.mk

PKG_NAME:=QLog
PKG_RELEASE:=1
PKG_VERSION:=1.5.12

include $(INCLUDE_DIR)/package.mk

define Package/QLog
  SECTION:=utils
  CATEGORY:=Network
  TITLE:=Quectel Log tool
  MAINTAINER:=LOK IN LIANG <20888191+AnsonLeong@users.noreply.github.com>
endef

define Package/QLog/description
Quectel Log tool for capturing modem log
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

define Package/QLog/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/QLog $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,QLog))
