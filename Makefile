
include $(TOPDIR)/rules.mk

PKG_NAME:=iptvscanner
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/iptvscanner
  SECTION:=net
  CATEGORY:=Network
  TITLE:=IPTV Multicast Scanner
  DEPENDS:=+libpcap +libstdcpp
endef

define Package/iptvscanner/description
  A multicast IPTV scanner that captures and displays streaming information.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/iptvscanner/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iptvscanner $(1)/usr/bin/
endef

$(eval $(call BuildPackage,iptvscanner))
