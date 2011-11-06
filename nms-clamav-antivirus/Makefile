#!/use/bin/make -f

CWD = $(shell pwd)
CP = ln -s
NZA_DIR = var/lib/nza
PLUGINDIR = $(NZA_DIR)/plugins/nms/nms-clamav-antivirus

build:

install:
	@$(MAKE) DEB_BUILD=1 CP='cp -d' deploy

clean:

deploy: deploy-clean deploy-dirs deploy-files

deploy-dirs: deploy-clean
	@echo "Deploing dirs..."
	@test -d $(DESTDIR)/$(NZA_DIR) || mkdir -p $(DESTDIR)/$(NZA_DIR)
	@test -d $(DESTDIR)/$(PLUGINDIR) || mkdir -p $(DESTDIR)/$(PLUGINDIR)

deploy-files: deploy-dirs
	@echo "Deploing files..."
	@$(CP) $(CWD)/metafile.pm $(DESTDIR)/$(PLUGINDIR)
	@$(CP) $(CWD)/ClamAV.pm $(DESTDIR)/$(PLUGINDIR)
	@$(CP) $(CWD)/Consts.pm $(DESTDIR)/$(PLUGINDIR)
	@$(CP) $(CWD)/ClamRunner.pm $(DESTDIR)/$(PLUGINDIR)
	@$(CP) $(CWD)/clamav-scan $(DESTDIR)/$(NZA_DIR)

ifndef DEB_BUILD
deploy-clean:
	@echo "Cleaning up before deploing..."
	@rm -rf $(DESTDIR)/$(PLUGINDIR) $(DESTDIR)/$(NZA_DIR)/clamav-scan
else
deploy-clean:
endif
