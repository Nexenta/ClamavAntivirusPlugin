#!/use/bin/make -f

CWD = $(shell pwd)
CP = ln -s
NZA_DIR = var/lib/nza
PLUGINDIR = $(NZA_DIR)/plugins/nms/nms-clamav-antivirus


build:

install:
	@$(MAKE) DEB_BUILD=1 CP='cp -d' deploy

clean:
	@rm -rf $(DESTDIR)/$(PLUGINDIR) $(DESTDIR)/$(NZA_DIR)/clamav-scan

deploy: deploy-dirs deploy-files

deploy-dirs: clean
	@mkdir -p $(DESTDIR)/$(NZA_DIR) $(DESTDIR)/$(PLUGINDIR)

deploy-files: deploy-dirs
	@$(CP) $(CWD)/metafile.pm $(DESTDIR)/$(PLUGINDIR)
	@$(CP) $(CWD)/ClamAV.pm $(DESTDIR)/$(PLUGINDIR)
	@$(CP) $(CWD)/Consts.pm $(DESTDIR)/$(PLUGINDIR)
	@$(CP) $(CWD)/ClamRunner.pm $(DESTDIR)/$(PLUGINDIR)
	@$(CP) $(CWD)/clamav-scan $(DESTDIR)/$(NZA_DIR)
