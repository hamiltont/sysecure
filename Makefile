# This Makefile is based in large off of the Makefile found in the Pidgin
# 'albums' plugin, which is now part of the Pidgin PluginPack

# This Makefile is kind of awful. I had no idea what I was doing, but it finally
# works (disclaimer, works for me, at this time, on this computer. Probably 
# nowhere else...)


# This is the location where the plugin will be installed. Modify this if you
# want to install the plugin system-wide.

  # *nix Plugin Directory Settings

  PLUGINDIR=$(HOME)/.purple/plugins
  NSS_TOP=-I/usr/include/nss -I/usr/include/nss/nss
  NSPR_TOP=-I/usr/include/nspr -I/usr/include/nspr/nspr

# DO NOT EDIT BELOW THIS LINE

PACKAGE=sysecure
VERSION=0.1

SOURCES = sysecure.o globals.o conv_encrypt_map.o gtk_ui.o msg_handle.o
          
PACKDIR=/tmp/pidgin-$(PACKAGE)-$(VERSION)

TARBALL=$(shell pwd)/../pidgin-$(PACKAGE)-$(VERSION).zip
ARCHIVER=zip -r -9
ARCHIVER_END=-x pidgin-$(PACKAGE)-$(VERSION)/.cvsignore

# Common Compiler Stuff
CC=gcc
DEFINES=-DPACKAGE=\"$(PACKAGE)\" -DVERSION=\"$(VERSION)\"
CFLAGS ?= -g3 -O2 -Wall
override CFLAGS += $(DEFINES)


  # *nix Compiler Stuff
  PIDGIN_CFLAGS=$(shell pkg-config --cflags pidgin) $(shell pkg-config --cflags gtk+-2.0) $(NSS_TOP) $(NSPR_TOP) -DDATADIR=\"$(shell pkg-config --variable=datadir pidgin)\"
  PIDGIN_LDFLAGS=$(shell pkg-config --libs pidgin) $(shell pkg-config --libs gtk+-2.0)
  override CFLAGS += $(PIDGIN_CFLAGS) -fPIC
  override LDFLAGS += $(PIDGIN_LDFLAGS) -fPIC
  SHARED_OBJECT_SUFFIX=.so


all: build
build: $(PACKAGE)$(SHARED_OBJECT_SUFFIX)	# Builds all components of the package
rebuild: clean build	# Builds all components of the package from scratch
install: build		# Installs the plugin in $(PLUGINDIR)
	mkdir -p $(PLUGINDIR)
	rm -f $(PLUGINDIR)/$(PACKAGE)$(SHARED_OBJECT_SUFFIX)
	cp $(PACKAGE)$(SHARED_OBJECT_SUFFIX) $(PLUGINDIR)
package:		# Builds the distribution package from this
	test ! -f "$(TARBALL)" || rm -f "$(TARBALL)"
	test ! -d "$(PACKDIR)" || rm -rf "$(PACKDIR)"
	cp -rL . "$(PACKDIR)"
	chmod u+w "$(PACKDIR)"
	cd "$(PACKDIR)" && make distclean
	-test $(WINDOWS) -ne 0 && cd "$(PACKDIR)" && make TOPDIR="$(shell cygpath.exe --windows `pwd`)/" && rm -f $(PACKAGE).dll.o
	cd "$(PACKDIR)/.." && $(ARCHIVER) "$(TARBALL)" "$(shell basename $(PACKDIR))" $(ARCHIVER_END)
	rm -rf "$(PACKDIR)"
	-gpg --armor --detach-sign "$(TARBALL)"
	rm -f ~/src/RPM/RPMS/i386/pidgin-$(PACKAGE)-$(VERSION)-0.i386.rpm
	-test $(WINDOWS) -eq 0 && rpmbuild -ta "$(TARBALL)"
	-test $(WINDOWS) -eq 0 && rpm --resign ~/src/RPM/RPMS/i386/pidgin-$(PACKAGE)-$(VERSION)-0.i386.rpm
	-test $(WINDOWS) -eq 0 && rpm --resign ~/src/RPM/RPMS/i386/pidgin-$(PACKAGE)-debuginfo-$(VERSION)-0.i386.rpm
	-test $(WINDOWS) -eq 0 && rpm --resign ~/src/RPM/SRPMS/pidgin-$(PACKAGE)-$(VERSION)-0.src.rpm
clean:			# Removes all generated files
	rm -f *$(SHARED_OBJECT_SUFFIX) *.o
distclean: clean	# Preparse the directory for distribution
	rm -rf .svn *~ .#* *.bak *.old *.orig *.rej
help:			# Displays usage information
	@sed -ne 's/^\([a-z]*\):.*# /\1\t- /p' Makefile

$(PACKAGE).so: $(PACKAGE).o $(SOURCES)
	$(LINK.o) --shared $^ $(LOADLIBES) $(LDLIBS) -o $@

.PHONY: all build rebuild package install clean distclean help
