# This Makefile is based in large off of the Makefile found in the Pidgin
# 'albums' plugin, which is now part of the Pidgin PluginPack

# If you're building on Windows, set this to 1.
WINDOWS ?= 0

# This is the location where the plugin will be installed. Modify this if you
# want to install the plugin system-wide.
ifeq ($(WINDOWS),0)

  # *nix Plugin Directory Settings

  PLUGINDIR=$(HOME)/.purple/plugins

else

  # Windows Plugin Directory Settings

  PLUGINDIR="$(HOME)/Application Data/.purple/plugins"

  # Sample system-wide plugin directory:
  #PLUGINDIR="/cygdrive/c/Program Files/Gaim/plugins"

endif

# This only matters on Windows.
GAIM_SOURCE_DIR=../gaim
GTK_TOP=../win32-dev/gtk_2_0

# DO NOT EDIT BELOW THIS LINE

PACKAGE=sysecure
VERSION=0.1

SOURCES = sysecure.o globals.o conv_encrypt_map.o gtk_ui.o
          
UI=$(PACKAGE)-ui
PACKDIR=/tmp/pidgin-$(PACKAGE)-$(VERSION)

ifeq ($(WINDOWS),0)
	TARBALL=$(shell pwd)/../pidgin-$(PACKAGE)-$(VERSION).tar.bz2
	ARCHIVER=tar --exclude=.cvsignore -cjf
	ARCHIVER_END=
else
	TARBALL=$(shell pwd)/../pidgin-$(PACKAGE)-$(VERSION).zip
	ARCHIVER=zip -r -9
	ARCHIVER_END=-x pidgin-$(PACKAGE)-$(VERSION)/.cvsignore
endif

# Common Compiler Stuff
CC=gcc
DEFINES=-DPACKAGE=\"$(PACKAGE)\" -DVERSION=\"$(VERSION)\"
CFLAGS ?= -g3 -O2 -Wall
override CFLAGS += $(DEFINES)

ifeq ($(WINDOWS),0)

  # *nix Compiler Stuff
  PIDGIN_CFLAGS=$(shell pkg-config --cflags pidgin) $(shell pkg-config --cflags gtk+-2.0) -DDATADIR=\"$(shell pkg-config --variable=datadir pidgin)\"
  PIDGIN_LDFLAGS=$(shell pkg-config --libs pidgin) $(shell pkg-config --libs gtk+-2.0)
  override CFLAGS += $(PIDGIN_CFLAGS) -fPIC
  override LDFLAGS += $(PIDGIN_LDFLAGS) -fPIC
  SHARED_OBJECT_SUFFIX=.so

else

  # Windows Compiler Stuff

  WIN32_CFLAGS= -I"$(TOPDIR)$(GTK_TOP)/include/atk-1.0" \
                -I"$(TOPDIR)$(GTK_TOP)/include/glib-2.0" \
                -I"$(TOPDIR)$(GTK_TOP)/include/gtk-2.0" \
                -I"$(TOPDIR)$(GTK_TOP)/include/freetype2" \
                -I"$(TOPDIR)$(GTK_TOP)/include/libpng13" \
                -I"$(TOPDIR)$(GTK_TOP)/include/pango-1.0" \
                -I"$(TOPDIR)$(GTK_TOP)/lib/glib-2.0/include" \
                -I"$(TOPDIR)$(GTK_TOP)/lib/gtk-2.0/include" \
                -I"$(TOPDIR)$(GAIM_SOURCE_DIR)/libgaim" \
                -I"$(TOPDIR)$(GAIM_SOURCE_DIR)/gtk" \
                -I"$(TOPDIR)$(GAIM_SOURCE_DIR)/gtk/win32" \
		-mno-cygwin -mms-bitfields \
                $(CFLAGS)

  WIN32_LIBS=   -lgtk-win32-2.0 \
                -lglib-2.0 \
                -lgdk-win32-2.0 \
                -lgobject-2.0 \
                -lgmodule-2.0 \
                -lgdk_pixbuf-2.0 \
                -lpango-1.0 \
                -lintl \
                -lws2_32 \
                -lgtkgaim \
                -lgaim

  SHARED_OBJECT_SUFFIX=.dll

endif

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

$(PACKAGE).dll: $(PACKAGE).c $(UI).c
	$(CC) $(WIN32_CFLAGS) -o $(PACKAGE).o -c $(PACKAGE).c
	$(CC) $(WIN32_CFLAGS) -o $(UI).o -c $(UI).c
	$(CC) -shared $(PACKAGE).o $(UI).o -L"$(TOPDIR)$(GTK_TOP)/lib" -L"$(TOPDIR)$(GAIM_SOURCE_DIR)/libgaim" -L"$(TOPDIR)$(GAIM_SOURCE_DIR)/gtk" $(WIN32_LIBS) $(DLL_LD_FLAGS) -o $@

.PHONY: all build rebuild package install clean distclean help
