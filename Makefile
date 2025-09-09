# ===== Hail (merged) Makefile — src/ layout =====
# Targets:
#   make native           -> gcc build into build/native
#   make arm-musl         -> arm-linux-musleabihf-gcc into build/arm-musl
#   make arm-gnu          -> arm-linux-gnueabihf-gcc into build/arm-gnu
#   make aarch64-gnu      -> aarch64-linux-gnu-gcc into build/aarch64-gnu
#   make mipsel-openwrt   -> mipsel-openwrt-linux-musl-gcc into build/mipsel-openwrt
#   make all              -> build all targets
#   make strip            -> strip any built binaries (best effort)
#   make install          -> install/deploy built waybeam_core binaries if present (best effort)
#   make clean            -> remove build artifacts

# ===== Sources / headers (new structure) =====
SRC_DIR := src

SRC_LIB := $(SRC_DIR)/hail.c $(SRC_DIR)/hail_app.c
HDR_LIB := $(SRC_DIR)/hail.h $(SRC_DIR)/hail_app.h
SRC_WS  := $(SRC_DIR)/hail_ws.c
HDR_WS  := $(SRC_DIR)/hail_ws.h

# Waybeam Core
SRC_DEMO := $(SRC_DIR)/waybeam_core.c

# Optional ncurses demo (auto-detected; keep commented if not used)
# NCURSES_DEMO_SRC := $(SRC_DIR)/hail_demo_cli.c
# HAVE_NCURSES_DEMO := $(wildcard $(NCURSES_DEMO_SRC))

# ===== Defaults =====
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -Isrc
LDFLAGS ?=
LIBS    ?= -lpthread
# NCURSES_LIBS ?= -lncurses

# Portable shell flags (no pipefail to keep BusyBox happy)
.SHELLFLAGS := -eu -c
.DELETE_ON_ERROR:

# ===== Toolchains =====
# Native
CC_NATIVE      ?= gcc
AR_NATIVE      ?= ar
RANLIB_NATIVE  ?= ranlib
STRIP_NATIVE   ?= strip

# ARM musl (e.g., Alpine toolchain)
CC_ARM_MUSL      ?= arm-linux-musleabihf-gcc
AR_ARM_MUSL      ?= ar
RANLIB_ARM_MUSL  ?= ranlib
STRIP_ARM_MUSL   ?= strip

# ARM gnu (Debian/Ubuntu cross)
CC_ARM_GNU      ?= arm-linux-gnueabihf-gcc
AR_ARM_GNU      ?= ar
RANLIB_ARM_GNU  ?= ranlib
STRIP_ARM_GNU   ?= strip

# AArch64 (arm64) GNU (Ubuntu cross)
CC_AARCH64_GNU      ?= aarch64-linux-gnu-gcc
AR_AARCH64_GNU      ?= ar
RANLIB_AARCH64_GNU  ?= ranlib
STRIP_AARCH64_GNU   ?= strip

# OpenWrt mipsel (24kc, musl)
OPENWRT_MIPSEL_BIN ?= $(HOME)/fpv/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin
ifeq ($(origin CC_MIPSEL_OPENWRT), undefined)
  ifneq ($(strip $(OPENWRT_MIPSEL_BIN)),)
    CC_MIPSEL_OPENWRT     := $(OPENWRT_MIPSEL_BIN)/mipsel-openwrt-linux-musl-gcc
    AR_MIPSEL_OPENWRT     := $(OPENWRT_MIPSEL_BIN)/mipsel-openwrt-linux-musl-ar
    RANLIB_MIPSEL_OPENWRT := $(OPENWRT_MIPSEL_BIN)/mipsel-openwrt-linux-musl-ranlib
    STRIP_MIPSEL_OPENWRT  := $(OPENWRT_MIPSEL_BIN)/mipsel-openwrt-linux-musl-strip
  else
    CC_MIPSEL_OPENWRT     ?= mipsel-openwrt-linux-musl-gcc
    AR_MIPSEL_OPENWRT     ?= mipsel-openwrt-linux-musl-ar
    RANLIB_MIPSEL_OPENWRT ?= mipsel-openwrt-linux-musl-ranlib
    STRIP_MIPSEL_OPENWRT  ?= mipsel-openwrt-linux-musl-strip
  endif
endif

# ===== Build dir =====
BUILD_DIR ?= build

# ===== Ruleset macro with WS + App integration =====
# Call as: $(eval $(call RULESET,<name>,<outdir>,<CC>,<AR>,<RANLIB>,<STRIP>))
define RULESET
$2:
	@mkdir -p $2

# Generic pattern: build any src/*.c to $2/*.o
$2/%.o: $(SRC_DIR)/%.c | $2
	$3 $(CFLAGS) -c $$< -o $$@

# Explicit object deps to ensure header tracking
$2/hail.o: $(SRC_DIR)/hail.c $(HDR_LIB) | $2
	$3 $(CFLAGS) -c $(SRC_DIR)/hail.c -o $$@

$2/hail_app.o: $(SRC_DIR)/hail_app.c $(HDR_LIB) | $2
	$3 $(CFLAGS) -c $(SRC_DIR)/hail_app.c -o $$@

$2/hail_ws.o: $(SRC_WS) $(HDR_LIB) $(HDR_WS) | $2
	$3 $(CFLAGS) -c $(SRC_WS) -o $$@

# Static lib from hail.o + hail_app.o
$2/libhail.a: $2/hail.o $2/hail_app.o | $2
	$4 rcs $$@ $$^
	-@$5 $$@ >/dev/null 2>&1 || true

# Waybeam Core
$2/waybeam_core.o: $(SRC_DEMO) $(HDR_LIB) $(HDR_WS) | $2
	$3 $(CFLAGS) -c $(SRC_DEMO) -o $$@

$2/waybeam_core: $2/waybeam_core.o $2/hail_ws.o $2/libhail.a
	$3 $(LDFLAGS) -o $$@ $$^ $(LIBS)

# Optional ncurses demo (auto, if file present)
# ifneq ($(strip $(HAVE_NCURSES_DEMO)),)
# $2/hail_demo_cli.o: $(NCURSES_DEMO_SRC) $(HDR_LIB) $(HDR_WS) | $2
# 	$3 $(CFLAGS) -c $(NCURSES_DEMO_SRC) -o $$@
# $2/hail_demo_cli: $2/hail_demo_cli.o $2/hail_ws.o $2/libhail.a
# 	$3 $(LDFLAGS) -o $$@ $$^ $(LIBS) $(NCURSES_LIBS)
# endif

.PHONY: $1
$1: $2/libhail.a $2/hail_ws.o $2/waybeam_core
	@echo "== Built $1 =="
endef

# ===== Top-level targets =====
.PHONY: all native arm-musl arm-gnu aarch64-gnu mipsel-openwrt clean help strip install

all: native arm-musl arm-gnu aarch64-gnu mipsel-openwrt

# native
$(eval $(call RULESET,native,$(BUILD_DIR)/native,$(CC_NATIVE),$(AR_NATIVE),$(RANLIB_NATIVE),$(STRIP_NATIVE)))

# arm-musl
$(eval $(call RULESET,arm-musl,$(BUILD_DIR)/arm-musl,$(CC_ARM_MUSL),$(AR_ARM_MUSL),$(RANLIB_ARM_MUSL),$(STRIP_ARM_MUSL)))

# arm-gnu
$(eval $(call RULESET,arm-gnu,$(BUILD_DIR)/arm-gnu,$(CC_ARM_GNU),$(AR_ARM_GNU),$(RANLIB_ARM_GNU),$(STRIP_ARM_GNU)))

# aarch64-gnu
$(eval $(call RULESET,aarch64-gnu,$(BUILD_DIR)/aarch64-gnu,$(CC_AARCH64_GNU),$(AR_AARCH64_GNU),$(RANLIB_AARCH64_GNU),$(STRIP_AARCH64_GNU)))

# mipsel-openwrt
$(eval $(call RULESET,mipsel-openwrt,$(BUILD_DIR)/mipsel-openwrt,$(CC_MIPSEL_OPENWRT),$(AR_MIPSEL_OPENWRT),$(RANLIB_MIPSEL_OPENWRT),$(STRIP_MIPSEL_OPENWRT)))

# ===== Install / Deploy (best-effort) =====
INSTALL_NATIVE_DIR   ?= /usr/bin
REMOTE_BIN_DIR       ?= /usr/bin

ARM_GNU_USER         ?= root
ARM_GNU_HOST         ?= 192.168.2.202

ARM_MUSL_USER        ?= root
ARM_MUSL_HOST        ?= 192.168.2.201

AARCH64_GNU_USER     ?= root
AARCH64_GNU_HOST     ?= 192.168.2.20

MIPSEL_OPENWRT_USER  ?= root
MIPSEL_OPENWRT_HOST  ?= 192.168.2.1

# Use sudo only for the local copy step
SUDO ?= sudo

install:
	@echo "== Install / Deploy (only if built; best-effort) =="
	@if [ -x "$(BUILD_DIR)/native/waybeam_core" ]; then \
	  echo "Local install: $(BUILD_DIR)/native/waybeam_core -> $(INSTALL_NATIVE_DIR) (with sudo)"; \
	  -$(SUDO) cp "$(BUILD_DIR)/native/waybeam_core" "$(INSTALL_NATIVE_DIR)" || echo "WARN: local install failed"; \
	else echo "Skip native (not built)"; fi
	@if [ -x "$(BUILD_DIR)/arm-gnu/waybeam_core" ]; then \
	  echo "Deploy arm-gnu to $(ARM_GNU_USER)@$(ARM_GNU_HOST):$(REMOTE_BIN_DIR)"; \
	  -scp -O "$(BUILD_DIR)/arm-gnu/waybeam_core" "$(ARM_GNU_USER)@$(ARM_GNU_HOST):$(REMOTE_BIN_DIR)" || echo "WARN: arm-gnu deploy failed"; \
	else echo "Skip arm-gnu (not built)"; fi
	@if [ -x "$(BUILD_DIR)/arm-musl/waybeam_core" ]; then \
	  echo "Deploy arm-musl to $(ARM_MUSL_USER)@$(ARM_MUSL_HOST):$(REMOTE_BIN_DIR)"; \
	  -scp -O "$(BUILD_DIR)/arm-musl/waybeam_core" "$(ARM_MUSL_USER)@$(ARM_MUSL_HOST):$(REMOTE_BIN_DIR)" || echo "WARN: arm-musl deploy failed"; \
	else echo "Skip arm-musl (not built)"; fi
	@if [ -x "$(BUILD_DIR)/aarch64-gnu/waybeam_core" ]; then \
	  echo "Deploy aarch64-gnu to $(AARCH64_GNU_USER)@$(AARCH64_GNU_HOST):$(REMOTE_BIN_DIR)"; \
	  -scp -O "$(BUILD_DIR)/aarch64-gnu/waybeam_core" "$(AARCH64_GNU_USER)@$(AARCH64_GNU_HOST):$(REMOTE_BIN_DIR)" || echo "WARN: aarch64-gnu deploy failed"; \
	else echo "Skip aarch64-gnu (not built)"; fi
	@if [ -x "$(BUILD_DIR)/mipsel-openwrt/waybeam_core" ]; then \
	  echo "Deploy mipsel-openwrt to $(MIPSEL_OPENWRT_USER)@$(MIPSEL_OPENWRT_HOST):$(REMOTE_BIN_DIR)"; \
	  -scp -O "$(BUILD_DIR)/mipsel-openwrt/waybeam_core" "$(MIPSEL_OPENWRT_USER)@$(MIPSEL_OPENWRT_HOST):$(REMOTE_BIN_DIR)" || echo "WARN: mipsel-openwrt deploy failed"; \
	else echo "Skip mipsel-openwrt (not built)"; fi

# ===== Strip all binaries that exist (best-effort) =====
strip:
	-@for d in native arm-musl arm-gnu aarch64-gnu mipsel-openwrt; do \
	  for f in waybeam_core; do \
	    test -x "$(BUILD_DIR)/$$d/$$f" && $(STRIP_NATIVE) "$(BUILD_DIR)/$$d/$$f" || true; \
	  done; \
	done

clean:
	@rm -rf $(BUILD_DIR) *.o *.a waybeam_core

help:
	@echo "Usage:"
	@echo "  make native           # gcc build into build/native"
	@echo "  make arm-musl         # arm-linux-musleabihf-gcc into build/arm-musl"
	@echo "  make arm-gnu          # arm-linux-gnueabihf-gcc into build/arm-gnu"
	@echo "  make aarch64-gnu      # aarch64-linux-gnu-gcc into build/aarch64-gnu"
	@echo "  make mipsel-openwrt   # mipsel-openwrt-linux-musl-gcc into build/mipsel-openwrt"
	@echo "  make all              # build all of the above"
	@echo "  make install          # cp/scp waybeam_core to targets if built (best-effort)"
	@echo
	@echo "Override vars if needed: CFLAGS, LDFLAGS, LIBS"
	@echo "Per-arch overrides: CC_*, AR_*, RANLIB_*, STRIP_*"
	@echo "OpenWrt default: OPENWRT_MIPSEL_BIN=$(OPENWRT_MIPSEL_BIN)"
	@echo "Install dirs: INSTALL_NATIVE_DIR=$(INSTALL_NATIVE_DIR), REMOTE_BIN_DIR=$(REMOTE_BIN_DIR)"
	@echo "Hosts: arm-gnu=$(ARM_GNU_USER)@$(ARM_GNU_HOST), arm-musl=$(ARM_MUSL_USER)@$(ARM_MUSL_HOST), aarch64=$(AARCH64_GNU_USER)@$(AARCH64_GNU_HOST), mipsel=$(MIPSEL_OPENWRT_USER)@$(MIPSEL_OPENWRT_HOST)"
