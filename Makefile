# EnvShield C Library — Build Instructions
#
# Targets:
#   make              — Build the static library (libenvshield.a)
#   make shared       — Build the shared library (libenvshield.so)
#   make test         — Build and run the test harness
#   make clean        — Remove build artifacts
#   make install      — Install to /usr/local/lib + /usr/local/include
#
# Prerequisites:
#   apt install build-essential libssl-dev   (Ubuntu/Debian)
#   yum install gcc openssl-devel            (RHEL/Fedora)
#   brew install openssl                     (macOS — set OPENSSL_DIR)

CC      ?= gcc
AR      ?= ar
CFLAGS  ?= -O2 -Wall -Wextra -fPIC
LDFLAGS ?= -lssl -lcrypto

# macOS Homebrew OpenSSL location (uncomment if needed):
# OPENSSL_DIR ?= /usr/local/opt/openssl@3
# CFLAGS  += -I$(OPENSSL_DIR)/include
# LDFLAGS += -L$(OPENSSL_DIR)/lib

SRC      = c/envshield.c
HDR      = c/envshield.h
OBJ      = envshield.o
STATIC   = libenvshield.a
SHARED   = libenvshield.so
TEST_SRC = test.c
TEST_BIN = test_envshield

PREFIX   ?= /usr/local

# ---------------------------------------------------------------------------

.PHONY: all shared test clean install

all: $(STATIC)

$(OBJ): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

$(STATIC): $(OBJ)
	$(AR) rcs $(STATIC) $(OBJ)
	@echo "[✓] Static library built: $(STATIC)"

shared: $(OBJ)
	$(CC) -shared -o $(SHARED) $(OBJ) $(LDFLAGS)
	@echo "[✓] Shared library built: $(SHARED)"

test: $(STATIC)
	$(CC) $(CFLAGS) -o $(TEST_BIN) $(TEST_SRC) $(STATIC) $(LDFLAGS)
	./$(TEST_BIN)

clean:
	rm -f $(OBJ) $(STATIC) $(SHARED) $(TEST_BIN)

install: $(STATIC) $(SHARED)
	install -d $(PREFIX)/lib $(PREFIX)/include/envshield
	install -m 644 $(STATIC) $(PREFIX)/lib/
	install -m 755 $(SHARED) $(PREFIX)/lib/
	install -m 644 $(HDR) $(PREFIX)/include/envshield/
	ldconfig 2>/dev/null || true
	@echo "[✓] Installed to $(PREFIX)"
