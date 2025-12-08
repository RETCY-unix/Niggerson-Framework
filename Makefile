# ═══════════════════════════════════════════════════════════════════════
#  NIGGERSON FRAMEWORK - LINUX ONLY
#  Compile: make
#  Run:     sudo ./vanguard
# ═══════════════════════════════════════════════════════════════════════

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I include -D_GNU_SOURCE
LDFLAGS = -lpthread

# Source directory
SRC_DIR = src

# All source files
SRCS = $(SRC_DIR)/core/main.c

# Output binary
TARGET = vanguard

# Colors for output
GREEN = \033[0;32m
RED = \033[0;31m
NC = \033[0m

.PHONY: all clean install help

all: check_root $(TARGET)
	@echo ""
	@echo "$(GREEN)╔══════════════════════════════════════╗$(NC)"
	@echo "$(GREEN)║   VANGUARD COMPILED SUCCESSFULLY     ║$(NC)"
	@echo "$(GREEN)║         LINUX EDITION                ║$(NC)"
	@echo "$(GREEN)╚══════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "Run with: $(GREEN)sudo ./$(TARGET)$(NC)"
	@echo ""

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

check_root:
	@echo "[*] Building Niggerson Framework for Linux..."

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -f $(TARGET)
	rm -rf build/
	@echo "[+] Clean complete"

install: $(TARGET)
	@echo "[*] Installing to /usr/local/bin..."
	sudo cp $(TARGET) /usr/local/bin/
	@echo "[+] Installed! Run with: sudo vanguard"

help:
	@echo "Niggerson Framework - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make        - Build the framework"
	@echo "  make clean  - Remove build artifacts"
	@echo "  make install- Install to /usr/local/bin"
	@echo "  make help   - Show this help"
	@echo ""
	@echo "Requirements:"
	@echo "  - GCC compiler"
	@echo "  - Root privileges for network operations"
