CC      := clang
CFLAGS  := -O0 -fno-inline -Wall -Wextra -arch arm64
SRC_DIR := src
BIN_DIR := bin

.PHONY: all clean check

all: $(BIN_DIR)/chal_symbols $(BIN_DIR)/chal_stripped

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/chal_symbols: $(SRC_DIR)/chal_symbols.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -g -o $@ $<
	@echo "[+] built $@ (NOT stripped)"
	@nm -gU $@ | head -20 || true
	@file $@

$(BIN_DIR)/chal_stripped: $(SRC_DIR)/chal_stripped.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<
	strip -x $@
	@echo "[+] built $@ (STRIPPED)"
	@nm -gU $@ 2>/dev/null | head -5 || echo "(no exported symbols)"
	@file $@

check: all
	@echo "--- symbols chal ---"
	@$(BIN_DIR)/chal_symbols wrong; test $$? -ne 0
	@$(BIN_DIR)/chal_symbols hunter2 | grep -F 'LAB{mcp_symbols_ok_arm64}'
	@echo "--- stripped chal ---"
	@$(BIN_DIR)/chal_stripped wrong; test $$? -ne 0
	@$(BIN_DIR)/chal_stripped ghidra | grep -F 'LAB{mcp_stripped_ok_arm64}'
	@echo "[+] check OK"

clean:
	rm -rf $(BIN_DIR)
