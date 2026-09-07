/*
 * Lab crackme — STRIPPED (no symbols).
 * Goal: recover the XOR-decoded password / flag via Ghidra MCP.
 *
 * Password: ghidra
 * Flag:     LAB{mcp_stripped_ok_arm64}
 *
 * Password bytes are stored XOR'd with 0x37 so a naive strings pass
 * will not show "ghidra" / the flag plaintext.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* "ghidra" XOR 0x37 */
static const uint8_t OBF_PASS[] = {0x50, 0x5f, 0x5e, 0x53, 0x45, 0x56};
/* "LAB{mcp_stripped_ok_arm64}" XOR 0x37 */
static const uint8_t OBF_FLAG[] = {
    0x7b, 0x76, 0x75, 0x4c, 0x5a, 0x54, 0x47, 0x68, 0x44, 0x43, 0x45, 0x5e,
    0x47, 0x47, 0x52, 0x53, 0x68, 0x58, 0x5c, 0x68, 0x56, 0x45, 0x5a, 0x01,
    0x03, 0x4a
};

static void xor_decode(const uint8_t *in, size_t n, char *out, uint8_t key) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)(in[i] ^ key);
    }
    out[n] = '\0';
}

static int validate(const char *guess) {
    char expected[16];
    xor_decode(OBF_PASS, sizeof(OBF_PASS), expected, 0x37);
    if (guess == NULL) {
        return 0;
    }
    return strcmp(guess, expected) == 0;
}

static void emit_flag(void) {
    char flag[48];
    xor_decode(OBF_FLAG, sizeof(OBF_FLAG), flag, 0x37);
    printf("Correct! Flag: %s\n", flag);
}

int main(int argc, char **argv) {
    char buf[64];

    puts("=== MCP Test Chal: STRIPPED ===");
    puts("Enter password:");

    if (argc >= 2) {
        strncpy(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
    } else {
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            puts("Nope.");
            return 1;
        }
        buf[strcspn(buf, "\n")] = '\0';
    }

    if (validate(buf)) {
        emit_flag();
        return 0;
    }

    puts("Nope.");
    return 1;
}
