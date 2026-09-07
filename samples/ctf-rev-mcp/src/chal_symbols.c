/*
 * Lab crackme — NOT stripped (symbols kept).
 * Goal: recover the password and print the flag via Ghidra MCP.
 *
 * Expected password: hunter2
 * Flag: LAB{mcp_symbols_ok_arm64}
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *SECRET_PASSWORD = "hunter2";
static const char *FLAG = "LAB{mcp_symbols_ok_arm64}";

static int check_password(const char *guess) {
    if (guess == NULL) {
        return 0;
    }
    return strcmp(guess, SECRET_PASSWORD) == 0;
}

static void print_banner(void) {
    puts("=== MCP Test Chal: symbols (NOT stripped) ===");
    puts("Enter password:");
}

static void win(void) {
    printf("Correct! Flag: %s\n", FLAG);
}

static void lose(void) {
    puts("Nope.");
}

int main(int argc, char **argv) {
    char buf[64];

    print_banner();

    if (argc >= 2) {
        strncpy(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
    } else {
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            lose();
            return 1;
        }
        buf[strcspn(buf, "\n")] = '\0';
    }

    if (check_password(buf)) {
        win();
        return 0;
    }

    lose();
    return 1;
}
