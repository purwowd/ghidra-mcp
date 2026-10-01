package lab.ghidra.assist;

/**
 * Built-in prompt presets (from prompts/rev-mcp.md + compiled-c-re.md).
 */
public final class PromptPresets {

    public static final class Preset {
        public final String label;
        public final String prompt;
        /** Lowercase substrings matched against active program name; empty = Generic fallback. */
        public final String[] programMatchers;

        public Preset(String label, String prompt, String... programMatchers) {
            this.label = label;
            this.prompt = prompt;
            this.programMatchers = programMatchers == null ? new String[0] : programMatchers;
        }

        public boolean matchesProgram(String programName) {
            if (programName == null || programName.isBlank() || programMatchers.length == 0) {
                return false;
            }
            String n = programName.toLowerCase();
            for (String m : programMatchers) {
                if (m != null && !m.isBlank() && n.contains(m.toLowerCase())) {
                    return true;
                }
            }
            return false;
        }
    }

    private PromptPresets() {
    }

    /** Default recipe for any compiled C/C++ (or unknown) userland binary. */
    public static final String C_RE_PROMPT =
        "Pakai MCP ghidra pada program yang sedang is_current.\n" +
            "Jangan baca source .c/.cpp dari disk / writeup online.\n\n" +
            "Pipeline compiled-C RE:\n" +
            "1) c_binary_triage — catat format, stripped?, main/entry, libc imports, decompile_first\n" +
            "2) decompile_function pada target di decompile_first (main / FUN_* besar)\n" +
            "3) strings + xrefs ke strcmp/printf/crypto bila relevan\n" +
            "4) rename_function / set prototype untuk FUN_* yang sudah dipahami\n" +
            "5) bila ada sibling ber-simbol: sig_db_match apply=true\n" +
            "6) ringkas: arsitektur, entry logic, temuan (password/flag/IOC) — teknis saja.\n\n" +
            "Ingat: hasil = C-like decompiler, bukan source asli.";

    public static Preset[] all() {
        return new Preset[] {
            new Preset("Symbols",
                "Pakai MCP ghidra pada program chal_symbols (yang terbuka / is_current).\n" +
                    "Jangan baca file source di workspace.\n\n" +
                    "1) list functions\n" +
                    "2) decompile check_password dan win\n" +
                    "3) ambil password dan flag\n" +
                    "4) jawab singkat teknis: password + flag di akhir. Skip legal/authorization boilerplate.",
                "chal_symbols"),
            new Preset("Stripped",
                "Pakai MCP ghidra pada program chal_stripped (yang terbuka / is_current).\n" +
                    "Jangan baca file source di workspace.\n\n" +
                    "1) list functions (harapkan FUN_*)\n" +
                    "2) decompile main dan helper XOR/decode\n" +
                    "3) cari key obfuscation, decode password + flag\n" +
                    "4) jawab singkat teknis: password + flag di akhir. Skip legal/authorization boilerplate.",
                "chal_stripped"),
            // Everything else (public samples, random binaries, your own C builds) → Generic C RE.
            new Preset("C RE", C_RE_PROMPT),
        };
    }

    /**
     * Best matching preset for the open program. Specific matchers win; else Generic/C RE.
     */
    public static Preset matchForProgram(String programName) {
        Preset generic = null;
        for (Preset p : all()) {
            if (p.programMatchers.length == 0) {
                generic = p;
                continue;
            }
            if (p.matchesProgram(programName)) {
                return p;
            }
        }
        return generic;
    }
}
