package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Triage for compiled C/C++ userland binaries — symbols vs stripped, libc imports,
 * main/entry candidates, and a Cursor Assist–friendly next-step playbook.
 * Does not recover original .c source; recovers decompiler-level C-like logic.
 */
@McpToolGroup(value = "analysis", description = "Compiled C/C++ binary triage for agent RE workflows")
public class CBinaryTriageService {

    private static final Set<String> LIBC_HINTS = Set.of(
        "strcmp", "strncmp", "strcasecmp", "strlen", "strcpy", "strncpy", "strcat",
        "memcpy", "memmove", "memset", "memcmp", "malloc", "calloc", "realloc", "free",
        "printf", "fprintf", "sprintf", "snprintf", "puts", "putchar", "fgets", "gets",
        "scanf", "sscanf", "atoi", "atol", "strtol", "exit", "abort",
        "open", "read", "write", "close", "socket", "connect", "send", "recv",
        "pthread_create", "dlopen", "dlsym"
    );

    private static final String[] MAIN_LIKE = {
        "main", "_main", "wmain", "WinMain", "wWinMain", "entry", "_start", "start",
        "DllMain", "DriverEntry"
    };

    private final ProgramProvider programProvider;
    private final PackerAssistService packerAssistService;

    public CBinaryTriageService(ProgramProvider programProvider, PackerAssistService packerAssistService) {
        this.programProvider = programProvider;
        this.packerAssistService = packerAssistService;
    }

    @McpTool(path = "/c_binary_triage",
            description = "One-shot triage for compiled C/C++ binaries: format, stripped?, debug sections, "
                + "main/entry candidates, libc-like imports, FUN_* ratio, and RE next steps for Cursor Assist.",
            category = "analysis")
    public Response cBinaryTriage(
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) {
            return pe.error();
        }
        Program program = pe.program();

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("name", program.getName());
        meta.put("language", program.getLanguageID().toString());
        meta.put("compiler_spec", program.getCompilerSpec().getCompilerSpecID().toString());
        meta.put("image_base", program.getImageBase().toString());
        meta.put("executable_path", program.getExecutablePath());
        meta.put("format", program.getExecutableFormat());

        int totalFn = 0;
        int funStar = 0;
        int thunks = 0;
        int namedUser = 0;
        List<Map<String, Object>> largeFuns = new ArrayList<>();
        FunctionManager fm = program.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            totalFn++;
            if (f.isThunk()) {
                thunks++;
                continue;
            }
            String name = f.getName();
            if (name.startsWith("FUN_") || name.startsWith("unnamed_function_")) {
                funStar++;
            }
            else if (!name.startsWith("EXTERNAL")) {
                namedUser++;
            }
            long body = f.getBody() != null ? f.getBody().getNumAddresses() : 0;
            if (body >= 32) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", name);
                row.put("entry", f.getEntryPoint().toString());
                row.put("body_addrs", body);
                largeFuns.add(row);
            }
        }
        largeFuns.sort((a, b) -> Long.compare(
            ((Number) b.get("body_addrs")).longValue(),
            ((Number) a.get("body_addrs")).longValue()));
        if (largeFuns.size() > 8) {
            largeFuns = new ArrayList<>(largeFuns.subList(0, 8));
        }

        double strippedRatio = totalFn == 0 ? 0.0 : (double) funStar / Math.max(1, totalFn - thunks);
        boolean likelyStripped = strippedRatio >= 0.55 || (namedUser < 3 && funStar >= 5);

        List<String> debugBlocks = new ArrayList<>();
        for (MemoryBlock b : program.getMemory().getBlocks()) {
            String n = b.getName() == null ? "" : b.getName().toLowerCase(Locale.ROOT);
            if (n.contains("debug") || n.contains("dwarf") || n.contains(".zdebug")
                || n.equals(".symtab") || n.contains("pdb")) {
                debugBlocks.add(b.getName());
            }
        }
        boolean hasDebugSections = !debugBlocks.isEmpty();

        List<Map<String, Object>> mainCandidates = new ArrayList<>();
        for (String cand : MAIN_LIKE) {
            SymbolIterator syms = program.getSymbolTable().getSymbols(cand);
            while (syms.hasNext()) {
                Symbol s = syms.next();
                Function f = fm.getFunctionAt(s.getAddress());
                if (f == null) {
                    f = fm.getFunctionContaining(s.getAddress());
                }
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("symbol", s.getName());
                row.put("address", s.getAddress().toString());
                row.put("source", s.getSource() != null ? s.getSource().toString() : "");
                if (f != null) {
                    row.put("function", f.getName());
                    row.put("entry", f.getEntryPoint().toString());
                }
                mainCandidates.add(row);
                if (mainCandidates.size() >= 10) {
                    break;
                }
            }
            if (mainCandidates.size() >= 10) {
                break;
            }
        }

        List<String> entries = new ArrayList<>();
        for (Address a : program.getSymbolTable().getExternalEntryPointIterator()) {
            entries.add(a.toString());
            if (entries.size() >= 12) {
                break;
            }
        }

        List<Map<String, Object>> libcImports = new ArrayList<>();
        SymbolTable st = program.getSymbolTable();
        for (Symbol sym : st.getExternalSymbols()) {
            String simple = sym.getName();
            if (simple.contains("::")) {
                simple = simple.substring(simple.lastIndexOf(':') + 1);
            }
            if (simple.contains("@")) {
                simple = simple.substring(0, simple.indexOf('@'));
            }
            String lower = simple.toLowerCase(Locale.ROOT);
            boolean hit = LIBC_HINTS.contains(lower);
            if (!hit) {
                for (String h : LIBC_HINTS) {
                    if (lower.startsWith(h)) {
                        hit = true;
                        break;
                    }
                }
            }
            if (hit) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", sym.getName());
                row.put("simple", simple);
                row.put("address", sym.getAddress().toString());
                libcImports.add(row);
                if (libcImports.size() >= 40) {
                    break;
                }
            }
        }

        Response packerResp = packerAssistService.detectPacker(programName);
        Object packerData = packerResp instanceof Response.Ok ok ? ok.data() : Map.of("note", "packer check unavailable");

        Map<String, Object> symbols = new LinkedHashMap<>();
        symbols.put("function_count", totalFn);
        symbols.put("thunk_count", thunks);
        symbols.put("fun_star_count", funStar);
        symbols.put("named_non_thunk_approx", namedUser);
        symbols.put("fun_star_ratio_non_thunk", Math.round(strippedRatio * 1000.0) / 1000.0);
        symbols.put("likely_stripped", likelyStripped);
        symbols.put("has_debug_like_sections", hasDebugSections);
        symbols.put("debug_like_blocks", debugBlocks);

        List<String> decompileFirst = new ArrayList<>();
        for (Map<String, Object> m : mainCandidates) {
            Object fn = m.get("function");
            if (fn != null) {
                decompileFirst.add(fn.toString());
            }
        }
        for (Map<String, Object> m : largeFuns) {
            String n = String.valueOf(m.get("name"));
            if (!decompileFirst.contains(n)) {
                decompileFirst.add(n);
            }
            if (decompileFirst.size() >= 6) {
                break;
            }
        }

        List<String> next = new ArrayList<>();
        next.add("Call c_binary_triage once, then decompile_function on decompile_first targets");
        next.add("Recover C logic from decompiler (not original .c); rename FUN_* via rename_function");
        if (likelyStripped) {
            next.add("Stripped: use strings + xrefs to strcmp/printf; sig_db_match if you seeded a sibling with symbols");
        }
        else {
            next.add("Symbols present: start at main / named helpers; apply_data_type / create_struct on recovered buffers");
        }
        if (hasDebugSections) {
            next.add("Debug-like sections present — Ghidra DWARF/PDB analyzers may already enrich types/names");
        }
        next.add("Do not read original .c from disk if this is a lab challenge; prefer MCP decompile");
        next.add("Optional: emulate_function for local paths; debugger for runtime strcmp args");

        Map<String, Object> mechanism = new LinkedHashMap<>();
        mechanism.put("pipeline", List.of(
            "C/C++ source compiled → machine code + optional symbols/DWARF",
            "Import into Ghidra → Auto Analysis (disasm, funcs, xrefs, decompiler)",
            "MCP tools expose listing/decompile/rename/patch to the agent",
            "Cursor Assist injects program/cursor context and runs agent against MCP"
        ));
        mechanism.put("what_you_get", "C-like pseudocode + recoverable types/names — not the original source tree");
        mechanism.put("what_you_lose", "comments, original variable names (if stripped), macros, inlined helpers may merge");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("meta", meta);
        result.put("symbols", symbols);
        result.put("entry_points", entries);
        result.put("main_candidates", mainCandidates);
        result.put("libc_like_imports", libcImports);
        result.put("large_functions", largeFuns);
        result.put("decompile_first", decompileFirst);
        result.put("packer", packerData);
        result.put("mechanism", mechanism);
        result.put("next_steps", next);
        result.put("source_type_note", SourceType.ANALYSIS.toString() + " vs IMPORTED/USER_DEFINED names matter for trust");
        return Response.ok(result);
    }
}
