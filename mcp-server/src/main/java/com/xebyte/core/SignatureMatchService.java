package com.xebyte.core;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Local FLIRT/Lumina-like function signature DB keyed by normalized opcode hashes.
 */
@McpToolGroup(value = "documentation", description = "Local function signature DB (FLIRT/Lumina-like)")
public class SignatureMatchService {

    private final ProgramProvider programProvider;
    private final DocumentationHashService hashService;
    private final Path dbPath;

    public SignatureMatchService(ProgramProvider programProvider, DocumentationHashService hashService) {
        this.programProvider = programProvider;
        this.hashService = hashService;
        String home = System.getProperty("user.home", ".");
        this.dbPath = Paths.get(home, ".ghidra-mcp", "function_sigs.json");
    }

    @McpTool(path = "/sig_db_info", description = "Show local function signature DB path and entry count.", category = "documentation")
    public Response sigDbInfo() {
        Map<String, Object> db = loadDb();
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) db.getOrDefault("entries", Map.of());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("path", dbPath.toString());
        result.put("count", entries.size());
        return Response.ok(result);
    }

    @McpTool(path = "/sig_db_add", method = "POST",
            description = "Add/update a signature: hash current function → suggested name (local FLIRT).",
            category = "documentation")
    public Response sigDbAdd(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY) String addressStr,
            @Param(value = "name", source = ParamSource.BODY, description = "Canonical name to store") String name,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (name == null || name.isBlank()) {
            return Response.err("name required");
        }
        Function func = resolveFunction(program, addressStr);
        if (func == null) {
            return Response.err("No function at " + addressStr);
        }
        String hash = hashService.hashFunction(program, func);
        Map<String, Object> db = loadDb();
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) db.computeIfAbsent("entries",
            k -> new LinkedHashMap<String, Object>());
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("name", name.trim());
        entry.put("source_program", program.getName());
        entry.put("source_address", func.getEntryPoint().toString());
        entry.put("instruction_count", hashService.countInstructions(program, func));
        entries.put(hash, entry);
        try {
            saveDb(db);
        } catch (IOException e) {
            return Response.err("Failed to save sig DB: " + e.getMessage());
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "success");
        result.put("hash", hash);
        result.put("name", name.trim());
        result.put("db_path", dbPath.toString());
        return Response.ok(result);
    }

    @McpTool(path = "/sig_db_match",
            description = "Match program functions against local signature DB; optionally apply renames.",
            category = "documentation")
    public Response sigDbMatch(
            @Param(value = "apply", defaultValue = "false",
                    description = "If true, rename auto-named functions to matched names") boolean apply,
            @Param(value = "limit", defaultValue = "200") int limit,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Map<String, Object> db = loadDb();
        @SuppressWarnings("unchecked")
        Map<String, Object> entries = (Map<String, Object>) db.getOrDefault("entries", Map.of());
        if (entries.isEmpty()) {
            return Response.ok(Map.of(
                "program", program.getName(),
                "matches", List.of(),
                "message", "Signature DB empty — add entries with sig_db_add"));
        }

        List<Map<String, Object>> matches = new ArrayList<>();
        FunctionManager fm = program.getFunctionManager();
        int checked = 0;
        for (Function func : fm.getFunctions(true)) {
            if (matches.size() >= Math.max(1, Math.min(limit, 2000))) {
                break;
            }
            checked++;
            String hash = hashService.hashFunction(program, func);
            Object raw = entries.get(hash);
            if (!(raw instanceof Map<?, ?> entry)) {
                continue;
            }
            String suggested = String.valueOf(entry.get("name"));
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", func.getEntryPoint().toString());
            row.put("current_name", func.getName());
            row.put("suggested_name", suggested);
            row.put("hash", hash);
            row.put("auto_named", ServiceUtils.isAutoGeneratedName(func.getName()));
            matches.add(row);
        }

        int renamed = 0;
        List<String> renameErrors = new ArrayList<>();
        if (apply) {
            int tx = program.startTransaction("MCP sig_db_match rename");
            boolean ok = false;
            try {
                for (Map<String, Object> row : matches) {
                    if (!Boolean.TRUE.equals(row.get("auto_named"))) {
                        continue;
                    }
                    String addrStr = (String) row.get("address");
                    String suggested = (String) row.get("suggested_name");
                    Function f = resolveFunction(program, addrStr);
                    if (f == null) {
                        continue;
                    }
                    try {
                        f.setName(suggested, ghidra.program.model.symbol.SourceType.USER_DEFINED);
                        renamed++;
                        row.put("renamed", true);
                    } catch (Exception e) {
                        row.put("renamed", false);
                        row.put("rename_error", e.getMessage());
                        renameErrors.add(addrStr + ": " + e.getMessage());
                    }
                }
                ok = true;
            } finally {
                program.endTransaction(tx, ok);
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", program.getName());
        result.put("checked", checked);
        result.put("match_count", matches.size());
        result.put("renamed", renamed);
        result.put("apply", apply);
        result.put("matches", matches);
        result.put("db_path", dbPath.toString());
        if (!renameErrors.isEmpty()) {
            result.put("rename_errors", renameErrors);
        }
        return Response.ok(result);
    }

    private Function resolveFunction(Program program, String addressStr) {
        var addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) {
            return null;
        }
        Function at = program.getFunctionManager().getFunctionAt(addr);
        if (at != null) {
            return at;
        }
        return program.getFunctionManager().getFunctionContaining(addr);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> loadDb() {
        if (!Files.isRegularFile(dbPath)) {
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("version", 1);
            empty.put("entries", new LinkedHashMap<String, Object>());
            return empty;
        }
        try {
            String json = Files.readString(dbPath, StandardCharsets.UTF_8);
            Map<String, Object> parsed = JsonHelper.parseJson(json);
            if (parsed != null) {
                parsed.computeIfAbsent("entries", k -> new LinkedHashMap<String, Object>());
                return parsed;
            }
        } catch (Exception ignored) {
            // fall through to empty
        }
        Map<String, Object> empty = new LinkedHashMap<>();
        empty.put("version", 1);
        empty.put("entries", new LinkedHashMap<String, Object>());
        return empty;
    }

    private void saveDb(Map<String, Object> db) throws IOException {
        Files.createDirectories(dbPath.getParent());
        Files.writeString(dbPath, JsonHelper.toJson(db), StandardCharsets.UTF_8);
    }
}
