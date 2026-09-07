package com.xebyte.core;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.database.mem.FileBytes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IDA-like binary patching: edit program bytes, track undo, export patched image.
 */
@McpToolGroup(value = "program", description = "Binary patching: patch_bytes, assemble, list/revert, export")
public class PatchService {

    private static final int MAX_PATCH_BYTES = 4096;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    /** program unique key → ordered patch records (for revert). */
    private final ConcurrentHashMap<String, List<PatchRecord>> patchesByProgram = new ConcurrentHashMap<>();

    private record PatchRecord(String id, String address, byte[] previous, byte[] applied, String note) {
    }

    public PatchService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    private static String programKey(Program program) {
        return program.getDomainFile().getPathname() + "::" + program.getUniqueProgramID();
    }

    private List<PatchRecord> listFor(Program program) {
        return patchesByProgram.computeIfAbsent(programKey(program),
            k -> Collections.synchronizedList(new ArrayList<>()));
    }

    private static byte[] parseHex(String hex) {
        String cleaned = hex == null ? "" : hex.replaceAll("\\s+", "").replace("0x", "").replace("0X", "");
        if (cleaned.isEmpty() || (cleaned.length() % 2) != 0) {
            throw new IllegalArgumentException("hex must be non-empty even-length hex string");
        }
        return HexFormat.of().parseHex(cleaned);
    }

    private static String toHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    @McpTool(path = "/list_patches", description = "List in-session binary patches applied to the program (IDA-like patch tracker).", category = "program")
    public Response listPatches(
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> out = new ArrayList<>();
        for (PatchRecord r : listFor(program)) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", r.id());
            row.put("address", r.address());
            row.put("previous_hex", toHex(r.previous()));
            row.put("applied_hex", toHex(r.applied()));
            row.put("length", r.applied().length);
            row.put("note", r.note());
            out.add(row);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", program.getName());
        result.put("count", out.size());
        result.put("patches", out);
        return Response.ok(result);
    }

    @McpTool(path = "/patch_bytes", method = "POST",
            description = "Patch program memory with raw bytes (hex). Tracks previous bytes for revert. Lab RE only.",
            category = "program")
    public Response patchBytes(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                    description = "Start address to patch") String addressStr,
            @Param(value = "hex", source = ParamSource.BODY,
                    description = "Replacement bytes as hex (e.g. 9090 or 90 90)") String hex,
            @Param(value = "note", source = ParamSource.BODY, defaultValue = "",
                    description = "Optional note for the patch tracker") String note,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        final byte[] neu;
        try {
            neu = parseHex(hex);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }
        if (neu.length == 0 || neu.length > MAX_PATCH_BYTES) {
            return Response.err("hex length must be 1.." + MAX_PATCH_BYTES + " bytes");
        }

        try {
            return threadingStrategy.executeWrite(program, "MCP patch_bytes", () -> {
                Memory memory = program.getMemory();
                byte[] prev = new byte[neu.length];
                try {
                    memory.getBytes(addr, prev);
                    memory.setBytes(addr, neu);
                } catch (MemoryAccessException e) {
                    throw new RuntimeException("Memory access failed: " + e.getMessage(), e);
                }
                String id = UUID.randomUUID().toString().substring(0, 8);
                listFor(program).add(new PatchRecord(id, addr.toString(), prev, neu.clone(),
                    note == null ? "" : note));
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "success");
                result.put("id", id);
                result.put("address", addr.toString());
                result.put("previous_hex", toHex(prev));
                result.put("applied_hex", toHex(neu));
                result.put("length", neu.length);
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err("patch_bytes failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/patch_assemble", method = "POST",
            description = "Assemble instruction text at address and write bytes (Ghidra Assembler). Tracks patch for revert.",
            category = "program")
    public Response patchAssemble(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY) String addressStr,
            @Param(value = "instruction", source = ParamSource.BODY,
                    description = "Assembly text, e.g. NOP or JMP 0x401000") String instruction,
            @Param(value = "note", source = ParamSource.BODY, defaultValue = "",
                    description = "Optional note") String note,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (instruction == null || instruction.isBlank()) {
            return Response.err("instruction required");
        }
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        try {
            return threadingStrategy.executeWrite(program, "MCP patch_assemble", () -> {
                Assembler assembler = Assemblers.getAssembler(program);
                byte[] neu;
                try {
                    neu = assembler.assembleLine(addr, instruction.trim());
                } catch (Exception e) {
                    throw new RuntimeException("Assemble failed: " + e.getMessage(), e);
                }
                if (neu == null || neu.length == 0) {
                    throw new RuntimeException("Assembler produced no bytes");
                }
                if (neu.length > MAX_PATCH_BYTES) {
                    throw new RuntimeException("Assembled length exceeds " + MAX_PATCH_BYTES);
                }
                byte[] prev = new byte[neu.length];
                try {
                    program.getMemory().getBytes(addr, prev);
                    assembler.patchProgram(neu, addr);
                } catch (MemoryAccessException e) {
                    throw new RuntimeException(e);
                }
                String id = UUID.randomUUID().toString().substring(0, 8);
                listFor(program).add(new PatchRecord(id, addr.toString(), prev, neu.clone(),
                    (note == null ? "" : note) + " [assemble:" + instruction.trim() + "]"));
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "success");
                result.put("id", id);
                result.put("address", addr.toString());
                result.put("instruction", instruction.trim());
                result.put("previous_hex", toHex(prev));
                result.put("applied_hex", toHex(neu));
                result.put("length", neu.length);
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err("patch_assemble failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/revert_patch", method = "POST",
            description = "Revert a tracked patch by id (or last patch if id empty).", category = "program")
    public Response revertPatch(
            @Param(value = "id", source = ParamSource.BODY, defaultValue = "",
                    description = "Patch id from list_patches; empty = revert last") String id,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        List<PatchRecord> list = listFor(program);
        if (list.isEmpty()) {
            return Response.err("No tracked patches for this program");
        }

        PatchRecord target = null;
        synchronized (list) {
            if (id == null || id.isBlank()) {
                target = list.get(list.size() - 1);
            } else {
                for (int i = list.size() - 1; i >= 0; i--) {
                    if (list.get(i).id().equals(id)) {
                        target = list.get(i);
                        break;
                    }
                }
            }
        }
        if (target == null) {
            return Response.err("Patch id not found: " + id);
        }
        final PatchRecord rec = target;
        boolean allZero = true;
        for (byte b : rec.previous()) {
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero && rec.note() != null && rec.note().contains("[assemble:")) {
            return Response.err("Cannot safely revert assemble patch without prior bytes; patch manually");
        }

        try {
            return threadingStrategy.executeWrite(program, "MCP revert_patch", () -> {
                Address addr = ServiceUtils.parseAddress(program, rec.address());
                if (addr == null) {
                    throw new RuntimeException("Bad patch address: " + rec.address());
                }
                try {
                    program.getMemory().setBytes(addr, rec.previous());
                } catch (MemoryAccessException e) {
                    throw new RuntimeException(e);
                }
                synchronized (list) {
                    list.remove(rec);
                }
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "success");
                result.put("reverted_id", rec.id());
                result.put("address", rec.address());
                result.put("restored_hex", toHex(rec.previous()));
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err("revert_patch failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/export_patched_file", method = "POST",
            description = "Export FileBytes layer (includes in-memory patches) to an output path. Lab RE only.",
            category = "program")
    public Response exportPatchedFile(
            @Param(value = "output_path", source = ParamSource.BODY,
                    description = "Absolute path to write the patched binary") String outputPath,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (outputPath == null || outputPath.isBlank()) {
            return Response.err("output_path required");
        }
        Path out = Paths.get(outputPath);
        if (!out.isAbsolute()) {
            return Response.err("output_path must be absolute");
        }

        try {
            Memory memory = program.getMemory();
            List<FileBytes> all = memory.getAllFileBytes();
            if (all == null || all.isEmpty()) {
                return Response.err("Program has no FileBytes (cannot export file image)");
            }
            FileBytes fb = all.get(0);
            long size = fb.getSize();
            if (size <= 0 || size > 256L * 1024 * 1024) {
                return Response.err("Refusing export: FileBytes size " + size);
            }
            byte[] data = new byte[(int) size];
            fb.getModifiedBytes(0, data);

            Path parent = out.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(out, data);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "success");
            result.put("output_path", out.toString());
            result.put("bytes_written", data.length);
            result.put("file_bytes_name", fb.getFilename());
            result.put("tracked_patches", listFor(program).size());
            return Response.ok(result);
        } catch (IOException e) {
            return Response.err("export failed: " + e.getMessage());
        } catch (Exception e) {
            return Response.err("export_patched_file failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/patch_file_offset",
            description = "Resolve program address to original file offset (for offline patching notes).",
            category = "program")
    public Response patchFileOffset(
            @Param(value = "address", paramType = "address") String addressStr,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        MemoryBlock block = program.getMemory().getBlock(addr);
        if (block == null) {
            return Response.err("No memory block at address");
        }
        for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
            if (!info.contains(addr)) {
                continue;
            }
            Long fileOff = info.getFileBytesOffset(addr);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("address", addr.toString());
            result.put("block", block.getName());
            result.put("file_offset", fileOff);
            result.put("has_file_bytes", info.getFileBytes() != null);
            return Response.ok(result);
        }
        return Response.err("Address not mapped to file bytes");
    }
}
