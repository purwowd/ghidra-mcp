package com.xebyte.core;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Packer triage helpers (UPX and friends) + unpack workflow hints for lab RE.
 */
@McpToolGroup(value = "analysis", description = "Packer detection and unpack workflow hints")
public class PackerAssistService {

    private final ProgramProvider programProvider;

    public PackerAssistService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    @McpTool(path = "/detect_packer",
            description = "Detect common packers (UPX, etc.) via section names, strings, and entropy hints.",
            category = "analysis")
    public Response detectPacker(
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> evidence = new ArrayList<>();
        List<String> packers = new ArrayList<>();
        Memory memory = program.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            String name = block.getName() == null ? "" : block.getName();
            String upper = name.toUpperCase(Locale.ROOT);
            if (upper.contains("UPX")) {
                packers.add("UPX");
                evidence.add("section:" + name);
            }
            if (upper.equals("MPRESS1") || upper.equals("MPRESS2")) {
                packers.add("MPRESS");
                evidence.add("section:" + name);
            }
            if (upper.contains(".ASPACK") || upper.equals("ASPACK")) {
                packers.add("ASPack");
                evidence.add("section:" + name);
            }
            if (upper.contains("PEC2") || upper.contains("PECOMPACT")) {
                packers.add("PECompact");
                evidence.add("section:" + name);
            }
            if (upper.contains("VMP") || upper.equals(".VMP0") || upper.equals(".VMP1")) {
                packers.add("VMProtect");
                evidence.add("section:" + name);
            }
            if (upper.contains("THEMIDA") || upper.contains("WINLICENSE") || upper.equals(".themida")) {
                packers.add("Themida");
                evidence.add("section:" + name);
            }
            if (upper.equals("UPX0") || upper.equals("UPX1") || upper.equals("UPX2")) {
                packers.add("UPX");
                evidence.add("section:" + name);
            }
        }

        // Sample first executable / loaded blocks for UPX magic / banner
        byte[] needleUpx = "UPX!".getBytes(StandardCharsets.US_ASCII);
        byte[] needleInfo = "UPX executable packer".getBytes(StandardCharsets.US_ASCII);
        byte[] needleVmp = "VMProtect".getBytes(StandardCharsets.US_ASCII);
        byte[] needleThemida = "Themida".getBytes(StandardCharsets.US_ASCII);
        byte[] needleAspack = "aPack".getBytes(StandardCharsets.US_ASCII);
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }
            long size = Math.min(block.getSize(), 512 * 1024);
            if (size <= 0) {
                continue;
            }
            byte[] buf = new byte[(int) size];
            try {
                memory.getBytes(block.getStart(), buf);
            } catch (MemoryAccessException e) {
                continue;
            }
            if (indexOf(buf, needleUpx) >= 0) {
                packers.add("UPX");
                evidence.add("bytes:UPX! in " + block.getName());
            }
            if (indexOf(buf, needleInfo) >= 0) {
                packers.add("UPX");
                evidence.add("string:UPX banner in " + block.getName());
            }
            if (indexOf(buf, needleVmp) >= 0) {
                packers.add("VMProtect");
                evidence.add("string:VMProtect in " + block.getName());
            }
            if (indexOf(buf, needleThemida) >= 0) {
                packers.add("Themida");
                evidence.add("string:Themida in " + block.getName());
            }
            if (indexOf(buf, needleAspack) >= 0) {
                packers.add("ASPack");
                evidence.add("string:aPack in " + block.getName());
            }
            // High entropy hint on small number of blocks
            double ent = shannonEntropy(buf);
            if (ent >= 7.2 && block.isExecute()) {
                evidence.add(String.format(Locale.ROOT, "high_entropy:%.2f in %s", ent, block.getName()));
            }
        }

        // Dedupe packers
        List<String> unique = new ArrayList<>();
        for (String p : packers) {
            if (!unique.contains(p)) {
                unique.add(p);
            }
        }

        String suggested = null;
        List<String> steps = new ArrayList<>();
        if (unique.contains("UPX")) {
            suggested = "UPX";
            String exe = program.getExecutablePath();
            steps.add("Copy the binary aside before unpacking");
            steps.add("upx -d \"" + (exe != null && !exe.isBlank() ? exe : program.getName()) + "\"");
            steps.add("Or: ./scripts/unpack-sample.sh <path-to-binary>");
            steps.add("Re-import unpacked file into Ghidra and Analyze");
            steps.add("Optionally compare packed vs unpacked with compare_programs_by_hash");
        } else if (unique.contains("VMProtect") || unique.contains("Themida")) {
            suggested = unique.contains("VMProtect") ? "VMProtect" : "Themida";
            steps.add("Commercial protector — use Windows lab VM only");
            steps.add("./scripts/custom-unpack-lab.sh scaffold <sample>");
            steps.add("x64dbg → OEP (or hardware BP on VirtualProtect/pack stubs) → Scylla dump + fix IAT");
            steps.add("Or at OEP: debugger/dump_memory_to_file from Ghidra Debugger session");
            steps.add("Re-import dump into Ghidra → compare_programs_by_hash");
        } else if (!unique.isEmpty()) {
            suggested = unique.get(0);
            steps.add("Identify packer version; try matching offline unpacker in the lab VM");
            steps.add("./scripts/custom-unpack-lab.sh scaffold <sample>");
            steps.add("Fallback: debug to OEP → dump → rebuild PE (Scylla)");
            steps.add("Re-import unpacked binary into Ghidra");
        } else {
            steps.add("No known packer signature; continue static triage (entropy may still indicate packing)");
            steps.add("If still packed: ./scripts/custom-unpack-lab.sh scaffold <sample>");
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program", program.getName());
        result.put("packed", !unique.isEmpty());
        result.put("packers", unique);
        result.put("suggested_packer", suggested);
        result.put("evidence", evidence);
        result.put("unpack_steps", steps);
        return Response.ok(result);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static double shannonEntropy(byte[] data) {
        if (data.length == 0) {
            return 0;
        }
        int[] counts = new int[256];
        for (byte b : data) {
            counts[b & 0xff]++;
        }
        double ent = 0;
        double len = data.length;
        for (int c : counts) {
            if (c == 0) {
                continue;
            }
            double p = c / len;
            ent -= p * (Math.log(p) / Math.log(2));
        }
        return ent;
    }

    @McpTool(path = "/unpack_workflow",
            description = "Lab unpack playbook for the current program: detect packer + concrete steps (UPX/local dump/re-import).",
            category = "analysis")
    public Response unpackWorkflow(
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        Response detected = detectPacker(programName);
        Map<String, Object> result = new LinkedHashMap<>();
        if (detected instanceof Response.Ok ok && ok.data() instanceof Map<?, ?> d) {
            for (Map.Entry<?, ?> e : d.entrySet()) {
                result.put(String.valueOf(e.getKey()), e.getValue());
            }
        } else if (detected instanceof Response.Err err) {
            return detected;
        }

        List<String> playbook = new ArrayList<>();
        playbook.add("1. Snapshot / copy sample outside the analysis VM");
        playbook.add("2. If UPX: ./scripts/unpack-sample.sh <path>  (keeps .packed backup)");
        playbook.add("3. Else: ./scripts/custom-unpack-lab.sh scaffold <path> then OEP dump in Windows lab");
        playbook.add("4. Re-import unpacked/dump into Ghidra → Analyze");
        playbook.add("5. compare_programs_by_hash packed vs unpacked (optional)");
        playbook.add("6. At OEP under Ghidra Debugger: debugger/dump_memory_to_file");
        playbook.add("7. Never unpack/run unknown malware on your primary macOS host");
        result.put("playbook", playbook);
        result.put("windows_lab_hint",
            "For commercial packers use an isolated Windows VM with x64dbg + Scylla; then import the dump into Ghidra.");
        result.put("automation", Map.of(
            "upx_script", "./scripts/unpack-sample.sh",
            "custom_script", "./scripts/custom-unpack-lab.sh",
            "mcp_dump", "debugger/dump_memory_to_file",
            "mcp_static_export", "export_memory_block"
        ));
        return Response.ok(result);
    }

    @McpTool(path = "/export_memory_block", method = "POST",
            description = "Export a named Ghidra memory block (or address range) to an absolute file path. "
                + "Useful after manual unpack / for dumping .text. Lab RE only.",
            category = "analysis")
    public Response exportMemoryBlock(
            @Param(value = "output_path", source = ParamSource.BODY,
                    description = "Absolute path to write raw bytes") String outputPath,
            @Param(value = "block", source = ParamSource.BODY, defaultValue = "",
                    description = "Memory block name (e.g. .text); empty = use address+size") String blockName,
            @Param(value = "address", source = ParamSource.BODY, defaultValue = "",
                    description = "Start address if block not set") String addressStr,
            @Param(value = "size", source = ParamSource.BODY, defaultValue = "0",
                    description = "Byte count when using address (max 64MB)") int size,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) {
            return pe.error();
        }
        Program program = pe.program();
        if (outputPath == null || outputPath.isBlank()) {
            return Response.err("output_path required");
        }
        java.nio.file.Path out = java.nio.file.Paths.get(outputPath);
        if (!out.isAbsolute()) {
            return Response.err("output_path must be absolute");
        }

        try {
            Memory memory = program.getMemory();
            byte[] data;
            String source;
            if (blockName != null && !blockName.isBlank()) {
                MemoryBlock block = memory.getBlock(blockName);
                if (block == null) {
                    return Response.err("Block not found: " + blockName);
                }
                if (!block.isInitialized()) {
                    return Response.err("Block not initialized: " + blockName);
                }
                long bsz = block.getSize();
                if (bsz <= 0 || bsz > 64L * 1024 * 1024) {
                    return Response.err("Refusing block size " + bsz);
                }
                data = new byte[(int) bsz];
                memory.getBytes(block.getStart(), data);
                source = "block:" + blockName;
            } else {
                ghidra.program.model.address.Address addr = ServiceUtils.parseAddress(program, addressStr);
                if (addr == null) {
                    return Response.err(ServiceUtils.getLastParseError());
                }
                int n = size;
                if (n <= 0 || n > 64 * 1024 * 1024) {
                    return Response.err("size must be 1..64MB");
                }
                data = new byte[n];
                memory.getBytes(addr, data);
                source = "addr:" + addr;
            }
            if (out.getParent() != null) {
                java.nio.file.Files.createDirectories(out.getParent());
            }
            java.nio.file.Files.write(out, data);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "success");
            result.put("output_path", out.toString());
            result.put("bytes_written", data.length);
            result.put("source", source);
            result.put("next", "If this is an OEP image dump, rebuild PE (Scylla) or re-import raw for analysis");
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("export_memory_block failed: " + e.getMessage());
        }
    }
}
