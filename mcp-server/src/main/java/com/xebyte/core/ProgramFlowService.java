package com.xebyte.core;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Linux/macOS (and general) RE deliverable: unpack status + application call/CFG flow.
 * Output is structured for Cursor Assist → findings (how the program works).
 */
@McpToolGroup(value = "analysis", description = "Program flow report: unpack + call/CFG outline")
public class ProgramFlowService {

    private final ProgramProvider programProvider;
    private final PackerAssistService packerAssistService;
    private final XrefCallGraphService xrefCallGraphService;

    public ProgramFlowService(ProgramProvider programProvider,
                              PackerAssistService packerAssistService,
                              XrefCallGraphService xrefCallGraphService) {
        this.programProvider = programProvider;
        this.packerAssistService = packerAssistService;
        this.xrefCallGraphService = xrefCallGraphService;
    }

    @McpTool(path = "/program_flow_report",
            description = "One-shot RE deliverable for ELF/Mach-O/PE: packer/unpack hints, root (main/_start), "
                + "callee call-graph, CFG summary, and a 'how it works' outline for findings. "
                + "Does not execute the binary.",
            category = "analysis")
    public Response programFlowReport(
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName,
            @Param(value = "function", description = "Root function (default: auto main/_start/entry)", defaultValue = "") String functionRef,
            @Param(value = "depth", description = "Call-graph depth for callees", defaultValue = "2") int depth) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) {
            return pe.error();
        }
        Program program = pe.program();

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("name", program.getName());
        meta.put("format", program.getExecutableFormat());
        meta.put("language", program.getLanguageID().toString());
        meta.put("compiler_spec", program.getCompilerSpec().getCompilerSpecID().toString());
        meta.put("executable_path", program.getExecutablePath());
        meta.put("image_base", program.getImageBase().toString());

        String fmt = program.getExecutableFormat() != null
            ? program.getExecutableFormat().toLowerCase(Locale.ROOT) : "";
        String platform;
        if (fmt.contains("elf")) {
            platform = "linux_elf";
        } else if (fmt.contains("mach") || fmt.contains("mac")) {
            platform = "macos_macho";
        } else if (fmt.contains("pe") || fmt.contains("portable")) {
            platform = "windows_pe";
        } else {
            platform = "unknown";
        }
        meta.put("platform_guess", platform);

        Response packerResp = packerAssistService.detectPacker(programName);
        Object packerData = packerResp instanceof Response.Ok ok ? ok.data() : Map.of();

        List<String> unpackSteps = new ArrayList<>();
        boolean packed = false;
        if (packerData instanceof Map<?, ?> pm) {
            Object p = pm.get("packed");
            packed = Boolean.TRUE.equals(p) || "true".equalsIgnoreCase(String.valueOf(p));
            Object packers = pm.get("packers");
            if (packed) {
                unpackSteps.add("Packed indicators: " + packers);
                unpackSteps.add("./scripts/unpack-sample.sh \"" +
                    (program.getExecutablePath() != null ? program.getExecutablePath() : program.getName()) + "\"");
                if ("macos_macho".equals(platform)) {
                    unpackSteps.add("Mach-O: UPX support varies; if upx -d fails, use custom-unpack-lab.sh + lldb in lab VM/container");
                }
                if ("linux_elf".equals(platform)) {
                    unpackSteps.add("ELF: after UPX, re-import; for custom packers use lldb/gdb to OEP then dump + re-import");
                }
                unpackSteps.add("Re-import unpacked → Analyze → re-run program_flow_report");
                unpackSteps.add("Optional: compare_programs_by_hash packed vs unpacked");
            } else {
                unpackSteps.add("No common packer signature — treat as already 'unpacked' for static flow analysis");
                unpackSteps.add("If runtime unpack (self-modifying): debug to OEP then debugger/dump_memory_to_file");
            }
        }

        String rootName = resolveRoot(program, functionRef);
        if (rootName == null) {
            return Response.err("Could not resolve root function (main/_start/entry). Pass function= explicitly.");
        }

        int d = Math.max(1, Math.min(depth, 4));
        Response cg = xrefCallGraphService.getFunctionCallGraph(rootName, "", d, "callees", programName);
        Object callGraph = cg instanceof Response.Ok ok ? ok.data() : Map.of("error", "call graph failed");

        Response cfg = xrefCallGraphService.getCfgSlice(rootName, 80, programName);
        Map<String, Object> cfgSummary = new LinkedHashMap<>();
        if (cfg instanceof Response.Ok ok && ok.data() instanceof Map<?, ?> cm) {
            cfgSummary.put("function", cm.get("function"));
            cfgSummary.put("entry", cm.get("entry"));
            cfgSummary.put("block_count", cm.get("block_count"));
            cfgSummary.put("edge_count", cm.get("edge_count"));
            cfgSummary.put("truncated", cm.get("truncated"));
            cfgSummary.put("note", "Full CFG via get_cfg_slice; summary only here");
        } else {
            cfgSummary.put("error", "cfg slice failed");
        }

        List<String> outline = new ArrayList<>();
        outline.add("Entry/root: " + rootName);
        if (callGraph instanceof Map<?, ?> cgm) {
            Object edges = cgm.get("edges");
            if (edges instanceof List<?> list) {
                List<String> callees = new ArrayList<>();
                for (Object e : list) {
                    if (e instanceof Map<?, ?> em) {
                        String callee = String.valueOf(em.get("callee"));
                        if (!callees.contains(callee) && callees.size() < 24) {
                            callees.add(callee);
                        }
                    }
                }
                if (!callees.isEmpty()) {
                    outline.add("Direct/near callees (depth≤" + d + "): " + String.join(", ", callees));
                }
            }
        }
        outline.add("Next: decompile_function on root + interesting callees; rename FUN_*; Save findings");

        Map<String, Object> deliverable = new LinkedHashMap<>();
        deliverable.put("title", "How " + program.getName() + " works (static RE)");
        deliverable.put("sections", List.of(
            "1. Binary identity (format/arch/packed?)",
            "2. Unpack steps / confirmation already unpacked",
            "3. Application flow from " + rootName + " (call graph + CFG)",
            "4. Decompiled logic of key functions (agent fills)",
            "5. Data/IO: strings, files, network, crypto (if any)",
            "6. Summary: phases of execution in plain language"
        ));
        deliverable.put("findings_hint", "Cursor Assist → Save findings → findings/<program>/findings.md");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("meta", meta);
        result.put("packed", packed);
        result.put("packer", packerData);
        result.put("unpack", Map.of(
            "needed", packed,
            "steps", unpackSteps,
            "scripts", List.of("./scripts/unpack-sample.sh", "./scripts/custom-unpack-lab.sh scaffold")
        ));
        result.put("flow_root", rootName);
        result.put("call_graph", callGraph);
        result.put("cfg_summary", cfgSummary);
        result.put("how_it_works_outline", outline);
        result.put("deliverable", deliverable);
        result.put("agent_next", List.of(
            "If packed: unpack then re-import before trusting flow",
            "decompile_function " + rootName,
            "decompile top callees from call_graph",
            "get_cfg_slice function=" + rootName + " for branchy logic",
            "Write phase narrative into findings"
        ));
        return Response.ok(result);
    }

    private static String resolveRoot(Program program, String functionRef) {
        FunctionManager fm = program.getFunctionManager();
        if (functionRef != null && !functionRef.isBlank()) {
            FunctionRef.Result r = FunctionRef.of(functionRef).tryResolve(program);
            if (r.isSuccess()) {
                return r.function().getName();
            }
            return null;
        }
        String[] prefs = {
            "main", "_main", "wmain", "start", "_start", "entry",
            "NSApplicationMain", "UIApplicationMain"
        };
        SymbolTable st = program.getSymbolTable();
        for (String cand : prefs) {
            SymbolIterator it = st.getSymbols(cand);
            while (it.hasNext()) {
                Symbol s = it.next();
                Function f = fm.getFunctionAt(s.getAddress());
                if (f == null) {
                    f = fm.getFunctionContaining(s.getAddress());
                }
                if (f != null && !f.isThunk()) {
                    return f.getName();
                }
            }
        }
        for (var a : st.getExternalEntryPointIterator()) {
            Function f = fm.getFunctionAt(a);
            if (f != null && !f.isThunk()) {
                return f.getName();
            }
        }
        return null;
    }
}
