package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
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
 * Static triage + debug playbook for Windows kernel drivers (.sys) and similar.
 * Live KD requires a guest + WinDbg/QEMU; this service does not attach to a live kernel.
 */
@McpToolGroup(value = "analysis", description = "Kernel/driver triage and KD playbooks (lab)")
public class KernelDriverTriageService {

    private static final Set<String> DRIVER_IMPORTS = Set.of(
        "iocreatedevice", "iocreatedevicesecure", "iodeletedevice", "iodeletesymboliclink",
        "iocreatesymboliclink", "iocompleterequest", "exallocatepool", "exallocatepool2",
        "exallocatepoolwithtag", "mmgetsystemroutineaddress", "obreferenceobjectbyhandle",
        "pscreatesystemthread", "zwquerysysteminformation", "keinitializeevent",
        "cmregistercallback", "obregistercallbacks", "ntquerydirectoryfile"
    );

    private final ProgramProvider programProvider;

    public KernelDriverTriageService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    @McpTool(path = "/kernel_driver_triage",
            description = "Static triage for kernel drivers: DriverEntry candidates, driver-like imports, "
                + "sections, and suggested IOCTL/IRP follow-ups. Lab RE only.",
            category = "analysis")
    public Response kernelDriverTriage(
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
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

        String nameLower = program.getName().toLowerCase(Locale.ROOT);
        String pathLower = meta.get("executable_path") != null
            ? meta.get("executable_path").toString().toLowerCase(Locale.ROOT) : "";
        boolean nameLooksDriver = nameLower.endsWith(".sys") || pathLower.endsWith(".sys")
            || nameLower.contains("driver");

        List<String> sections = new ArrayList<>();
        boolean hasInit = false;
        boolean hasPage = false;
        for (MemoryBlock b : program.getMemory().getBlocks()) {
            String n = b.getName() == null ? "" : b.getName();
            sections.add(n + " size=" + b.getSize() + " x=" + b.isExecute());
            String u = n.toUpperCase(Locale.ROOT);
            if (u.contains("INIT")) {
                hasInit = true;
            }
            if (u.contains("PAGE")) {
                hasPage = true;
            }
        }

        List<Map<String, Object>> driverImports = new ArrayList<>();
        SymbolTable st = program.getSymbolTable();
        for (Symbol sym : st.getExternalSymbols()) {
            String simple = sym.getName();
            if (simple.contains("::")) {
                simple = simple.substring(simple.lastIndexOf(':') + 1);
            }
            if (simple.contains("@")) {
                simple = simple.substring(0, simple.indexOf('@'));
            }
            String key = simple.toLowerCase(Locale.ROOT);
            if (DRIVER_IMPORTS.contains(key) || key.startsWith("io") && key.contains("device")
                || key.startsWith("zw") || key.startsWith("nt") && key.contains("file")) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", sym.getName());
                row.put("simple", simple);
                row.put("address", sym.getAddress().toString());
                driverImports.add(row);
                if (driverImports.size() >= 50) {
                    break;
                }
            }
        }

        List<Map<String, Object>> entryCandidates = new ArrayList<>();
        String[] names = {"DriverEntry", "GsDriverEntry", "FxDriverEntry", "entry", "_start"};
        FunctionManager fm = program.getFunctionManager();
        for (String cand : names) {
            SymbolIterator syms = st.getSymbols(cand);
            while (syms.hasNext()) {
                Symbol s = syms.next();
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("symbol", s.getName());
                row.put("address", s.getAddress().toString());
                Function f = fm.getFunctionAt(s.getAddress());
                if (f != null) {
                    row.put("function", f.getName());
                }
                entryCandidates.add(row);
            }
        }
        // Fallback: external entry points
        List<String> entries = new ArrayList<>();
        for (Address a : st.getExternalEntryPointIterator()) {
            entries.add(a.toString());
            Function f = fm.getFunctionAt(a);
            if (f != null && entryCandidates.size() < 8) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("symbol", f.getName());
                row.put("address", a.toString());
                row.put("function", f.getName());
                entryCandidates.add(row);
            }
            if (entries.size() >= 12) {
                break;
            }
        }

        List<String> largeFns = new ArrayList<>();
        FunctionIterator fit = fm.getFunctions(true);
        List<Function> sized = new ArrayList<>();
        while (fit.hasNext()) {
            Function f = fit.next();
            if (!f.isThunk() && f.getBody() != null && f.getBody().getNumAddresses() >= 80) {
                sized.add(f);
            }
        }
        sized.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
        for (int i = 0; i < Math.min(6, sized.size()); i++) {
            Function f = sized.get(i);
            largeFns.add(f.getName() + "@" + f.getEntryPoint());
        }

        boolean likelyDriver = nameLooksDriver || hasInit || !driverImports.isEmpty()
            || entryCandidates.stream().anyMatch(m -> String.valueOf(m.get("symbol")).toLowerCase(Locale.ROOT).contains("driver"));

        List<String> next = new ArrayList<>();
        next.add("decompile DriverEntry / GsDriverEntry; find DriverObject->MajorFunction assignments");
        next.add("Search for DeviceIoControl / IRP_MJ_DEVICE_CONTROL handlers and CTL_CODE constants");
        next.add("Map IoCreateDevice / symbolic link names → user-mode IOCTL surface");
        next.add("For live KD: kernel_debug_playbook then WinDbg in lab VM (never on host)");
        next.add("Optional: sig_db_match if you have a symbolized sibling driver");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("meta", meta);
        result.put("likely_kernel_driver", likelyDriver);
        result.put("hints", Map.of(
            "name_looks_driver", nameLooksDriver,
            "has_INIT_section", hasInit,
            "has_PAGE_section", hasPage,
            "driver_like_import_count", driverImports.size()
        ));
        result.put("sections_sample", sections.size() > 30 ? sections.subList(0, 30) : sections);
        result.put("entry_points", entries);
        result.put("driver_entry_candidates", entryCandidates);
        result.put("driver_like_imports", driverImports);
        result.put("decompile_first", largeFns);
        result.put("next_steps", next);
        return Response.ok(result);
    }

    @McpTool(path = "/kernel_debug_playbook",
            description = "Lab playbook for Windows kernel debugging with WinDbg/QEMU + Ghidra Debugger notes. "
                + "Does not attach to a live kernel by itself.",
            category = "analysis")
    public Response kernelDebugPlaybook(
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        Map<String, Object> result = new LinkedHashMap<>();
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (!pe.hasError()) {
            result.put("program", pe.program().getName());
            Response triage = kernelDriverTriage(programName);
            if (triage instanceof Response.Ok ok) {
                result.put("static_triage_summary", ok.data());
            }
        }

        List<String> setup = new ArrayList<>();
        setup.add("Use an isolated Windows guest (UTM/VMware/Hyper-V) with a clean snapshot");
        setup.add("Enable kernel debug: bcdedit /debug on + network/serial/pipe per hypervisor docs");
        setup.add("Host or second VM: WinDbg (WinDbg Preview) attach KD; load symbols (symchk / srv*)");
        setup.add("Optional: QEMU + gdbstub for Linux kernel modules (different playbook)");
        setup.add("Ghidra: import .sys → Analyze → kernel_driver_triage before live KD");

        List<String> windbg = List.of(
            "lm m <driver>",
            "x <driver>!DriverEntry",
            "bp <driver>!DriverEntry ; g",
            "dt _DRIVER_OBJECT",
            "!drvobj <device> 2",
            "!devobj /d",
            "Tracing IOCTL: bp nt!IofCallDriver / log Irp"
        );

        List<String> ghidraDbg = List.of(
            "User-mode only for most Ghidra Debugger sessions on macOS host",
            "For driver static: decompile + rename IRP handlers",
            "If TraceRMI Windows target available in guest tool chain: debugger/launch_offers",
            "Prefer WinDbg for true KD; use Ghidra for static map of IOCTL surface"
        );

        List<String> safety = List.of(
            "Never load unsigned experimental drivers on a primary machine",
            "KD session can BSOD the guest — snapshot first",
            "Keep samples and dumps outside git; hash in reports/"
        );

        result.put("setup", setup);
        result.put("windbg_cheatsheet", windbg);
        result.put("ghidra_notes", ghidraDbg);
        result.put("safety", safety);
        result.put("host_commands", List.of(
            "./scripts/detonate-lab.sh check",
            "MCP: kernel_driver_triage then kernel_debug_playbook"
        ));
        return Response.ok(result);
    }
}
