package com.xebyte.core;

import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Lab detonation loop playbooks — scaffold guidance only; never executes samples.
 */
@McpToolGroup(value = "malware", description = "Detonation lab playbooks (guest-only execution)")
public class DetonationLabService {

    private final ProgramProvider programProvider;

    public DetonationLabService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    @McpTool(path = "/detonation_playbook",
            description = "Windows/Linux guest detonation loop for the current program: snapshot → "
                + "sinkhole → run in VM → collect → revert → Ghidra follow-up. Does not execute the sample.",
            category = "malware")
    public Response detonationPlaybook(
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName,
            @Param(value = "label", description = "Report label / hash shorthand", defaultValue = "") String label) {
        Map<String, Object> result = new LinkedHashMap<>();
        String prog = "";
        String path = "";
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (!pe.hasError()) {
            Program program = pe.program();
            prog = program.getName();
            path = program.getExecutablePath() != null ? program.getExecutablePath() : "";
            result.put("program", prog);
            result.put("executable_path_host", path);
            result.put("format", program.getExecutableFormat());
            result.put("language", program.getLanguageID().toString());
        } else if (programName != null && !programName.isBlank()) {
            return pe.error();
        }

        String labLabel = (label != null && !label.isBlank()) ? label : (prog.isBlank() ? "sample" : prog);

        List<String> loop = new ArrayList<>();
        loop.add("1. Host: ./scripts/detonate-lab.sh full " + labLabel);
        loop.add("2. Host: cd pocs/POC-DETONATION-LAB && docker compose up -d  (HTTP :8088, DNS :5353)");
        loop.add("3. Guest: restore clean snapshot; point DNS at sinkhole");
        loop.add("4. Guest: copy sample into VM only — never execute on macOS host");
        loop.add("5. Guest: start Procmon/Sysmon + PCAP; run sample once");
        loop.add("6. Guest→Host: copy drops/logs into reports/RE-" + labLabel + "/dynamic/evidence/");
        loop.add("7. Guest: revert snapshot immediately");
        loop.add("8. Ghidra: malware_triage / c_binary_triage on packed or dropped payloads");

        List<String> capture = List.of(
            "Procmon CSV (filtered)",
            "Sysmon events (ProcessCreate, NetworkConnect, FileCreate)",
            "PCAP from sinkhole / host-only tap",
            "Dropped files + hashes",
            "Persistence keys / scheduled tasks notes"
        );

        List<String> mcpFollowup = List.of(
            "malware_triage",
            "find_interesting_imports",
            "detect_packer / unpack_workflow",
            "debugger/break_on_import (in guest debug session)",
            "extract_iocs_with_context"
        );

        result.put("label", labLabel);
        result.put("loop", loop);
        result.put("capture_checklist", capture);
        result.put("mcp_followup", mcpFollowup);
        result.put("host_commands", List.of(
            "./scripts/detonate-lab.sh check",
            "./scripts/detonate-lab.sh full " + labLabel,
            "cd pocs/POC-DETONATION-LAB && docker compose up -d"
        ));
        result.put("safety", List.of(
            "No DETONATE_ON_HOST",
            "Sinkhole / host-only NIC default deny egress",
            "Hashes in git; binaries outside repo"
        ));
        result.put("lab_note", "Controlled lab only — harness never launches the sample on the analysis host");
        return Response.ok(result);
    }
}
