package lab.ghidra.cursorassist;

import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;

/**
 * Builds a preamble with active Ghidra program / cursor context for Cursor Agent.
 */
public final class ContextBuilder {

    private ContextBuilder() {
    }

    public static String buildPrompt(PluginTool tool, Program program, String userText) {
        return buildPrompt(tool, program, userText, null);
    }

    public static String buildPrompt(PluginTool tool, Program program, String userText, String priorFindings) {
        StringBuilder sb = new StringBuilder();
        sb.append("[Ghidra context]\n");
        if (program == null) {
            sb.append("program=(none open)\n");
        }
        else {
            sb.append("program=").append(program.getName()).append('\n');
            sb.append("language=").append(program.getLanguageID()).append('\n');
            sb.append("compiler=").append(program.getCompilerSpec().getCompilerSpecID()).append('\n');
            String fmt = program.getExecutableFormat();
            if (fmt != null && !fmt.isBlank()) {
                sb.append("format=").append(fmt).append('\n');
            }
            sb.append("image_base=").append(program.getImageBase()).append('\n');

            int total = 0;
            int funStar = 0;
            FunctionManager fm = program.getFunctionManager();
            FunctionIterator fit = fm.getFunctions(true);
            while (fit.hasNext()) {
                Function f = fit.next();
                if (f.isThunk()) {
                    continue;
                }
                total++;
                String n = f.getName();
                if (n.startsWith("FUN_") || n.startsWith("unnamed_function_")) {
                    funStar++;
                }
            }
            sb.append("functions_non_thunk=").append(total).append('\n');
            sb.append("fun_star_count=").append(funStar).append('\n');
            if (total > 0) {
                boolean stripped = ((double) funStar / total) >= 0.55 || (funStar >= 5 && funStar > total - 3);
                sb.append("likely_stripped=").append(stripped).append('\n');
            }

            boolean debugLike = false;
            for (MemoryBlock b : program.getMemory().getBlocks()) {
                String bn = b.getName() == null ? "" : b.getName().toLowerCase();
                if (bn.contains("debug") || bn.contains("dwarf") || bn.contains("pdb")) {
                    debugLike = true;
                    break;
                }
            }
            sb.append("debug_like_sections=").append(debugLike).append('\n');

            Address addr = null;
            ProgramLocation loc = null;
            try {
                CodeViewerService cvs = tool.getService(CodeViewerService.class);
                if (cvs != null) {
                    loc = cvs.getCurrentLocation();
                }
            }
            catch (Throwable ignored) {
                // service unavailable
            }
            if (loc != null) {
                addr = loc.getAddress();
            }
            if (addr != null) {
                sb.append("address=").append(addr).append('\n');
                Function fn = fm.getFunctionContaining(addr);
                if (fn != null) {
                    sb.append("function=").append(fn.getName()).append('\n');
                    sb.append("function_entry=").append(fn.getEntryPoint()).append('\n');
                }
                else {
                    sb.append("function=(none at cursor)\n");
                }
            }
            else {
                sb.append("address=(unknown)\n");
                sb.append("function=(unknown)\n");
            }
        }
        if (priorFindings != null && !priorFindings.isBlank()) {
            String clip = priorFindings.length() > 4000
                ? priorFindings.substring(priorFindings.length() - 4000)
                : priorFindings;
            sb.append("\n[Prior findings for this program]\n");
            sb.append(clip).append('\n');
        }
        sb.append("Prefer MCP ghidra tools for decompile/list/strings; do not invent decompilation.\n");
        sb.append("For compiled C/C++: start with c_binary_triage when unsure; recover logic via decompile — not original .c.\n");
        sb.append("Use the program named above (is_current) when calling tools.\n");
        sb.append("Reply with technical findings only. Skip legal, authorization, and policy boilerplate.\n");
        sb.append("Do not echo this Ghidra context block back to the user.\n");
        sb.append("\n[User]\n");
        sb.append(userText);
        return sb.toString();
    }
}
