package lab.ghidra.cursorassist;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * CodeBrowser plugin: dockable chat UI backed by Cursor Agent CLI.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "GhidraCursorAssist",
    category = "Analysis",
    shortDescription = "Cursor Agent chat panel",
    description = "In-Ghidra chat that runs Cursor Agent CLI with GhidraMCP tools."
)
//@formatter:on
public class GhidraCursorAssistPlugin extends ProgramPlugin {

    public static final String OPTIONS_NAME = "Cursor Assist";

    public static final String OPT_AGENT_PATH = "Agent binary path";
    public static final String OPT_WORKSPACE = "Workspace directory";
    public static final String OPT_MODEL = "Model (optional)";
    public static final String OPT_EXTRA_ARGS = "Extra agent args";
    public static final String OPT_MCP_URL = "GhidraMCP base URL";
    public static final String OPT_INJECT_CONTEXT = "Inject Ghidra context by default";

    private CursorAssistProvider provider;

    public GhidraCursorAssistPlugin(PluginTool tool) {
        super(tool);
        provider = new CursorAssistProvider(this);
        tool.addComponentProvider(provider, false);
        registerOptions();
    }

    private void registerOptions() {
        Options options = tool.getOptions(OPTIONS_NAME);
        HelpLocation help = new HelpLocation("GhidraCursorAssist", "Options");

        options.registerOption(OPT_AGENT_PATH, "", help,
            "Absolute path to the Cursor Agent CLI (agent). Empty = auto-detect ~/.local/bin/agent");
        options.registerOption(OPT_WORKSPACE,
            System.getProperty("user.home") + "/Developments/personal/ghidra-mcp", help,
            "Workspace passed to agent --workspace (should contain .cursor/mcp.json)");
        options.registerOption(OPT_MODEL, "", help,
            "Optional --model value for Cursor Agent");
        options.registerOption(OPT_EXTRA_ARGS, "", help,
            "Extra args appended to agent (space-separated)");
        options.registerOption(OPT_MCP_URL, "http://127.0.0.1:8089", help,
            "GhidraMCP HTTP base URL for health checks");
        options.registerOption(OPT_INJECT_CONTEXT, true, help,
            "Default for the Inject context checkbox");
    }

    Options getAssistOptions() {
        return tool.getOptions(OPTIONS_NAME);
    }

    Program getCurrentProgramPublic() {
        return getCurrentProgram();
    }

    @Override
    protected void programActivated(Program program) {
        if (provider != null) {
            provider.onProgramChanged(program);
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        if (provider != null) {
            provider.onProgramChanged(null);
        }
    }

    @Override
    protected void dispose() {
        if (provider != null) {
            provider.dispose();
            tool.removeComponentProvider(provider);
            provider = null;
        }
        super.dispose();
    }
}
