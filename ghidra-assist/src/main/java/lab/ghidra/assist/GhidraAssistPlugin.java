package lab.ghidra.assist;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * CodeBrowser plugin: dockable chat UI backed by the Cursor and DeepSeek backends.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "GhidraAssist",
    category = "Analysis",
    shortDescription = "Ghidra Assist chat panel",
    description = "In-Ghidra chat that runs the Cursor or DeepSeek backends with GhidraMCP tools."
)
//@formatter:on
public class GhidraAssistPlugin extends ProgramPlugin {

    public static final String OPTIONS_NAME = "Ghidra Assist";

    public static final String OPT_AGENT_PATH = "Agent binary path";
    public static final String OPT_WORKSPACE = "Workspace directory";
    public static final String OPT_MODEL = "Model (optional)";
    public static final String OPT_EXTRA_ARGS = "Extra agent args";
    public static final String OPT_MCP_URL = "GhidraMCP base URL";
    public static final String OPT_INJECT_CONTEXT = "Inject Ghidra context by default";
    public static final String OPT_DS_API_KEY = "DeepSeek API key";
    public static final String OPT_DS_BASE_URL = "DeepSeek base URL";
    public static final String OPT_DS_MODEL_V4_PRO = "DeepSeek V4 Pro model id";
    public static final String OPT_DS_MODEL_FLASH = "DeepSeek V4.1 Flash model id";
    public static final String OPT_DS_EFFORT = "DeepSeek effort";

    private AssistProvider provider;

    public GhidraAssistPlugin(PluginTool tool) {
        super(tool);
        provider = new AssistProvider(this);
        tool.addComponentProvider(provider, false);
        registerOptions();
    }

    private void registerOptions() {
        Options options = tool.getOptions(OPTIONS_NAME);
        HelpLocation help = new HelpLocation("GhidraAssist", "Options");

        options.registerOption(OPT_AGENT_PATH, "", help,
            "Absolute path to the Cursor Agent CLI (agent). Empty = auto-detect ~/.local/bin/agent");
        options.registerOption(OPT_WORKSPACE,
            System.getProperty("user.home") + "/Developments/personal/ghidra-mcp", help,
            "Workspace passed to agent --workspace (should contain .cursor/mcp.json)");
        options.registerOption(OPT_MODEL, "", help,
            "Optional --model value for the assistant backends");
        options.registerOption(OPT_EXTRA_ARGS, "", help,
            "Extra args appended to agent (space-separated)");
        options.registerOption(OPT_MCP_URL, "http://127.0.0.1:8089", help,
            "GhidraMCP HTTP base URL for health checks");
        options.registerOption(OPT_INJECT_CONTEXT, true, help,
            "Default for the Inject context checkbox");
        options.registerOption(OPT_DS_API_KEY, "", help,
            "DeepSeek API key. Empty = read DEEPSEEK_API_KEY environment variable");
        options.registerOption(OPT_DS_BASE_URL, "https://api.deepseek.com", help,
            "DeepSeek OpenAI-compatible base URL (no trailing slash)");
        options.registerOption(OPT_DS_MODEL_V4_PRO, "deepseek-v4-pro", help,
            "API model id used when the panel selects DeepSeek V4 Pro");
        options.registerOption(OPT_DS_MODEL_FLASH, "deepseek-flash", help,
            "API model id used when the panel selects DeepSeek V4.1 Flash");
        options.registerOption(OPT_DS_EFFORT, "low", help,
            "DeepSeek effort level: low (fast), high, or max");
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
