package lab.ghidra.cursorassist;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import ghidra.framework.options.Options;

/**
 * Spawns Cursor Agent CLI (create-chat / -p stream-json).
 */
public class AgentProcessRunner {

    public interface Listener {
        void onChunk(String text);

        void onStatus(String status);

        void onComplete(int exitCode);

        void onError(String message);
    }

    public static final class Config {
        public final String agentPath;
        public final String workspace;
        public final String model;
        public final String extraArgs;
        public final String mcpUrl;

        public Config(String agentPath, String workspace, String model, String extraArgs,
            String mcpUrl) {
            this.agentPath = agentPath;
            this.workspace = workspace;
            this.model = model;
            this.extraArgs = extraArgs;
            this.mcpUrl = mcpUrl;
        }

        public static Config fromOptions(Options opts) {
            String agent = opts.getString(GhidraCursorAssistPlugin.OPT_AGENT_PATH, "").trim();
            if (agent.isEmpty()) {
                agent = resolveDefaultAgent();
            }
            String workspace = opts.getString(GhidraCursorAssistPlugin.OPT_WORKSPACE, "").trim();
            if (workspace.isEmpty()) {
                workspace = System.getProperty("user.home") + "/Developments/personal/ghidra-mcp";
            }
            String model = opts.getString(GhidraCursorAssistPlugin.OPT_MODEL, "").trim();
            String extra = opts.getString(GhidraCursorAssistPlugin.OPT_EXTRA_ARGS, "").trim();
            String mcp = opts.getString(GhidraCursorAssistPlugin.OPT_MCP_URL, "").trim();
            if (mcp.isEmpty()) {
                mcp = "http://127.0.0.1:8089";
            }
            return new Config(agent, workspace, model, extra, mcp);
        }
    }

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicReference<Process> current = new AtomicReference<>();

    public boolean isRunning() {
        return running.get();
    }

    public void cancel() {
        Process p = current.getAndSet(null);
        if (p != null) {
            p.destroyForcibly();
        }
        running.set(false);
    }

    public String createChat(Config cfg) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(cfg.agentPath);
        cmd.add("create-chat");
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out;
        try (BufferedReader r =
            new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line.trim());
            }
            out = sb.toString().trim();
        }
        int code = p.waitFor();
        if (code != 0 || out.isEmpty()) {
            throw new IllegalStateException("agent create-chat failed (exit " + code + "): " + out);
        }
        String[] parts = out.split("\\s+");
        return parts[parts.length - 1];
    }

    public void runPrompt(Config cfg, String chatId, String prompt, Listener listener)
        throws Exception {
        if (!running.compareAndSet(false, true)) {
            listener.onError("Already running");
            return;
        }
        List<String> cmd = new ArrayList<>();
        cmd.add(cfg.agentPath);
        cmd.add("-p");
        cmd.add("--trust");
        cmd.add("--approve-mcps");
        cmd.add("--force");
        cmd.add("--workspace");
        cmd.add(cfg.workspace);
        cmd.add("--output-format");
        cmd.add("stream-json");
        cmd.add("--stream-partial-output");
        if (chatId != null && !chatId.isBlank()) {
            cmd.add("--resume");
            cmd.add(chatId);
        }
        if (cfg.model != null && !cfg.model.isBlank()) {
            cmd.add("--model");
            cmd.add(cfg.model);
        }
        if (cfg.extraArgs != null && !cfg.extraArgs.isBlank()) {
            for (String a : cfg.extraArgs.split("\\s+")) {
                if (!a.isBlank()) {
                    cmd.add(a);
                }
            }
        }
        cmd.add(prompt);

        listener.onStatus("Starting Cursor Agent…");
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        String path = pb.environment().getOrDefault("PATH", "");
        String home = System.getProperty("user.home");
        pb.environment().put("PATH", home + "/.local/bin:/opt/homebrew/bin:" + path);

        Process proc;
        try {
            proc = pb.start();
        }
        catch (Exception ex) {
            running.set(false);
            throw ex;
        }
        current.set(proc);

        boolean sawJson = false;
        boolean sawDelta = false;
        String lastSnapshot = null;
        StringBuilder plainFallback = new StringBuilder();
        String lastChunk = "";

        try (BufferedReader r =
            new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (Thread.currentThread().isInterrupted()) {
                    break;
                }
                StreamJsonParser.Event ev = StreamJsonParser.parse(line);
                switch (ev.kind) {
                    case ASSISTANT_DELTA:
                        sawJson = true;
                        sawDelta = true;
                        if (!ev.text.isEmpty() && !ev.text.equals(lastChunk)) {
                            lastChunk = ev.text;
                            listener.onChunk(ev.text);
                        }
                        break;
                    case ASSISTANT_SNAPSHOT:
                        sawJson = true;
                        lastSnapshot = ev.text;
                        // Prefer deltas; hold snapshot until end if no deltas
                        break;
                    case TOOL_STATUS:
                        sawJson = true;
                        if (!ev.text.isEmpty()) {
                            listener.onStatus(ev.text);
                        }
                        break;
                    case THINKING_STATUS:
                        sawJson = true;
                        if (!ev.text.isEmpty()) {
                            listener.onStatus(ev.text);
                        }
                        break;
                    case PLAIN:
                        plainFallback.append(ev.text).append('\n');
                        break;
                    case IGNORE:
                    default:
                        sawJson = sawJson || line.trim().startsWith("{");
                        break;
                }
            }
        }
        finally {
            int code;
            try {
                code = proc.waitFor();
            }
            catch (InterruptedException ie) {
                proc.destroyForcibly();
                Thread.currentThread().interrupt();
                code = -1;
            }
            current.compareAndSet(proc, null);
            running.set(false);

            if (!sawDelta && lastSnapshot != null && !lastSnapshot.isBlank()) {
                listener.onChunk(lastSnapshot);
            }
            else if (!sawJson && plainFallback.length() > 0) {
                listener.onChunk(plainFallback.toString());
            }
            listener.onComplete(code);
        }
    }

    static String resolveDefaultAgent() {
        String home = System.getProperty("user.home");
        File local = new File(home, ".local/bin/agent");
        if (local.isFile() && local.canExecute()) {
            return local.getAbsolutePath();
        }
        File brew = new File("/opt/homebrew/bin/agent");
        if (brew.isFile() && brew.canExecute()) {
            return brew.getAbsolutePath();
        }
        return "agent";
    }
}
