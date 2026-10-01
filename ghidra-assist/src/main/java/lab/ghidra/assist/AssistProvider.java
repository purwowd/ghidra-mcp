package lab.ghidra.assist;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Insets;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.IOException;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.html.HTMLEditorKit;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.services.GoToService;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import resources.Icons;

/**
 * Dockable chat panel for the Ghidra Assist backends.
 */
public class AssistProvider extends ComponentProvider {

    private static final String BACKEND_CURSOR = "Cursor";
    private static final String BACKEND_DS_V4_PRO = "DeepSeek V4 Pro";
    private static final String BACKEND_DS_FLASH = "DeepSeek V4.1 Flash";

    private final GhidraAssistPlugin plugin;
    private final JPanel mainPanel;
    private final JEditorPane transcript;
    private final JScrollPane transcriptScroll;
    private final JLabel thinkingBanner;
    private final JTextArea input;
    private final JLabel statusLabel;
    private final JLabel programLabel;
    private final JLabel mcpDot;
    private final JCheckBox injectContext;
    private final JButton sendButton;
    private final JButton stopButton;
    private final JButton newChatButton;
    private final JButton toolsButton;
    private final JButton loadPromptButton;
    private final JComboBox<String> backendBox;
    private final JPopupMenu toolsMenu;

    private final AgentProcessRunner runner;
    private final DeepSeekRunner deepseekRunner;
    private final StringBuilder markdownLog = new StringBuilder();
    private PromptPresets.Preset activePreset;
    private String chatId;
    private Program activeProgram;
    private boolean renderDirty;
    private int lastSavedLogLength;
    private Timer thinkingTimer;
    private Timer renderTimer;
    private int thinkingTick;
    private String thinkingBase = "Thinking";
    private boolean awaitingFirstChunk;

    public AssistProvider(GhidraAssistPlugin plugin) {
        super(plugin.getTool(), "Ghidra Assist", plugin.getName());
        this.plugin = plugin;
        this.runner = new AgentProcessRunner();
        this.deepseekRunner = new DeepSeekRunner();

        setDefaultWindowPosition(docking.WindowPosition.RIGHT);

        boolean dark = MarkdownLite.preferDark();
        Color chromeBg = dark ? new Color(0x30, 0x30, 0x30) : new Color(0xF2, 0xF2, 0xF2);
        Color chromeBorder = dark ? new Color(0x4A, 0x4A, 0x4A) : new Color(0xD5, 0xD5, 0xD5);
        Color accent = dark ? new Color(0x9C, 0xCC, 0x65) : new Color(0x1B, 0x5E, 0x20);
        Color bannerBg = dark ? new Color(0x33, 0x33, 0x33) : new Color(0xF0, 0xF4, 0xF8);
        Color bannerFg = dark ? new Color(0xB0, 0xBE, 0xC5) : new Color(0x54, 0x6E, 0x7A);

        transcript = new JEditorPane();
        transcript.setEditable(false);
        transcript.setContentType("text/html");
        transcript.setEditorKit(new HTMLEditorKit());
        transcript.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        transcript.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        transcript.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        transcript.addHyperlinkListener(e -> {
            if (e.getEventType() != HyperlinkEvent.EventType.ACTIVATED) {
                return;
            }
            String desc = e.getDescription();
            if (desc == null) {
                return;
            }
            goToAddressLink(desc);
        });
        transcriptScroll = new JScrollPane(transcript);
        transcriptScroll.setBorder(BorderFactory.createEmptyBorder());

        thinkingBanner = new JLabel(" ");
        thinkingBanner.setVisible(false);
        thinkingBanner.setFont(thinkingBanner.getFont().deriveFont(Font.ITALIC, 12f));
        thinkingBanner.setBorder(BorderFactory.createEmptyBorder(6, 12, 8, 12));
        thinkingBanner.setOpaque(true);
        thinkingBanner.setBackground(bannerBg);
        thinkingBanner.setForeground(bannerFg);

        JPanel transcriptWrap = new JPanel(new BorderLayout());
        transcriptWrap.add(transcriptScroll, BorderLayout.CENTER);
        transcriptWrap.add(thinkingBanner, BorderLayout.SOUTH);

        input = new JTextArea(3, 40);
        input.setLineWrap(true);
        input.setWrapStyleWord(true);
        input.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        input.setMargin(new Insets(8, 8, 8, 8));
        input.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER && (e.isMetaDown() || e.isControlDown())) {
                    e.consume();
                    send();
                }
            }
        });

        statusLabel = new JLabel("Ready");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.PLAIN, 11f));
        programLabel = new JLabel("No program");
        programLabel.setFont(programLabel.getFont().deriveFont(Font.BOLD, 13f));
        programLabel.setForeground(accent);
        mcpDot = new JLabel("●");
        mcpDot.setToolTipText("MCP status unknown — Ping from Tools");
        mcpDot.setForeground(new Color(0x88, 0x88, 0x88));

        injectContext = new JCheckBox("Context", true);
        injectContext.setToolTipText("Inject Ghidra program/cursor + prior findings into the agent prompt");
        Options opts = plugin.getAssistOptions();
        injectContext.setSelected(opts.getBoolean(GhidraAssistPlugin.OPT_INJECT_CONTEXT, true));

        sendButton = compactButton("Send");
        stopButton = compactButton("Stop");
        newChatButton = compactButton("New");
        newChatButton.setToolTipText("New chat session");
        loadPromptButton = compactButton("Prompt");
        toolsButton = compactButton("Tools ▾");
        stopButton.setEnabled(false);
        loadPromptButton.setEnabled(false);

        backendBox = new JComboBox<>(new String[] {
            BACKEND_CURSOR, BACKEND_DS_V4_PRO, BACKEND_DS_FLASH
        });
        backendBox.setToolTipText("AI backend / model used on Send");
        backendBox.setFocusable(false);
        backendBox.setMaximumSize(new Dimension(Short.MAX_VALUE, 26));

        toolsMenu = buildToolsMenu();
        toolsButton.addActionListener(e ->
            toolsMenu.show(toolsButton, 0, toolsButton.getHeight()));

        sendButton.addActionListener(e -> send());
        stopButton.addActionListener(e -> stop());
        newChatButton.addActionListener(e -> newChat());
        loadPromptButton.addActionListener(e -> loadActivePrompt());

        // Header: two rows — (1) program + backend, (2) tools
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBackground(chromeBg);
        header.setOpaque(true);
        header.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, chromeBorder),
            BorderFactory.createEmptyBorder(6, 12, 6, 12)));

        JPanel topRow = new JPanel();
        topRow.setLayout(new BoxLayout(topRow, BoxLayout.X_AXIS));
        topRow.setOpaque(false);
        topRow.add(mcpDot);
        topRow.add(Box.createHorizontalStrut(6));
        topRow.add(programLabel);
        topRow.add(Box.createHorizontalGlue());
        topRow.add(backendBox);

        JPanel toolRow = new JPanel();
        toolRow.setLayout(new BoxLayout(toolRow, BoxLayout.X_AXIS));
        toolRow.setOpaque(false);
        toolRow.add(injectContext);
        toolRow.add(Box.createHorizontalGlue());
        toolRow.add(loadPromptButton);
        toolRow.add(Box.createHorizontalStrut(4));
        toolRow.add(toolsButton);
        toolRow.add(Box.createHorizontalStrut(4));
        toolRow.add(newChatButton);

        header.add(topRow);
        header.add(Box.createVerticalStrut(4));
        header.add(toolRow);

        JPanel composer = new JPanel(new BorderLayout(6, 4));
        composer.setBackground(chromeBg);
        composer.setOpaque(true);
        composer.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, chromeBorder),
            BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        JPanel sendCol = new JPanel();
        sendCol.setLayout(new BoxLayout(sendCol, BoxLayout.Y_AXIS));
        sendCol.add(sendButton);
        sendCol.add(Box.createVerticalStrut(4));
        sendCol.add(stopButton);
        JScrollPane inputScroll = new JScrollPane(input);
        inputScroll.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 1, chromeBorder));
        composer.add(inputScroll, BorderLayout.CENTER);
        composer.add(sendCol, BorderLayout.EAST);
        composer.add(statusLabel, BorderLayout.SOUTH);

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setPreferredSize(new Dimension(480, 680));
        mainPanel.add(header, BorderLayout.NORTH);
        mainPanel.add(transcriptWrap, BorderLayout.CENTER);
        mainPanel.add(composer, BorderLayout.SOUTH);

        createActions();
        appendSystem("Ghidra Assist ready.");
        onProgramChanged(plugin.getCurrentProgramPublic());
        // Soft ping MCP in background for the status dot
        SwingUtilities.invokeLater(this::pingHealthQuiet);
    }

    private static JButton compactButton(String text) {
        JButton b = new JButton(text);
        b.setMargin(new Insets(4, 10, 4, 10));
        b.setFocusable(false);
        return b;
    }

    private JPopupMenu buildToolsMenu() {
        JPopupMenu menu = new JPopupMenu("Tools");
        menu.add(item("Ping MCP", e -> pingHealth()));
        menu.add(item("C binary triage", e -> runCBinaryTriage()));
        menu.add(item("App flow", e -> runAppFlow()));
        menu.add(item("Malware triage", e -> runMalwareTriage()));
        menu.add(item("Unpack workflow", e -> runUnpackWorkflow()));
        menu.add(item("Detonation playbook", e -> runDetonationPlaybook()));
        menu.add(item("Kernel triage", e -> runKernelTriage()));
        menu.add(item("Break WinAPI…", e -> breakWinApiDialog()));
        menu.add(item("Debug strcmp", e -> runDebugStrcmpRecipe()));
        menu.add(item("Patch bytes…", e -> applyPatchDialog()));
        menu.add(new JSeparator());
        menu.add(item("Sync bookmarks", e -> syncBookmarks()));
        menu.add(item("Save findings", e -> saveFindingsNow()));
        menu.add(new JSeparator());
        menu.add(item("Store DeepSeek key (Keychain)…", e -> storeDeepSeekKeyDialog()));
        menu.add(item("Clear DeepSeek key (Keychain)", e -> clearDeepSeekKey()));
        return menu;
    }

    private JMenuItem item(String label, java.awt.event.ActionListener action) {
        JMenuItem mi = new JMenuItem(label);
        mi.addActionListener(action);
        return mi;
    }

    private void storeDeepSeekKeyDialog() {
        javax.swing.JPasswordField pf = new javax.swing.JPasswordField(32);
        int choice = javax.swing.JOptionPane.showConfirmDialog(mainPanel, pf,
            "Store DeepSeek API key in macOS Keychain",
            javax.swing.JOptionPane.OK_CANCEL_OPTION);
        if (choice != javax.swing.JOptionPane.OK_OPTION) {
            return;
        }
        String key = new String(pf.getPassword()).trim();
        if (key.isEmpty()) {
            setStatus("Key empty — not stored");
            return;
        }
        boolean ok = KeychainStore.store(key);
        appendSystem(ok ? "DeepSeek key stored in macOS Keychain."
            : "Keychain store failed (see Ghidra log).");
        setStatus(ok ? "DeepSeek key stored in Keychain" : "Keychain store failed");
    }

    private void clearDeepSeekKey() {
        boolean ok = KeychainStore.clear();
        appendSystem(ok ? "DeepSeek key removed from macOS Keychain."
            : "Keychain clear failed.");
        setStatus(ok ? "DeepSeek key cleared" : "Keychain clear failed");
    }

    private void setStatus(String text) {
        String t = text == null ? "" : text.trim();
        statusLabel.setToolTipText(t);
        if (t.length() > 72) {
            statusLabel.setText(t.substring(0, 69) + "…");
        }
        else {
            statusLabel.setText(t.isEmpty() ? " " : t);
        }
    }

    private void setMcpDot(boolean ok, String detail) {
        if (ok) {
            mcpDot.setForeground(new Color(0x4C, 0xAF, 0x50));
            mcpDot.setToolTipText(detail == null ? "MCP healthy" : detail);
        }
        else {
            mcpDot.setForeground(new Color(0xE5, 0x73, 0x73));
            mcpDot.setToolTipText(detail == null ? "MCP down" : detail);
        }
    }

    private void createActions() {
        DockingAction show = new DockingAction("Ghidra Assist", getOwner()) {
            @Override
            public void actionPerformed(ActionContext context) {
                getTool().showComponentProvider(AssistProvider.this, true);
            }
        };
        show.setToolBarData(new ToolBarData(Icons.HELP_ICON, null));
        show.setDescription("Show Ghidra Assist chat");
        show.setEnabled(true);
        addLocalAction(show);
    }

    void onProgramChanged(Program program) {
        activeProgram = program;
        if (program == null) {
            activePreset = null;
            loadPromptButton.setEnabled(false);
            loadPromptButton.setText("Prompt");
            loadPromptButton.setToolTipText("Open a program first");
            programLabel.setText("No program");
            setStatus("Open a program in CodeBrowser");
            return;
        }

        String name = program.getName();
        programLabel.setText(name);
        programLabel.setToolTipText(program.getExecutablePath());
        activePreset = PromptPresets.matchForProgram(name);
        loadPromptButton.setEnabled(activePreset != null);
        if (activePreset != null) {
            loadPromptButton.setText(activePreset.label);
            loadPromptButton.setToolTipText("Load prompt: " + activePreset.label);
            if (input.getText().trim().isEmpty()) {
                input.setText(activePreset.prompt);
                input.setCaretPosition(0);
            }
        }
        else {
            loadPromptButton.setText("Prompt");
            loadPromptButton.setToolTipText(null);
        }

        Options opts = plugin.getAssistOptions();
        String workspace = opts.getString(GhidraAssistPlugin.OPT_WORKSPACE,
            System.getProperty("user.home") + "/Developments/personal/ghidra-mcp");
        String prior = FindingsStore.load(workspace, program);
        if (!prior.isBlank()) {
            setStatus("Prior findings available");
            appendSystem("Loaded prior findings from " + FindingsStore.findingsPath(workspace, program));
        }
        else {
            setStatus(activePreset != null ? "Prompt: " + activePreset.label : "Ready");
        }
    }

    private void goToAddressLink(String href) {
        String raw = href;
        if (raw.startsWith("ghidra:")) {
            raw = raw.substring("ghidra:".length());
        }
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        if (p == null) {
            setStatus("No program for GoTo");
            return;
        }
        Address addr = p.getAddressFactory().getAddress(raw);
        if (addr == null && raw.startsWith("0x")) {
            addr = p.getAddressFactory().getAddress(raw.substring(2));
        }
        if (addr == null) {
            setStatus("Bad address: " + raw);
            return;
        }
        GoToService gts = plugin.getTool().getService(GoToService.class);
        if (gts == null) {
            setStatus("GoToService unavailable");
            return;
        }
        boolean ok = gts.goTo(addr);
        setStatus(ok ? "GoTo " + addr : "GoTo failed: " + addr);
    }

    private void saveFindingsNow() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        if (p == null) {
            setStatus("No program — cannot save findings");
            return;
        }
        Options opts = plugin.getAssistOptions();
        String workspace = opts.getString(GhidraAssistPlugin.OPT_WORKSPACE,
            System.getProperty("user.home") + "/Developments/personal/ghidra-mcp");
        try {
            FindingsStore.saveFull(workspace, p, markdownLog.toString());
            lastSavedLogLength = markdownLog.length();
            BookmarkSync.SyncResult sync = BookmarkSync.sync(p, markdownLog.toString());
            if (sync.fromBookmarks > 0 && sync.detail.contains("## Bookmarks")) {
                int idx = sync.detail.indexOf("## Bookmarks");
                FindingsStore.append(workspace, p, sync.detail.substring(idx));
            }
            setStatus("Saved findings + bookmarks (" + sync.fromFindings + " new)");
            appendSystem("Findings saved. " + sync.detail.split("\n")[0]);
        }
        catch (IOException ex) {
            setStatus("Save failed: " + ex.getMessage());
        }
    }

    private void syncBookmarks() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        if (p == null) {
            setStatus("No program");
            return;
        }
        Options opts = plugin.getAssistOptions();
        String workspace = opts.getString(GhidraAssistPlugin.OPT_WORKSPACE,
            System.getProperty("user.home") + "/Developments/personal/ghidra-mcp");
        String findings = FindingsStore.load(workspace, p);
        if (findings.isBlank()) {
            findings = markdownLog.toString();
        }
        BookmarkSync.SyncResult sync = BookmarkSync.sync(p, findings);
        if (sync.detail.contains("## Bookmarks")) {
            int idx = sync.detail.indexOf("## Bookmarks");
            appendSystem(sync.detail.substring(idx).trim());
            try {
                FindingsStore.append(workspace, p, sync.detail.substring(idx));
            }
            catch (IOException ignored) {
                // non-fatal
            }
        }
        setStatus("Bookmarks: created=" + sync.fromFindings + " listed=" + sync.fromBookmarks);
    }

    private void applyPatchDialog() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        if (p == null) {
            setStatus("Open a program first");
            return;
        }
        javax.swing.JTextField addrField = new javax.swing.JTextField(18);
        javax.swing.JTextField hexField = new javax.swing.JTextField(24);
        hexField.setText("90");
        // Prefill cursor address if available
        try {
            ghidra.app.services.CodeViewerService cvs =
                plugin.getTool().getService(ghidra.app.services.CodeViewerService.class);
            if (cvs != null && cvs.getCurrentLocation() != null) {
                addrField.setText(cvs.getCurrentLocation().getAddress().toString());
            }
        }
        catch (Throwable ignored) {
            // ignore
        }
        javax.swing.JPanel form = new javax.swing.JPanel(new java.awt.GridLayout(0, 1, 4, 4));
        form.add(new JLabel("Address (e.g. 00401234 or 0x401234)"));
        form.add(addrField);
        form.add(new JLabel("Hex bytes (e.g. 90 or 9090)"));
        form.add(hexField);
        int choice = javax.swing.JOptionPane.showConfirmDialog(mainPanel, form,
            "Apply patch_bytes via MCP", javax.swing.JOptionPane.OK_CANCEL_OPTION);
        if (choice != javax.swing.JOptionPane.OK_OPTION) {
            return;
        }
        String addr = addrField.getText().trim();
        String hex = hexField.getText().trim();
        if (addr.isEmpty() || hex.isEmpty()) {
            setStatus("Address and hex required");
            return;
        }
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        String body = McpHttpClient.jsonObject(java.util.Map.of(
            "address", addr,
            "hex", hex,
            "note", "GhidraAssist Patch bytes",
            "program", p.getName()));
        setStatus("Patching…");
        Thread t = new Thread(() -> {
            McpHttpClient.Result r = McpHttpClient.postJson(url, "/patch_bytes", body);
            SwingUtilities.invokeLater(() -> {
                if (r.ok) {
                    appendSystem("Patched " + addr + " ← " + hex + " — " + truncate(r.body, 160));
                    setStatus("Patch OK @ " + addr);
                }
                else {
                    appendSystem("Patch FAIL: " + truncate(r.body, 200));
                    setStatus("Patch failed");
                }
            });
        }, "GhidraAssist-Patch");
        t.setDaemon(true);
        t.start();
    }

    private void runDebugStrcmpRecipe() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        String prog = p != null ? p.getName() : "";

        // Prefer MCP breakpoint; also load agent recipe into input for follow-up.
        String recipe =
            "Pakai MCP debugger pada program " + (prog.isEmpty() ? "is_current" : prog) + ".\n" +
                "Asumsi: Window → Debugger sudah open + target launched.\n\n" +
                "1) debugger/break_at_symbol symbol=strcmp\n" +
                "2) debugger/resume\n" +
                "3) saat break: debugger/registers + debugger/read_memory arg password\n" +
                "4) laporkan password yang terlihat. Teknis saja.";
        if (input.getText().trim().isEmpty()) {
            input.setText(recipe);
            input.setCaretPosition(0);
        }

        String body = McpHttpClient.jsonObject(java.util.Map.of(
            "symbol", "strcmp",
            "program", prog));
        setStatus("Debug: break_at_symbol strcmp…");
        Thread t = new Thread(() -> {
            McpHttpClient.Result r = McpHttpClient.postJson(url, "/debugger/break_at_symbol", body);
            SwingUtilities.invokeLater(() -> {
                appendSystem("Debug recipe strcmp → " + truncate(r.body, 220));
                if (r.ok) {
                    setStatus("Breakpoint requested — resume in Debugger / Send recipe");
                }
                else {
                    setStatus("Debug MCP call failed — recipe loaded in input");
                }
            });
        }, "GhidraAssist-Debug");
        t.setDaemon(true);
        t.start();
    }

    private void runAppFlow() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        String prog = p != null ? p.getName() : "";
        String path = "/program_flow_report" + (prog.isEmpty() ? ""
            : "?program=" + java.net.URLEncoder.encode(prog, java.nio.charset.StandardCharsets.UTF_8));
        setStatus("App flow report…");
        String recipe =
            "Pakai MCP ghidra pada program " + (prog.isEmpty() ? "is_current" : prog) + ".\n" +
                "Tujuan: unpack (jika perlu) + jelaskan alur kerja aplikasi.\n\n" +
                "1) program_flow_report\n" +
                "2) jika packed: instruksikan unpack-sample.sh / custom-unpack, re-import, ulangi\n" +
                "3) decompile flow_root + callees penting\n" +
                "4) tulis alur per fase: init → input → core → output/exit\n" +
                "5) Save findings. Teknis saja — bukan source .c asli.";
        if (input.getText().trim().isEmpty()) {
            input.setText(recipe);
        }
        Thread t = new Thread(() -> {
            McpHttpClient.Result r = McpHttpClient.get(url, path);
            SwingUtilities.invokeLater(() -> {
                appendSystem("program_flow_report → " + truncate(r.body, 520));
                setStatus(r.ok ? "App flow OK — Send for narrative" : "App flow failed (redeploy MCP?)");
            });
        }, "GhidraAssist-AppFlow");
        t.setDaemon(true);
        t.start();
    }

    private void runCBinaryTriage() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        String prog = p != null ? p.getName() : "";
        String path = "/c_binary_triage" + (prog.isEmpty() ? ""
            : "?program=" + java.net.URLEncoder.encode(prog, java.nio.charset.StandardCharsets.UTF_8));
        setStatus("C binary triage…");
        if (input.getText().trim().isEmpty()) {
            input.setText(PromptPresets.C_RE_PROMPT);
        }
        Thread t = new Thread(() -> {
            McpHttpClient.Result r = McpHttpClient.get(url, path);
            SwingUtilities.invokeLater(() -> {
                appendSystem("c_binary_triage → " + truncate(r.body, 480));
                setStatus(r.ok ? "C triage OK — Send to let agent decompile" : "C triage failed (redeploy MCP?)");
            });
        }, "GhidraAssist-CTriage");
        t.setDaemon(true);
        t.start();
    }

    private void runUnpackWorkflow() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        String prog = p != null ? p.getName() : "";
        String path = "/unpack_workflow" + (prog.isEmpty() ? ""
            : "?program=" + java.net.URLEncoder.encode(prog, java.nio.charset.StandardCharsets.UTF_8));
        setStatus("Unpack workflow…");
        String recipe =
            "Pakai MCP ghidra pada program " + (prog.isEmpty() ? "is_current" : prog) + ".\n" +
                "1) unpack_workflow / detect_packer\n" +
                "2) UPX → ./scripts/unpack-sample.sh; else custom-unpack-lab.sh scaffold\n" +
                "3) OEP: debugger/dump_memory_to_file atau Scylla di Windows lab\n" +
                "4) re-import dump; compare_programs_by_hash. Teknis saja.";
        if (input.getText().trim().isEmpty()) {
            input.setText(recipe);
        }
        Thread t = new Thread(() -> {
            McpHttpClient.Result r = McpHttpClient.get(url, path);
            SwingUtilities.invokeLater(() -> {
                appendSystem("unpack_workflow → " + truncate(r.body, 480));
                setStatus(r.ok ? "Unpack playbook OK — Send" : "Unpack workflow failed");
            });
        }, "GhidraAssist-Unpack");
        t.setDaemon(true);
        t.start();
    }

    private void runDetonationPlaybook() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        String prog = p != null ? p.getName() : "";
        String q = prog.isEmpty() ? ""
            : "?program=" + java.net.URLEncoder.encode(prog, java.nio.charset.StandardCharsets.UTF_8);
        setStatus("Detonation playbook…");
        String recipe =
            "Pakai MCP ghidra.\n" +
                "1) detonation_playbook\n" +
                "2) Host: ./scripts/detonate-lab.sh full <label>\n" +
                "3) JANGAN eksekusi sample di macOS host — hanya guest + snapshot + sinkhole\n" +
                "4) Setelah collect: malware_triage pada drops. Teknis saja.";
        if (input.getText().trim().isEmpty()) {
            input.setText(recipe);
        }
        Thread t = new Thread(() -> {
            McpHttpClient.Result r = McpHttpClient.get(url, "/detonation_playbook" + q);
            SwingUtilities.invokeLater(() -> {
                appendSystem("detonation_playbook → " + truncate(r.body, 480));
                setStatus(r.ok ? "Detonation playbook OK — Send" : "Detonation playbook failed");
            });
        }, "GhidraAssist-Detonate");
        t.setDaemon(true);
        t.start();
    }

    private void runKernelTriage() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        String prog = p != null ? p.getName() : "";
        String enc = prog.isEmpty() ? ""
            : "?program=" + java.net.URLEncoder.encode(prog, java.nio.charset.StandardCharsets.UTF_8);
        setStatus("Kernel triage…");
        String recipe =
            "Pakai MCP ghidra pada program " + (prog.isEmpty() ? "is_current" : prog) + ".\n" +
                "1) kernel_driver_triage\n" +
                "2) decompile DriverEntry / candidates; cari MajorFunction + IOCTL\n" +
                "3) kernel_debug_playbook untuk live KD di guest (WinDbg)\n" +
                "4) ringkas attack surface. Teknis saja.";
        if (input.getText().trim().isEmpty()) {
            input.setText(recipe);
        }
        Thread t = new Thread(() -> {
            McpHttpClient.Result r = McpHttpClient.get(url, "/kernel_driver_triage" + enc);
            McpHttpClient.Result r2 = McpHttpClient.get(url, "/kernel_debug_playbook" + enc);
            SwingUtilities.invokeLater(() -> {
                appendSystem("kernel_driver_triage → " + truncate(r.body, 400));
                appendSystem("kernel_debug_playbook → " + truncate(r2.body, 320));
                setStatus(r.ok ? "Kernel triage OK — Send" : "Kernel triage failed");
            });
        }, "GhidraAssist-Kernel");
        t.setDaemon(true);
        t.start();
    }

    private void runMalwareTriage() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        String prog = p != null ? p.getName() : "";
        String path = "/malware_triage" + (prog.isEmpty() ? ""
            : "?program=" + java.net.URLEncoder.encode(prog, java.nio.charset.StandardCharsets.UTF_8));
        setStatus("Malware triage…");
        String recipe =
            "Pakai MCP ghidra pada program " + (prog.isEmpty() ? "is_current" : prog) + ".\n" +
                "1) malware_triage\n" +
                "2) jika packed: unpack_workflow\n" +
                "3) resolve_import_thunk pada API menarik + decompile call sites\n" +
                "4) ringkas C2/persistence/injection findings. Teknis saja.";
        if (input.getText().trim().isEmpty()) {
            input.setText(recipe);
        }
        Thread t = new Thread(() -> {
            McpHttpClient.Result r = McpHttpClient.get(url, path);
            SwingUtilities.invokeLater(() -> {
                appendSystem("malware_triage → " + truncate(r.body, 400));
                setStatus(r.ok ? "Triage OK — see System + Send recipe" : "Triage failed");
            });
        }, "GhidraAssist-Triage");
        t.setDaemon(true);
        t.start();
    }

    private void breakWinApiDialog() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        String api = javax.swing.JOptionPane.showInputDialog(mainPanel,
            "API / import name to break on:",
            "VirtualAlloc");
        if (api == null || api.isBlank()) {
            return;
        }
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        String prog = p != null ? p.getName() : "";
        String body = McpHttpClient.jsonObject(java.util.Map.of(
            "name", api.trim(),
            "program", prog));
        setStatus("break_on_import " + api.trim() + "…");
        Thread t = new Thread(() -> {
            String q = "?name=" + java.net.URLEncoder.encode(api.trim(), java.nio.charset.StandardCharsets.UTF_8)
                + (prog.isEmpty() ? ""
                    : "&program=" + java.net.URLEncoder.encode(prog, java.nio.charset.StandardCharsets.UTF_8));
            McpHttpClient.Result resolved = McpHttpClient.get(url, "/resolve_import_thunk" + q);
            McpHttpClient.Result br = McpHttpClient.postJson(url, "/debugger/break_on_import", body);
            SwingUtilities.invokeLater(() -> {
                appendSystem("resolve_import_thunk → " + truncate(resolved.body, 220));
                appendSystem("break_on_import → " + truncate(br.body, 220));
                setStatus(br.ok || resolved.ok
                    ? "WinAPI break requested — open Debugger & resume"
                    : "Break failed — check Debugger session");
            });
        }, "GhidraAssist-BreakAPI");
        t.setDaemon(true);
        t.start();
    }

    private static String truncate(String s, int n) {
        if (s == null) {
            return "";
        }
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }

    private void autoAppendFindings() {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        if (p == null) {
            return;
        }
        if (markdownLog.length() <= lastSavedLogLength) {
            return;
        }
        String chunk = markdownLog.substring(lastSavedLogLength);
        Options opts = plugin.getAssistOptions();
        String workspace = opts.getString(GhidraAssistPlugin.OPT_WORKSPACE,
            System.getProperty("user.home") + "/Developments/personal/ghidra-mcp");
        try {
            FindingsStore.append(workspace, p, chunk);
            lastSavedLogLength = markdownLog.length();
        }
        catch (IOException ignored) {
            // non-fatal
        }
    }

    private void loadActivePrompt() {
        if (activePreset == null) {
            return;
        }
        input.setText(activePreset.prompt);
        input.setCaretPosition(0);
        String prog = activeProgram != null ? activeProgram.getName() : "?";
        setStatus("Loaded " + activePreset.label + " for " + prog);
    }

    private void pingHealth() {
        pingHealth(true);
    }

    private void pingHealthQuiet() {
        pingHealth(false);
    }

    private void pingHealth(boolean noisy) {
        Options opts = plugin.getAssistOptions();
        String url = opts.getString(GhidraAssistPlugin.OPT_MCP_URL, "http://127.0.0.1:8089");
        if (noisy) {
            setStatus("Pinging MCP…");
        }
        Thread t = new Thread(() -> {
            McpHealthChecker.Result r = McpHealthChecker.check(url);
            SwingUtilities.invokeLater(() -> {
                setMcpDot(r.ok, r.detail);
                if (noisy) {
                    setStatus(r.ok ? "MCP healthy" : "MCP down");
                    appendSystem(r.ok ? "MCP OK" : "MCP FAIL — " + r.detail);
                }
            });
        }, "GhidraAssist-Health");
        t.setDaemon(true);
        t.start();
    }

    private void send() {
        String userText = input.getText().trim();
        if (userText.isEmpty()) {
            return;
        }
        if (runner.isRunning() || deepseekRunner.isRunning()) {
            Msg.showWarn(this, mainPanel, "Ghidra Assist",
                "An assistant is already running. Stop it first.");
            return;
        }

        Options opts = plugin.getAssistOptions();
        String backend = backendBox.getSelectedItem() == null
            ? BACKEND_CURSOR : backendBox.getSelectedItem().toString();
        boolean deepseek = !BACKEND_CURSOR.equals(backend);
        String mcpUrl = opts.getString(GhidraAssistPlugin.OPT_MCP_URL,
            "http://127.0.0.1:8089");

        // Preflight health (non-blocking warning only)
        McpHealthChecker.Result health = McpHealthChecker.check(mcpUrl);
        if (!health.ok) {
            int choice = javax.swing.JOptionPane.showConfirmDialog(mainPanel,
                health.detail + "\n\nSend anyway?", "MCP health",
                javax.swing.JOptionPane.YES_NO_OPTION);
            if (choice != javax.swing.JOptionPane.YES_OPTION) {
                setStatus(health.detail);
                return;
            }
        }

        String prompt = userText;
        if (injectContext.isSelected()) {
            Program prog = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
            String workspace = opts.getString(GhidraAssistPlugin.OPT_WORKSPACE,
                System.getProperty("user.home") + "/Developments/personal/ghidra-mcp");
            String prior = prog != null ? FindingsStore.load(workspace, prog) : "";
            prompt = ContextBuilder.buildPrompt(plugin.getTool(), prog, userText, prior);
        }

        appendUser(userText);
        input.setText("");
        setBusy(true);
        startThinking("Thinking");
        setStatus("Thinking…");

        final String promptFinal = prompt;

        if (deepseek) {
            sendDeepSeek(opts, backend, mcpUrl, promptFinal);
            return;
        }

        final AgentProcessRunner.Config cfg = AgentProcessRunner.Config.fromOptions(opts);
        Thread t = new Thread(() -> {
            try {
                if (chatId == null || chatId.isBlank()) {
                    SwingUtilities.invokeLater(() -> updateThinkingActivity("Starting session"));
                    chatId = runner.createChat(cfg);
                    SwingUtilities.invokeLater(
                        () -> setStatus("chat " + chatId.substring(0, 8) + "…"));
                }
                runner.runPrompt(cfg, chatId, promptFinal, new AgentProcessRunner.Listener() {
                    @Override
                    public void onChunk(String text) {
                        dispatchChunk(text);
                    }

                    @Override
                    public void onStatus(String status) {
                        dispatchStatus(status);
                    }

                    @Override
                    public void onComplete(int exitCode) {
                        dispatchComplete(exitCode);
                    }

                    @Override
                    public void onError(String message) {
                        dispatchError(message);
                    }
                });
            }
            catch (Exception ex) {
                dispatchError(ex.getMessage());
            }
        }, "GhidraAssist-Agent");
        t.setDaemon(true);
        t.start();
    }

    private void sendDeepSeek(Options opts, String backend, String mcpUrl, String promptFinal) {
        String modelId = BACKEND_DS_V4_PRO.equals(backend)
            ? opts.getString(GhidraAssistPlugin.OPT_DS_MODEL_V4_PRO, "deepseek-v4-pro")
            : opts.getString(GhidraAssistPlugin.OPT_DS_MODEL_FLASH, "deepseek-flash");
        String key = opts.getString(GhidraAssistPlugin.OPT_DS_API_KEY, "").trim();
        if (key.isEmpty()) {
            key = System.getenv("DEEPSEEK_API_KEY");
        }
        if (key == null || key.isEmpty()) {
            key = KeychainStore.get();
        }
        String baseUrl = opts.getString(GhidraAssistPlugin.OPT_DS_BASE_URL,
            "https://api.deepseek.com");
        String effort = opts.getString(GhidraAssistPlugin.OPT_DS_EFFORT, "low");
        DeepSeekRunner.Config cfg = new DeepSeekRunner.Config(key, baseUrl, modelId, mcpUrl, effort);

        setStatus("Thinking (DeepSeek " + backend + ")…");
        Thread t = new Thread(() -> {
            deepseekRunner.runPrompt(cfg, promptFinal, new DeepSeekRunner.Listener() {
                @Override
                public void onChunk(String text) {
                    dispatchChunk(text);
                }

                @Override
                public void onStatus(String status) {
                    dispatchStatus(status);
                }

                @Override
                public void onComplete(int exitCode) {
                    dispatchComplete(exitCode);
                }

                @Override
                public void onError(String message) {
                    dispatchError(message);
                }
            });
        }, "GhidraAssist-DeepSeek");
        t.setDaemon(true);
        t.start();
    }

    private void dispatchChunk(String text) {
        SwingUtilities.invokeLater(() -> {
            noteAssistantOutput();
            appendAssistantChunk(text);
        });
    }

    private void dispatchStatus(String status) {
        SwingUtilities.invokeLater(() -> {
            if (status != null && !status.isBlank()) {
                updateThinkingActivity(status);
                setStatus(status);
            }
        });
    }

    private void dispatchComplete(int exitCode) {
        SwingUtilities.invokeLater(() -> {
            stopThinking();
            appendAssistantChunk("\n");
            renderNow();
            autoAppendFindings();
            setBusy(false);
            setStatus(exitCode == 0 ? "Done (findings auto-saved)" : "Exit code " + exitCode);
        });
    }

    private void dispatchError(String message) {
        SwingUtilities.invokeLater(() -> {
            stopThinking();
            appendSystem("ERROR: " + message);
            renderNow();
            setBusy(false);
            setStatus("Error");
        });
    }

    private void startThinking(String base) {
        awaitingFirstChunk = true;
        thinkingBase = base == null || base.isBlank() ? "Thinking" : base;
        thinkingTick = 0;
        thinkingBanner.setVisible(true);
        refreshThinkingBanner();
        if (thinkingTimer == null) {
            thinkingTimer = new Timer(400, e -> {
                thinkingTick++;
                refreshThinkingBanner();
            });
            thinkingTimer.setRepeats(true);
        }
        if (!thinkingTimer.isRunning()) {
            thinkingTimer.start();
        }
    }

    private void updateThinkingActivity(String activity) {
        if (activity == null || activity.isBlank()) {
            return;
        }
        String a = activity.trim();
        if (a.toLowerCase().startsWith("mcp:")) {
            thinkingBase = "Using tool " + a.substring(4).trim();
        }
        else if (a.toLowerCase().startsWith("done ")) {
            thinkingBase = "Got " + a.substring(5).trim();
        }
        else if (a.toLowerCase().contains("thinking")) {
            thinkingBase = a.length() > 60 ? a.substring(0, 57) + "…" : a;
        }
        else if (a.toLowerCase().startsWith("starting")) {
            thinkingBase = "Starting";
        }
        else {
            thinkingBase = a.length() > 60 ? a.substring(0, 57) + "…" : a;
        }
        if (awaitingFirstChunk || thinkingBanner.isVisible()) {
            thinkingBanner.setVisible(true);
            refreshThinkingBanner();
            if (thinkingTimer != null && !thinkingTimer.isRunning()) {
                thinkingTimer.start();
            }
        }
    }

    private void refreshThinkingBanner() {
        if (!thinkingBanner.isVisible()) {
            return;
        }
        int dots = (thinkingTick % 3) + 1;
        StringBuilder sb = new StringBuilder("✦ ");
        sb.append(thinkingBase);
        for (int i = 0; i < dots; i++) {
            sb.append('.');
        }
        thinkingBanner.setText(sb.toString());
    }

    private void noteAssistantOutput() {
        if (awaitingFirstChunk) {
            awaitingFirstChunk = false;
            // Keep a light "Writing…" pulse until complete, then stop on complete
            thinkingBase = "Writing response";
            refreshThinkingBanner();
        }
    }

    private void stopThinking() {
        awaitingFirstChunk = false;
        if (thinkingTimer != null) {
            thinkingTimer.stop();
        }
        thinkingBanner.setVisible(false);
        thinkingBanner.setText(" ");
    }

    private void stop() {
        runner.cancel();
        deepseekRunner.cancel();
        stopThinking();
        setStatus("Stopping…");
    }

    private void newChat() {
        if (runner.isRunning()) {
            runner.cancel();
        }
        if (deepseekRunner.isRunning()) {
            deepseekRunner.cancel();
        }
        deepseekRunner.resetConversation();
        chatId = null;
        appendSystem("--- new chat ---");
        setStatus("New chat (next send creates a session)");
    }

    private void setBusy(boolean busy) {
        sendButton.setEnabled(!busy);
        stopButton.setEnabled(busy);
        newChatButton.setEnabled(!busy);
        toolsButton.setEnabled(!busy);
        loadPromptButton.setEnabled(!busy && activePreset != null);
        injectContext.setEnabled(!busy);
        backendBox.setEnabled(!busy);
        input.setEnabled(!busy);
    }

    private void appendUser(String text) {
        markdownLog.append("\nYou:\n").append(text).append("\n\nAssistant:\n");
        scheduleRefresh();
    }

    private void appendAssistantChunk(String text) {
        markdownLog.append(text);
        scheduleRefresh();
    }

    private void appendSystem(String text) {
        markdownLog.append("\nSystem: ").append(text).append("\n");
        scheduleRefresh();
    }

    private void scheduleRefresh() {
        renderDirty = true;
        if (renderTimer == null) {
            renderTimer = new Timer(120, e -> {
                if (renderDirty) {
                    renderDirty = false;
                    renderNow();
                }
            });
            renderTimer.setRepeats(true);
            renderTimer.start();
        }
    }

    private void renderNow() {
        String html = MarkdownLite.toHtmlDocument(markdownLog.toString());
        transcript.setText(html);
        transcript.setCaretPosition(transcript.getDocument().getLength());
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    @Override
    public ActionContext getActionContext(java.awt.event.MouseEvent event) {
        Program p = activeProgram != null ? activeProgram : plugin.getCurrentProgramPublic();
        if (p != null) {
            return new ProgramActionContext(this, p);
        }
        return super.getActionContext(event);
    }

    public void dispose() {
        stopThinking();
        if (thinkingTimer != null) {
            thinkingTimer.stop();
            thinkingTimer = null;
        }
        if (renderTimer != null) {
            renderTimer.stop();
            renderTimer = null;
        }
        deepseekRunner.cancel();
        runner.cancel();
    }
}
