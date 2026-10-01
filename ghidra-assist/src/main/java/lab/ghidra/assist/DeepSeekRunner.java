package lab.ghidra.assist;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

/**
 * DeepSeek backend for the Assist panel.
 *
 * Talks to DeepSeek's OpenAI-compatible {@code /chat/completions} API with
 * function calling. Each function maps to a GhidraMCP HTTP endpoint discovered
 * live from {@code /mcp/schema}, so the model drives the same tool surface the
 * Python bridge exposes over stdio — without the Cursor backend.
 */
public final class DeepSeekRunner {

    public interface Listener {
        void onChunk(String text);

        void onStatus(String status);

        void onComplete(int exitCode);

        void onError(String message);
    }

    public static final class Config {
        public final String apiKey;
        public final String baseUrl;
        public final String model;
        public final String mcpUrl;
        public final String effort;

        public Config(String apiKey, String baseUrl, String model, String mcpUrl, String effort) {
            this.apiKey = apiKey;
            this.baseUrl = baseUrl == null || baseUrl.isBlank()
                ? "https://api.deepseek.com" : baseUrl;
            this.model = model == null || model.isBlank() ? "deepseek-v4-pro" : model;
            this.mcpUrl = mcpUrl == null || mcpUrl.isBlank()
                ? "http://127.0.0.1:8089" : mcpUrl;
            this.effort = effort == null || effort.isBlank() ? "low" : effort;
        }
    }

    private static final String SYSTEM_PROMPT =
        "You are a reverse-engineering assistant driving the Ghidra MCP tools of the "
            + "currently open program. Use the provided tools to inspect functions, decompile, "
            + "list strings and cross-references, and answer the user's question with concrete "
            + "evidence (addresses, decompiled code). Be technical and concise; skip legal or "
            + "authorization boilerplate.";

    private static final int MAX_TOOL_ITERATIONS = 20;
    private static final int MAX_TOOL_RESULT_CHARS = 60000;
    private static final Gson GSON = new Gson();

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicReference<HttpURLConnection> activeConn = new AtomicReference<>();
    private JsonArray history;

    public boolean isRunning() {
        return running.get();
    }

    public void cancel() {
        running.set(false);
        HttpURLConnection c = activeConn.getAndSet(null);
        if (c != null) {
            try {
                c.disconnect();
            }
            catch (Exception ignored) {
                // ignore
            }
        }
    }

    public void runPrompt(Config cfg, String prompt, Listener listener) {
        if (!running.compareAndSet(false, true)) {
            listener.onError("Already running");
            return;
        }
        try {
            if (cfg.apiKey == null || cfg.apiKey.isBlank()) {
                listener.onError(
                    "DeepSeek API key missing — set DEEPSEEK_API_KEY, the Tool Options field, "
                        + "or store it in the macOS Keychain");
                return;
            }
            if (history == null) {
                history = new JsonArray();
                history.add(msg("system", SYSTEM_PROMPT));
            }
            history.add(msg("user", prompt));
            List<ToolSpec> tools = fetchTools(cfg.mcpUrl, listener);
            chatLoop(cfg, tools, history, listener);
            listener.onComplete(0);
        }
        catch (Exception ex) {
            listener.onError(
                ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
        }
        finally {
            running.set(false);
        }
    }

    /** Clear conversation history so the next prompt starts fresh. */
    public void resetConversation() {
        history = null;
    }

    // ==================================================================
    // Chat loop
    // ==================================================================

    private void chatLoop(Config cfg, List<ToolSpec> tools, JsonArray messages, Listener listener)
        throws Exception {
        int iteration = 0;
        while (running.get() && iteration < MAX_TOOL_ITERATIONS) {
            iteration++;
            JsonObject req = new JsonObject();
            req.addProperty("model", cfg.model);
            if (cfg.effort != null && !cfg.effort.isBlank()) {
                req.addProperty("effort", cfg.effort);
            }
            req.add("messages", messages);
            if (!tools.isEmpty()) {
                req.add("tools", buildToolsJson(tools));
                req.addProperty("tool_choice", "auto");
            }
            req.addProperty("stream", true);

            StreamResult result = streamChat(cfg, req, listener);
            if (result.toolCalls.isEmpty()) {
                // Final answer already streamed as text deltas.
                return;
            }

            JsonObject assistant = msg("assistant", null);
            JsonArray tcArray = new JsonArray();
            for (ToolCall tc : result.toolCalls) {
                JsonObject fn = new JsonObject();
                fn.addProperty("name", tc.name);
                fn.addProperty("arguments", tc.arguments.toString());
                JsonObject tcObj = new JsonObject();
                tcObj.addProperty("id", tc.id);
                tcObj.addProperty("type", "function");
                tcObj.add("function", fn);
                tcArray.add(tcObj);
            }
            assistant.add("tool_calls", tcArray);
            messages.add(assistant);

            for (ToolCall tc : result.toolCalls) {
                if (!running.get()) {
                    return;
                }
                listener.onStatus("MCP: " + tc.name);
                String outcome = executeTool(cfg.mcpUrl, tools, tc);
                JsonObject toolMsg = new JsonObject();
                toolMsg.addProperty("role", "tool");
                toolMsg.addProperty("tool_call_id", tc.id);
                toolMsg.addProperty("content", outcome);
                messages.add(toolMsg);
                listener.onStatus("done " + tc.name);
            }
        }
    }

    private static final class StreamResult {
        String finishReason = "";
        final List<ToolCall> toolCalls = new ArrayList<>();
    }

    private static final class ToolCall {
        String id = "";
        String name = "";
        final StringBuilder arguments = new StringBuilder();
    }

    private StreamResult streamChat(Config cfg, JsonObject req, Listener listener) throws Exception {
        String url = cfg.baseUrl.replaceAll("/$", "") + "/chat/completions";
        HttpURLConnection conn = open(url, 15000, 120000);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        conn.setRequestProperty("Authorization", "Bearer " + cfg.apiKey);
        conn.setDoOutput(true);
        byte[] bodyBytes = req.toString().getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyBytes);
        }
        activeConn.set(conn);
        try {
            int code = conn.getResponseCode();
            if (code >= 400) {
                String err = readAll(conn.getErrorStream());
                throw new IllegalStateException("DeepSeek HTTP " + code + ": " + truncate(err, 500));
            }
            StreamResult result = new StreamResult();
            Map<Integer, ToolCall> toolAcc = new LinkedHashMap<>();
            try (BufferedReader r = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while (running.get() && (line = r.readLine()) != null) {
                    if (line.isEmpty()) {
                        continue;
                    }
                    if (line.startsWith("data:")) {
                        String data = line.substring(5).trim();
                        if (data.equals("[DONE]")) {
                            break;
                        }
                        try {
                            JsonElement el = JsonParser.parseString(data);
                            if (el.isJsonObject()) {
                                handleDelta(el.getAsJsonObject(), result, toolAcc, listener);
                            }
                        }
                        catch (Exception ignored) {
                            // skip malformed SSE frame
                        }
                    }
                }
            }
            List<Integer> idxs = new ArrayList<>(toolAcc.keySet());
            idxs.sort(Integer::compareTo);
            for (int i : idxs) {
                result.toolCalls.add(toolAcc.get(i));
            }
            return result;
        }
        finally {
            activeConn.compareAndSet(conn, null);
        }
    }

    private void handleDelta(JsonObject obj, StreamResult result, Map<Integer, ToolCall> acc,
        Listener listener) {
        if (!obj.has("choices")) {
            return;
        }
        JsonArray choices = obj.getAsJsonArray("choices");
        if (choices == null || choices.isEmpty() || !choices.get(0).isJsonObject()) {
            return;
        }
        JsonObject choice = choices.get(0).getAsJsonObject();
        if (choice.has("finish_reason") && !choice.get("finish_reason").isJsonNull()) {
            result.finishReason = choice.get("finish_reason").getAsString();
        }
        if (!choice.has("delta") || choice.get("delta").isJsonNull()) {
            return;
        }
        JsonObject delta = choice.getAsJsonObject("delta");

        if (delta.has("content") && delta.get("content").isJsonPrimitive()) {
            String c = delta.get("content").getAsString();
            if (c != null && !c.isEmpty()) {
                listener.onChunk(c);
            }
        }
        if (delta.has("reasoning_content") && delta.get("reasoning_content").isJsonPrimitive()) {
            String rc = delta.get("reasoning_content").getAsString();
            if (rc != null && !rc.isBlank()) {
                listener.onStatus("Thinking: " + oneLine(rc, 70));
            }
        }
        if (delta.has("tool_calls") && delta.get("tool_calls").isJsonArray()) {
            for (JsonElement te : delta.getAsJsonArray("tool_calls")) {
                if (!te.isJsonObject()) {
                    continue;
                }
                JsonObject to = te.getAsJsonObject();
                int index = to.has("index") ? to.get("index").getAsInt() : 0;
                ToolCall tc = acc.computeIfAbsent(index, k -> new ToolCall());
                if (to.has("id") && to.get("id").isJsonPrimitive()) {
                    tc.id = to.get("id").getAsString();
                }
                if (to.has("function") && to.get("function").isJsonObject()) {
                    JsonObject fn = to.getAsJsonObject("function");
                    if (fn.has("name") && fn.get("name").isJsonPrimitive()) {
                        String n = fn.get("name").getAsString();
                        if (n != null && !n.isEmpty()) {
                            tc.name = n;
                        }
                    }
                    if (fn.has("arguments") && fn.get("arguments").isJsonPrimitive()) {
                        tc.arguments.append(fn.get("arguments").getAsString());
                    }
                }
            }
        }
    }

    // ==================================================================
    // Tool execution against GhidraMCP HTTP endpoints
    // ==================================================================

    private String executeTool(String mcpUrl, List<ToolSpec> tools, ToolCall tc) {
        ToolSpec spec = null;
        for (ToolSpec t : tools) {
            if (t.name.equals(tc.name)) {
                spec = t;
                break;
            }
        }
        if (spec == null) {
            return "{\"error\":\"unknown tool " + tc.name + "\"}";
        }
        Map<String, Object> args = parseArgs(tc.arguments.toString());
        return callEndpoint(mcpUrl, spec, args);
    }

    private static String callEndpoint(String mcpUrl, ToolSpec spec, Map<String, Object> args) {
        String base = mcpUrl.replaceAll("/$", "");
        boolean post = "POST".equalsIgnoreCase(spec.method);
        List<String> qparts = new ArrayList<>();
        JsonObject body = new JsonObject();
        for (ParamSpec p : spec.params) {
            Object v = args.get(p.name);
            if (v == null) {
                continue;
            }
            boolean bodyParam = post && "body".equalsIgnoreCase(p.source);
            if (bodyParam) {
                putValue(body, p, v);
            }
            else {
                qparts.add(URLEncoder.encode(p.name, StandardCharsets.UTF_8) + "="
                    + URLEncoder.encode(scalarString(v), StandardCharsets.UTF_8));
            }
        }
        String url = base + spec.path;
        if (!qparts.isEmpty()) {
            url += "?" + String.join("&", qparts);
        }

        try {
            HttpURLConnection conn = open(url, 4000, 300000);
            conn.setRequestMethod(spec.method);
            if (post) {
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                conn.setDoOutput(true);
                byte[] b = body.toString().getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(b);
                }
            }
            int code = conn.getResponseCode();
            String resp = readAll(code >= 400 ? conn.getErrorStream() : conn.getInputStream());
            return truncate(resp, MAX_TOOL_RESULT_CHARS);
        }
        catch (Exception ex) {
            return "{\"error\":\"" + escapeJson(ex.getMessage()) + "\"}";
        }
    }

    private static void putValue(JsonObject body, ParamSpec p, Object v) {
        if (v == null) {
            return;
        }
        if ("json".equalsIgnoreCase(p.type) && (v instanceof Map || v instanceof List)) {
            body.addProperty(p.name, GSON.toJson(v));
        }
        else if (v instanceof Map || v instanceof List) {
            body.add(p.name, GSON.toJsonTree(v));
        }
        else if (v instanceof Number n) {
            body.addProperty(p.name, n);
        }
        else if (v instanceof Boolean b) {
            body.addProperty(p.name, b);
        }
        else {
            body.addProperty(p.name, String.valueOf(v));
        }
    }

    private static String scalarString(Object v) {
        if (v == null) {
            return "";
        }
        if (v instanceof Map || v instanceof List) {
            return GSON.toJson(v);
        }
        return String.valueOf(v);
    }

    private static Map<String, Object> parseArgs(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            JsonElement el = JsonParser.parseString(json);
            if (el.isJsonObject()) {
                Map<String, Object> out = new LinkedHashMap<>();
                for (Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                    out.put(e.getKey(), toPlain(e.getValue()));
                }
                return out;
            }
        }
        catch (Exception ignored) {
            // fall through
        }
        return Map.of();
    }

    private static Object toPlain(JsonElement e) {
        if (e == null || e.isJsonNull()) {
            return null;
        }
        if (e.isJsonPrimitive()) {
            JsonPrimitive p = e.getAsJsonPrimitive();
            if (p.isBoolean()) {
                return p.getAsBoolean();
            }
            if (p.isNumber()) {
                return p.getAsNumber();
            }
            return p.getAsString();
        }
        if (e.isJsonArray()) {
            List<Object> l = new ArrayList<>();
            for (JsonElement x : e.getAsJsonArray()) {
                l.add(toPlain(x));
            }
            return l;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> en : e.getAsJsonObject().entrySet()) {
            m.put(en.getKey(), toPlain(en.getValue()));
        }
        return m;
    }

    // ==================================================================
    // Schema discovery → OpenAI function tools
    // ==================================================================

    private static List<ToolSpec> fetchTools(String mcpUrl, Listener listener) {
        String url = mcpUrl.replaceAll("/$", "") + "/mcp/schema";
        try {
            HttpURLConnection conn = open(url, 4000, 15000);
            conn.setRequestMethod("GET");
            int code = conn.getResponseCode();
            String body = readAll(code >= 400 ? conn.getErrorStream() : conn.getInputStream());
            if (code != 200) {
                listener.onStatus("MCP /mcp/schema HTTP " + code);
                return List.of();
            }
            JsonElement el = JsonParser.parseString(body);
            if (!el.isJsonObject() || !el.getAsJsonObject().has("tools")) {
                listener.onStatus("MCP /mcp/schema returned no tools");
                return List.of();
            }
            JsonArray arr = el.getAsJsonObject().getAsJsonArray("tools");
            List<ToolSpec> out = new ArrayList<>();
            for (JsonElement e : arr) {
                if (!e.isJsonObject()) {
                    continue;
                }
                JsonObject o = e.getAsJsonObject();
                String path = str(o, "path");
                if (path == null || path.isBlank()) {
                    continue;
                }
                String method = str(o, "method");
                List<ParamSpec> params = new ArrayList<>();
                if (o.has("params") && o.get("params").isJsonArray()) {
                    for (JsonElement pe : o.getAsJsonArray("params")) {
                        if (!pe.isJsonObject()) {
                            continue;
                        }
                        JsonObject po = pe.getAsJsonObject();
                        params.add(new ParamSpec(
                            str(po, "name"),
                            str(po, "type"),
                            str(po, "source"),
                            po.has("required") && po.get("required").getAsBoolean(),
                            str(po, "description")));
                    }
                }
                out.add(new ToolSpec(toolNameFromPath(path), path,
                    method == null ? "GET" : method, str(o, "description"), params));
            }
            listener.onStatus("Loaded " + out.size() + " GhidraMCP tools");
            return out;
        }
        catch (Exception ex) {
            listener.onStatus("MCP /mcp/schema unreachable: " + oneLine(ex.getMessage(), 60));
            return List.of();
        }
    }

    static JsonArray buildToolsJson(List<ToolSpec> tools) {
        JsonArray arr = new JsonArray();
        for (ToolSpec t : tools) {
            JsonObject fn = new JsonObject();
            fn.addProperty("name", t.name);
            fn.addProperty("description", t.description == null ? "" : t.description);
            JsonObject params = new JsonObject();
            params.addProperty("type", "object");
            JsonObject props = new JsonObject();
            JsonArray required = new JsonArray();
            for (ParamSpec p : t.params) {
                if (p.name == null || p.name.isBlank()) {
                    continue;
                }
                JsonObject prop = new JsonObject();
                prop.addProperty("type", schemaType(p.type));
                if (p.description != null && !p.description.isBlank()) {
                    prop.addProperty("description", p.description);
                }
                props.add(p.name, prop);
                if (p.required) {
                    required.add(p.name);
                }
            }
            params.add("properties", props);
            params.add("required", required);
            fn.add("parameters", params);
            JsonObject tool = new JsonObject();
            tool.addProperty("type", "function");
            tool.add("function", fn);
            arr.add(tool);
        }
        return arr;
    }

    static String schemaType(String t) {
        if (t == null) {
            return "string";
        }
        switch (t) {
            case "integer":
            case "boolean":
            case "number":
            case "object":
            case "array":
                return t;
            default:
                return "string";
        }
    }

    static String toolNameFromPath(String path) {
        String p = path;
        while (p.startsWith("/")) {
            p = p.substring(1);
        }
        String name = p.replace('/', '_');
        if (name.isEmpty()) {
            name = "tool";
        }
        // OpenAI/DeepSeek function names are capped at 64 chars.
        if (name.length() > 64) {
            String hash = Integer.toHexString(name.hashCode());
            name = name.substring(0, 64 - hash.length() - 1) + "_" + hash;
        }
        return name;
    }

    // ==================================================================
    // Small helpers
    // ==================================================================

    private static JsonObject msg(String role, String content) {
        JsonObject o = new JsonObject();
        o.addProperty("role", role);
        if (content != null) {
            o.addProperty("content", content);
        }
        return o;
    }

    private static HttpURLConnection open(String url, int connectMs, int readMs) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
        conn.setConnectTimeout(connectMs);
        conn.setReadTimeout(readMs);
        return conn;
    }

    private static String readAll(InputStream in) {
        if (in == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r =
            new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            char[] buf = new char[8192];
            int n;
            while ((n = r.read(buf)) > 0) {
                sb.append(buf, 0, n);
            }
        }
        catch (Exception ex) {
            sb.append(" (read error: ").append(ex.getMessage()).append(')');
        }
        return sb.toString();
    }

    private static String str(JsonObject o, String key) {
        if (o.has(key) && o.get(key).isJsonPrimitive()) {
            return o.get(key).getAsString();
        }
        return null;
    }

    private static String oneLine(String s, int max) {
        if (s == null) {
            return "";
        }
        String t = s.replace('\n', ' ').trim();
        return t.length() <= max ? t : t.substring(0, max - 1) + "…";
    }

    private static String truncate(String s, int n) {
        if (s == null) {
            return "";
        }
        return s.length() <= n ? s : s.substring(0, n) + "\n…[truncated]";
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    // ==================================================================
    // Records
    // ==================================================================

    public record ToolSpec(String name, String path, String method, String description,
        List<ParamSpec> params) {
    }

    public record ParamSpec(String name, String type, String source, boolean required,
        String description) {
    }
}
