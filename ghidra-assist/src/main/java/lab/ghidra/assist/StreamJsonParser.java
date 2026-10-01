package lab.ghidra.assist;

/**
 * Classifies the Cursor backend --output-format stream-json lines into UI events.
 */
public final class StreamJsonParser {

    public enum Kind {
        /** Visible assistant text delta (prefer these). */
        ASSISTANT_DELTA,
        /** Full assistant message snapshot (use only if no deltas seen). */
        ASSISTANT_SNAPSHOT,
        /** Tool / MCP progress for status bar. */
        TOOL_STATUS,
        /** Model thinking / planning — status only, not transcript. */
        THINKING_STATUS,
        /** Recognized JSON, ignore for transcript. */
        IGNORE,
        /** Non-JSON line (fallback plain). */
        PLAIN
    }

    public static final class Event {
        public final Kind kind;
        public final String text;

        public Event(Kind kind, String text) {
            this.kind = kind;
            this.text = text == null ? "" : text;
        }
    }

    private StreamJsonParser() {
    }

    public static Event parse(String line) {
        if (line == null) {
            return new Event(Kind.IGNORE, "");
        }
        String trimmed = line.trim();
        if (trimmed.isEmpty()) {
            return new Event(Kind.IGNORE, "");
        }
        if (!trimmed.startsWith("{")) {
            return new Event(Kind.PLAIN, trimmed);
        }

        String type = extractJsonStringField(trimmed, "type");
        if (type != null) {
            type = type.toLowerCase();
            if (type.contains("thinking") || type.equals("reasoning") ||
                type.equals("plan") || trimmed.contains("\"thinking\"")) {
                String tip = firstNonNull(
                    extractJsonStringField(trimmed, "text"),
                    extractJsonStringField(trimmed, "delta"),
                    extractJsonStringField(trimmed, "thinking"));
                if (tip != null && tip.length() > 80) {
                    tip = tip.substring(0, 77) + "…";
                }
                String label = tip != null && !tip.isBlank()
                    ? "Thinking: " + tip.replace('\n', ' ')
                    : "Thinking";
                return new Event(Kind.THINKING_STATUS, label);
            }
            if (type.equals("system") || type.equals("user") || type.equals("ping")) {
                return new Event(Kind.IGNORE, "");
            }
        }

        // Tool call progress
        if (type != null && (type.contains("tool") || type.equals("mcp") ||
            trimmed.contains("\"tool_call\"") || trimmed.contains("\"toolCall\"") ||
            trimmed.contains("\"name\":\"mcp") || trimmed.contains("\"mcp__"))) {
            String name = firstNonNull(
                extractJsonStringField(trimmed, "name"),
                extractJsonStringField(trimmed, "tool"),
                extractJsonStringField(trimmed, "toolName"));
            if (name == null) {
                name = "tool";
            }
            // Strip mcp server prefix noise
            if (name.startsWith("mcp_")) {
                int i = name.indexOf('_', 4);
                if (i > 0 && i + 1 < name.length()) {
                    name = name.substring(i + 1);
                }
            }
            String status = type != null && type.contains("result") ? "done " + name : "MCP: " + name;
            return new Event(Kind.TOOL_STATUS, status);
        }

        // Streaming deltas (best)
        if (trimmed.contains("\"delta\"") || "assistant_delta".equals(type) ||
            (type != null && type.contains("delta"))) {
            String delta = extractJsonStringField(trimmed, "delta");
            if (delta == null) {
                delta = extractJsonStringField(trimmed, "text");
            }
            if (delta != null && !delta.isEmpty()) {
                return new Event(Kind.ASSISTANT_DELTA, unescape(delta));
            }
            return new Event(Kind.IGNORE, "");
        }

        // Full assistant message — only as snapshot fallback
        if ((type != null && type.contains("assistant")) ||
            trimmed.contains("\"role\":\"assistant\"") ||
            trimmed.contains("\"type\":\"assistant\"")) {
            // Skip if this looks like thinking content
            if (trimmed.contains("\"thinking\"") && !trimmed.contains("\"text\"")) {
                return new Event(Kind.IGNORE, "");
            }
            StringBuilder sb = new StringBuilder();
            int idx = 0;
            int guards = 0;
            while (guards++ < 32) {
                int key = indexOfField(trimmed, "text", idx);
                if (key < 0) {
                    break;
                }
                // Skip thinking-adjacent text keys when subtype says thinking
                int windowStart = Math.max(0, key - 80);
                String around = trimmed.substring(windowStart, Math.min(trimmed.length(), key + 20));
                if (around.contains("thinking")) {
                    idx = key + 1;
                    continue;
                }
                String val = readJsonStringValue(trimmed, key);
                if (val != null) {
                    sb.append(unescape(val));
                    idx = key + 1;
                }
                else {
                    break;
                }
            }
            if (sb.length() > 0) {
                return new Event(Kind.ASSISTANT_SNAPSHOT, sb.toString());
            }
            return new Event(Kind.IGNORE, "");
        }

        // Generic text field without dumping tool payloads
        if (trimmed.contains("\"text\"") && !trimmed.contains("\"tool\"")) {
            String text = extractJsonStringField(trimmed, "text");
            if (text != null && !text.isEmpty() && text.length() < 8000) {
                return new Event(Kind.ASSISTANT_DELTA, unescape(text));
            }
        }

        return new Event(Kind.IGNORE, "");
    }

    @SafeVarargs
    private static String firstNonNull(String... vals) {
        for (String v : vals) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    private static String extractJsonStringField(String json, String field) {
        int key = indexOfField(json, field, 0);
        if (key < 0) {
            return null;
        }
        return readJsonStringValue(json, key);
    }

    private static int indexOfField(String json, String field, int from) {
        String a = "\"" + field + "\":";
        String b = "\"" + field + "\" :";
        int i = json.indexOf(a, from);
        int j = json.indexOf(b, from);
        if (i < 0) {
            return j;
        }
        if (j < 0) {
            return i;
        }
        return Math.min(i, j);
    }

    private static String readJsonStringValue(String json, int fieldIndex) {
        int colon = json.indexOf(':', fieldIndex);
        if (colon < 0) {
            return null;
        }
        int i = colon + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
            i++;
        }
        if (i >= json.length() || json.charAt(i) != '"') {
            return null;
        }
        i++;
        StringBuilder sb = new StringBuilder();
        while (i < json.length()) {
            char c = json.charAt(i++);
            if (c == '\\' && i < json.length()) {
                sb.append('\\').append(json.charAt(i++));
                continue;
            }
            if (c == '"') {
                return sb.toString();
            }
            sb.append(c);
        }
        return null;
    }

    private static String unescape(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case 'n':
                        out.append('\n');
                        break;
                    case 't':
                        out.append('\t');
                        break;
                    case 'r':
                        out.append('\r');
                        break;
                    case '"':
                        out.append('"');
                        break;
                    case '\\':
                        out.append('\\');
                        break;
                    case 'u':
                        if (i + 4 < s.length()) {
                            try {
                                int cp = Integer.parseInt(s.substring(i + 1, i + 5), 16);
                                out.append((char) cp);
                                i += 4;
                            }
                            catch (NumberFormatException ex) {
                                out.append('u');
                            }
                        }
                        else {
                            out.append('u');
                        }
                        break;
                    default:
                        out.append(n);
                        break;
                }
            }
            else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
