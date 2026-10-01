package lab.ghidra.assist;

import java.util.ArrayList;
import java.util.List;

/**
 * Tiny markdown → HTML for the chat transcript panel.
 */
public final class MarkdownLite {

    private MarkdownLite() {
    }

    public static String toHtmlDocument(String markdown) {
        return toHtmlDocument(markdown, preferDark());
    }

    public static String toHtmlDocument(String markdown, boolean dark) {
        String body = toHtmlBody(markdown == null ? "" : markdown);
        String css = dark ? darkCss() : lightCss();
        return "<html><head><style>" + css + "</style></head><body>" + body + "</body></html>";
    }

    /** Prefer dark when Swing background is dark (Ghidra Flat Dark, etc.). */
    public static boolean preferDark() {
        try {
            java.awt.Color bg = javax.swing.UIManager.getColor("Panel.background");
            if (bg == null) {
                bg = javax.swing.UIManager.getColor("window");
            }
            if (bg == null) {
                return false;
            }
            // perceived luminance
            double y = 0.2126 * bg.getRed() + 0.7152 * bg.getGreen() + 0.0722 * bg.getBlue();
            return y < 140;
        }
        catch (Throwable t) {
            return false;
        }
    }

    private static String lightCss() {
        return "body{font-family:SansSerif;font-size:12pt;margin:10px;color:#1a1a1a;background:#ffffff;}" +
            "h2{font-size:14pt;margin:14px 0 6px 0;}" +
            "h3{font-size:13pt;margin:12px 0 4px 0;}" +
            "pre,code{font-family:Monospaced;}" +
            "pre{background:#f4f4f4;padding:10px;border:1px solid #ddd;color:#111;font-size:11pt;}" +
            "code{background:#eef1f6;padding:1px 4px;color:#b3261e;font-size:11pt;}" +
            "a{color:#0b57d0;text-decoration:none;}" +
            "table{border:1px solid #ccc;margin:8px 0;}" +
            "th{background:#eceff4;color:#111;font-family:Monospaced;font-size:11pt;padding:4px 8px;}" +
            "td{color:#1a1a1a;font-family:Monospaced;font-size:11pt;padding:3px 8px;border-top:1px solid #ddd;}" +
            ".you{color:#0b57d0;font-weight:bold;margin-top:14px;}" +
            ".asst{color:#1b5e20;font-weight:bold;margin-top:10px;}" +
            ".sys{color:#666;font-style:italic;margin-top:8px;}";
    }

    private static String darkCss() {
        return "body{font-family:SansSerif;font-size:12pt;margin:10px;color:#e6e6e6;background:#2b2b2b;}" +
            "h2{font-size:14pt;margin:14px 0 6px 0;color:#f0f0f0;}" +
            "h3{font-size:13pt;margin:12px 0 4px 0;color:#f0f0f0;}" +
            "pre,code{font-family:Monospaced;}" +
            "pre{background:#1e1e1e;padding:10px;border:1px solid #444;color:#dcdcdc;font-size:11pt;}" +
            "code{background:#3a3a3a;padding:1px 4px;color:#ffd580;font-size:11pt;}" +
            "a{color:#7cb7ff;text-decoration:none;}" +
            "table{border:1px solid #555;margin:8px 0;}" +
            "th{background:#3a3a3a;color:#f0f0f0;font-family:Monospaced;font-size:11pt;padding:4px 8px;}" +
            "td{color:#e6e6e6;font-family:Monospaced;font-size:11pt;padding:3px 8px;border-top:1px solid #444;}" +
            ".you{color:#7cb7ff;font-weight:bold;margin-top:14px;}" +
            ".asst{color:#9ccc65;font-weight:bold;margin-top:10px;}" +
            ".sys{color:#9e9e9e;font-style:italic;margin-top:8px;}";
    }

    public static String toHtmlBody(String markdown) {
        String[] lines = markdown.replace("\r\n", "\n").split("\n", -1);
        StringBuilder out = new StringBuilder();
        boolean inCode = false;
        StringBuilder code = new StringBuilder();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line.startsWith("```")) {
                if (inCode) {
                    out.append("<pre>").append(linkifyAddresses(escape(code.toString()))).append("</pre>");
                    code.setLength(0);
                    inCode = false;
                }
                else {
                    inCode = true;
                }
                continue;
            }
            if (inCode) {
                if (code.length() > 0) {
                    code.append('\n');
                }
                code.append(line);
                continue;
            }

            // GFM table block: consecutive lines starting with '|'
            if (line.trim().startsWith("|")) {
                List<String> tbl = new ArrayList<>();
                tbl.add(line.trim());
                while (i + 1 < lines.length && lines[i + 1].trim().startsWith("|")) {
                    i++;
                    tbl.add(lines[i].trim());
                }
                out.append(renderTable(tbl));
                continue;
            }

            if (line.startsWith("### ")) {
                out.append("<h3>").append(inline(line.substring(4))).append("</h3>");
            }
            else if (line.startsWith("## ")) {
                out.append("<h2>").append(inline(line.substring(3))).append("</h2>");
            }
            else if (line.startsWith("# ")) {
                out.append("<h2>").append(inline(line.substring(2))).append("</h2>");
            }
            else if (line.equals("---")) {
                out.append("<hr/>");
            }
            else if (line.startsWith("You:")) {
                out.append("<div class='you'>You</div>");
                String rest = line.substring(4).trim();
                if (!rest.isEmpty()) {
                    out.append("<p>").append(inline(rest)).append("</p>");
                }
            }
            else if (line.startsWith("Assistant:")) {
                out.append("<div class='asst'>Assistant</div>");
                String rest = line.substring(10).trim();
                if (!rest.isEmpty()) {
                    out.append("<p>").append(inline(rest)).append("</p>");
                }
            }
            else if (line.startsWith("System:")) {
                out.append("<div class='sys'>").append(inline(line.substring(7).trim())).append("</div>");
            }
            else if (line.isBlank()) {
                out.append("<br/>");
            }
            else if (line.startsWith("- ") || line.startsWith("* ")) {
                out.append("<div>• ").append(inline(line.substring(2))).append("</div>");
            }
            else {
                out.append("<p>").append(inline(line)).append("</p>");
            }
        }
        if (inCode) {
            out.append("<pre>").append(linkifyAddresses(escape(code.toString()))).append("</pre>");
        }
        return out.toString();
    }

    private static String renderTable(List<String> rows) {
        if (rows.isEmpty()) {
            return "";
        }
        String[] headers = splitRow(rows.get(0));
        StringBuilder sb = new StringBuilder();
        sb.append("<table border='1' cellspacing='0' cellpadding='4'>");
        sb.append("<tr>");
        for (String h : headers) {
            sb.append("<th>").append(inline(h.trim())).append("</th>");
        }
        sb.append("</tr>");
        for (int r = 1; r < rows.size(); r++) {
            if (isSeparator(rows.get(r))) {
                continue;
            }
            String[] cells = splitRow(rows.get(r));
            sb.append("<tr>");
            for (int c = 0; c < headers.length; c++) {
                String v = c < cells.length ? cells[c].trim() : "";
                sb.append("<td>").append(inline(v)).append("</td>");
            }
            sb.append("</tr>");
        }
        sb.append("</table>");
        return sb.toString();
    }

    private static boolean isSeparator(String row) {
        String stripped = row.replace("|", "").replace(":", "").replace("-", "").replace(" ", "");
        return stripped.isEmpty() && row.contains("-");
    }

    private static String[] splitRow(String row) {
        String s = row.trim();
        if (s.startsWith("|")) {
            s = s.substring(1);
        }
        if (s.endsWith("|")) {
            s = s.substring(0, s.length() - 1);
        }
        return s.split("\\|", -1);
    }

    private static String inline(String s) {
        String e = escape(s);
        e = e.replaceAll("\\*\\*([^*]+)\\*\\*", "<b>$1</b>");
        e = e.replaceAll("`([^`]+)`", "<code>$1</code>");
        e = linkifyAddresses(e);
        return e;
    }

    static String linkifyAddresses(String htmlEscaped) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "(?<![\\w/])(0x[0-9a-fA-F]{4,}|LAB_[0-9a-fA-F]+|FUN_[0-9a-fA-F]+|DAT_[0-9a-fA-F]+)(?![\\w])");
        java.util.regex.Matcher m = p.matcher(htmlEscaped);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String tok = m.group(1);
            String addr = tok;
            if (tok.startsWith("LAB_") || tok.startsWith("FUN_") || tok.startsWith("DAT_")) {
                addr = "0x" + tok.substring(4);
            }
            String repl = "<a href=\"ghidra:" + addr + "\">" + tok + "</a>";
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(repl));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;");
    }
}
