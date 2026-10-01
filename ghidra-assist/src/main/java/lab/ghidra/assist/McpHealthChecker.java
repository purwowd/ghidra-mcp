package lab.ghidra.assist;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * Quick health probe for GhidraMCP HTTP server.
 */
public final class McpHealthChecker {

    private McpHealthChecker() {
    }

    public static final class Result {
        public final boolean ok;
        public final String detail;

        public Result(boolean ok, String detail) {
            this.ok = ok;
            this.detail = detail;
        }
    }

    public static Result check(String baseUrl) {
        String url = (baseUrl == null || baseUrl.isBlank())
            ? "http://127.0.0.1:8089"
            : baseUrl.replaceAll("/$", "");
        try {
            HttpURLConnection conn =
                (HttpURLConnection) URI.create(url + "/mcp/health").toURL().openConnection();
            conn.setConnectTimeout(1500);
            conn.setReadTimeout(2000);
            conn.setRequestMethod("GET");
            int code = conn.getResponseCode();
            String body;
            try (BufferedReader r = new BufferedReader(
                new InputStreamReader(
                    code >= 400 ? conn.getErrorStream() : conn.getInputStream(),
                    StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line);
                }
                body = sb.toString();
            }
            if (code == 200 && body.contains("\"status\"")) {
                return new Result(true, "MCP healthy @ " + url + " — " + truncate(body, 120));
            }
            return new Result(false, "HTTP " + code + " from " + url + " — " + truncate(body, 120));
        }
        catch (Exception ex) {
            return new Result(false,
                "MCP down @ " + url + " (" + ex.getClass().getSimpleName() + ": " + ex.getMessage() +
                    "). Open CodeBrowser + enable GhidraMCP.");
        }
    }

    private static String truncate(String s, int n) {
        if (s == null) {
            return "";
        }
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }
}
