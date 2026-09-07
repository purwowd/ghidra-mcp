package lab.ghidra.cursorassist;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Minimal HTTP client for GhidraMCP endpoints from the Assist panel.
 */
public final class McpHttpClient {

    private McpHttpClient() {
    }

    public static final class Result {
        public final boolean ok;
        public final int code;
        public final String body;

        public Result(boolean ok, int code, String body) {
            this.ok = ok;
            this.code = code;
            this.body = body == null ? "" : body;
        }
    }

    public static Result get(String baseUrl, String path) {
        return request(baseUrl, path, "GET", null);
    }

    public static Result postJson(String baseUrl, String path, String jsonBody) {
        return request(baseUrl, path, "POST", jsonBody);
    }

    public static String jsonObject(Map<String, String> fields) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escape(e.getKey())).append("\":\"");
            sb.append(escape(e.getValue() == null ? "" : e.getValue())).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    private static Result request(String baseUrl, String path, String method, String body) {
        String url = (baseUrl == null || baseUrl.isBlank() ? "http://127.0.0.1:8089" : baseUrl)
            .replaceAll("/$", "") + path;
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(2500);
            conn.setReadTimeout(8000);
            conn.setRequestMethod(method);
            if (body != null) {
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(bytes);
                }
            }
            int code = conn.getResponseCode();
            String resp;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(
                code >= 400 ? conn.getErrorStream() : conn.getInputStream(),
                StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line);
                }
                resp = sb.toString();
            }
            boolean ok = code >= 200 && code < 300 && !resp.contains("\"error\"");
            return new Result(ok, code, resp);
        }
        catch (Exception ex) {
            return new Result(false, -1, ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
