package lab.ghidra.assist;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Minimal macOS Keychain access for the DeepSeek API key, via the {@code security}
 * command-line tool. Falls back to empty string on any failure so the panel can
 * degrade to the Tool Options field or {@code DEEPSEEK_API_KEY} env var.
 */
public final class KeychainStore {

    private static final String SERVICE = "ghidra-assist";
    private static final String ACCOUNT = "deepseek-api-key";

    private KeychainStore() {
    }

    /** Read the stored key, or {@code ""} when absent/unavailable. */
    public static String get() {
        try {
            Process p = new ProcessBuilder(
                "security", "find-generic-password",
                "-s", SERVICE, "-a", ACCOUNT, "-w")
                .redirectErrorStream(true)
                .start();
            String out = readAll(p.getInputStream());
            int code = p.waitFor();
            return code == 0 ? out.trim() : "";
        }
        catch (Exception e) {
            return "";
        }
    }

    /** Store (replace) the key in the login keychain. Returns success. */
    public static boolean store(String secret) {
        if (secret == null || secret.isEmpty()) {
            return false;
        }
        try {
            new ProcessBuilder(
                "security", "delete-generic-password",
                "-s", SERVICE, "-a", ACCOUNT)
                .redirectErrorStream(true)
                .start()
                .waitFor();
            Process p = new ProcessBuilder(
                "security", "add-generic-password",
                "-s", SERVICE, "-a", ACCOUNT,
                "-w", secret, "-U")
                .redirectErrorStream(true)
                .start();
            readAll(p.getInputStream());
            return p.waitFor() == 0;
        }
        catch (Exception e) {
            return false;
        }
    }

    /** Remove the stored key. Returns success. */
    public static boolean clear() {
        try {
            return new ProcessBuilder(
                "security", "delete-generic-password",
                "-s", SERVICE, "-a", ACCOUNT)
                .redirectErrorStream(true)
                .start()
                .waitFor() == 0;
        }
        catch (Exception e) {
            return false;
        }
    }

    private static String readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        return bos.toString(StandardCharsets.UTF_8);
    }
}
