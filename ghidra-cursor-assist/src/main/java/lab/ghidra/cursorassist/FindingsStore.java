package lab.ghidra.cursorassist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;

import ghidra.program.model.listing.Program;

/**
 * Persist per-program findings markdown under the agent workspace.
 */
public final class FindingsStore {

    private FindingsStore() {
    }

    public static Path findingsPath(String workspace, Program program) {
        String safe = sanitize(program != null ? program.getName() : "unknown");
        return Paths.get(workspace, "findings", safe, "findings.md");
    }

    public static String load(String workspace, Program program) {
        Path p = findingsPath(workspace, program);
        if (!Files.isRegularFile(p)) {
            return "";
        }
        try {
            return Files.readString(p, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    public static void append(String workspace, Program program, String markdownChunk) throws IOException {
        if (markdownChunk == null || markdownChunk.isBlank()) {
            return;
        }
        Path p = findingsPath(workspace, program);
        Files.createDirectories(p.getParent());
        String header = Files.isRegularFile(p) ? "\n\n---\n\n" : "# Findings: " +
            (program != null ? program.getName() : "unknown") + "\n\n";
        String stamped = header + "<!-- " + Instant.now() + " -->\n" + markdownChunk.trim() + "\n";
        Files.writeString(p, stamped, StandardCharsets.UTF_8,
            java.nio.file.StandardOpenOption.CREATE,
            java.nio.file.StandardOpenOption.APPEND);
    }

    public static void saveFull(String workspace, Program program, String fullMarkdown) throws IOException {
        Path p = findingsPath(workspace, program);
        Files.createDirectories(p.getParent());
        String body = "# Findings: " + (program != null ? program.getName() : "unknown")
            + "\n\n<!-- saved " + Instant.now() + " -->\n\n"
            + (fullMarkdown == null ? "" : fullMarkdown.trim()) + "\n";
        Files.writeString(p, body, StandardCharsets.UTF_8);
    }

    private static String sanitize(String name) {
        return name.replaceAll("[^A-Za-z0-9._-]+", "_");
    }
}
