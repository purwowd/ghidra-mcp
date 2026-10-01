package lab.ghidra.assist;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for the markdown → HTML renderer.
 */
public class MarkdownLiteTest {

    @Test
    public void rendersGfmTable() {
        String html = MarkdownLite.toHtmlBody("| A | B |\n|---|---|\n| 1 | 2 |");
        assertTrue(html.contains("<table"), html);
        assertTrue(html.contains("<th>A</th>"), html);
        assertTrue(html.contains("<th>B</th>"), html);
        assertTrue(html.contains("<td>1</td>"), html);
        assertFalse(html.contains("| A |"), html);
    }

    @Test
    public void rendersHeaders() {
        assertEquals("<h2>Title</h2>", MarkdownLite.toHtmlBody("## Title"));
        assertEquals("<h3>Sub</h3>", MarkdownLite.toHtmlBody("### Sub"));
    }

    @Test
    public void rendersRoleLabels() {
        String html = MarkdownLite.toHtmlBody("You: hi\nAssistant: hello");
        assertTrue(html.contains("class='you'"), html);
        assertTrue(html.contains("class='asst'"), html);
    }

    @Test
    public void linkifiesAddresses() {
        String s = MarkdownLite.linkifyAddresses("call 0x401000 then FUN_0044ae0c");
        assertTrue(s.contains("href=\"ghidra:0x401000\""), s);
        assertTrue(s.contains("href=\"ghidra:0x0044ae0c\""), s);
    }
}
