package lab.ghidra.assist;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * Unit tests for DeepSeek backend helpers (no network, no Ghidra).
 */
public class DeepSeekRunnerTest {

    @Test
    public void toolNameFromPath() {
        assertEquals("decompile_function",
            DeepSeekRunner.toolNameFromPath("/decompile_function"));
        assertEquals("debugger_break_at_symbol",
            DeepSeekRunner.toolNameFromPath("/debugger/break_at_symbol"));
        assertEquals("tool", DeepSeekRunner.toolNameFromPath("/"));
    }

    @Test
    public void toolNameCappedAt64() {
        StringBuilder sb = new StringBuilder("/");
        for (int i = 0; i < 20; i++) {
            sb.append("a_very_long_segment_");
        }
        String name = DeepSeekRunner.toolNameFromPath(sb.toString());
        assertTrue(name.length() <= 64, "got length " + name.length());
        assertTrue(name.matches("[a-zA-Z0-9_-]+"), name);
    }

    @Test
    public void schemaTypeMaps() {
        assertEquals("integer", DeepSeekRunner.schemaType("integer"));
        assertEquals("boolean", DeepSeekRunner.schemaType("boolean"));
        assertEquals("string", DeepSeekRunner.schemaType("json"));
        assertEquals("string", DeepSeekRunner.schemaType(null));
    }

    @Test
    public void buildToolsJsonProducesFunctions() {
        List<DeepSeekRunner.ParamSpec> params = List.of(
            new DeepSeekRunner.ParamSpec("address", "string", "query", true, "addr"));
        DeepSeekRunner.ToolSpec spec = new DeepSeekRunner.ToolSpec(
            "decompile_function", "/decompile_function", "GET", "Decompile a function", params);

        JsonArray arr = DeepSeekRunner.buildToolsJson(List.of(spec));
        assertEquals(1, arr.size());
        assertEquals("function", arr.get(0).getAsJsonObject().get("type").getAsString());
        JsonObject fn = arr.get(0).getAsJsonObject().getAsJsonObject("function");
        assertEquals("decompile_function", fn.get("name").getAsString());
        assertEquals("object", fn.getAsJsonObject("parameters").get("type").getAsString());
        assertTrue(fn.getAsJsonObject("parameters").getAsJsonArray("required").size() == 1);
    }
}
