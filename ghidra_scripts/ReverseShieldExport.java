// Bounded static export. This script never executes or emulates the input.
// @category ReverseShield
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitorAdapter;

public class ReverseShieldExport extends HeadlessScript {
    private static final int FUNCTION_LIMIT = 1000, DECOMPILE_LIMIT = 40;
    private static final int CFG_LIMIT = 100, CFG_EDGE_LIMIT = 400, CALL_LIMIT = 10000;
    private static final int SYMBOL_LIMIT = 10000, STRING_LIMIT = 10000;
    private static final int TEXT_LIMIT = 64000, NAME_LIMIT = 1024;
    private final JsonObject coverage = new JsonObject();
    private final JsonArray limitations = new JsonArray();

    private String addr(Address address) {
        return address.isMemoryAddress() ? "0x" + address.toString() : address.toString();
    }

    private String bounded(String value, int limit) {
        return value.length() > limit ? value.substring(0, limit) : value;
    }

    private int priority(Function f) {
        String n = f.getName();
        if (n.equals("main") || n.equals("_main")) return 0;
        if (f.isExternal()) return 5;
        if (f.isThunk()) return 4;
        if (n.startsWith("_") || n.equals("frame_dummy") || n.contains("tm_clones")) return 3;
        return n.startsWith("FUN_") ? 2 : 1;
    }

    private JsonObject functionRecord(Function f) {
        JsonObject item = new JsonObject();
        item.addProperty("name", bounded(f.getName(), NAME_LIMIT));
        item.addProperty("address", addr(f.getEntryPoint()));
        item.addProperty("size", f.getBody().getNumAddresses());
        item.addProperty("external", f.isExternal());
        item.addProperty("thunk", f.isThunk());
        item.addProperty("source", "ghidra_headless");
        return item;
    }

    private void cfg(JsonObject record, HighFunction high) {
        JsonArray nodes = new JsonArray(), edges = new JsonArray();
        List<PcodeBlockBasic> blocks = high.getBasicBlocks();
        Set<Integer> ids = new HashSet<>();
        for (PcodeBlockBasic b : blocks) {
            if (nodes.size() >= CFG_LIMIT) break;
            JsonObject node = new JsonObject();
            node.addProperty("id", Integer.toString(b.getIndex()));
            node.addProperty("label", "Block " + b.getIndex() + ": " + addr(b.getStart()) + " – " + addr(b.getStop()));
            nodes.add(node);
            ids.add(b.getIndex());
        }
        boolean truncated = blocks.size() > CFG_LIMIT;
        for (PcodeBlockBasic b : blocks) {
            if (!ids.contains(b.getIndex())) continue;
            for (int i = 0; i < b.getOutSize(); i++) {
                if (edges.size() >= CFG_EDGE_LIMIT) { truncated = true; break; }
                int destination = b.getOut(i).getIndex();
                if (!ids.contains(destination)) { truncated = true; continue; }
                JsonObject edge = new JsonObject();
                edge.addProperty("source", Integer.toString(b.getIndex()));
                edge.addProperty("target", Integer.toString(destination));
                edges.add(edge);
            }
        }
        record.add("cfg_nodes", nodes);
        record.add("cfg_edges", edges);
        record.addProperty("cfg_total_nodes", blocks.size());
        record.addProperty("cfg_truncated", truncated);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected one JSON output path");
        JsonObject root = new JsonObject();
        JsonArray functions = new JsonArray(), symbols = new JsonArray(), strings = new JsonArray(), calls = new JsonArray();
        root.add("functions", functions); root.add("symbols", symbols);
        root.add("strings", strings); root.add("call_edges", calls);
        root.add("coverage", coverage); root.add("limitations", limitations);
        root.addProperty("analysis_mode", "static_only");
        root.addProperty("image_base", addr(currentProgram.getImageBase()));
        coverage.addProperty("function_limit", FUNCTION_LIMIT);
        coverage.addProperty("decompile_limit", DECOMPILE_LIMIT);
        coverage.addProperty("decompile_timeout_seconds", 3);
        coverage.addProperty("decompile_budget_seconds", 40);
        coverage.addProperty("cfg_node_limit", CFG_LIMIT);
        coverage.addProperty("cfg_edge_limit", CFG_EDGE_LIMIT);
        coverage.addProperty("call_edge_limit", CALL_LIMIT);
        coverage.addProperty("symbol_limit", SYMBOL_LIMIT);
        coverage.addProperty("string_limit", STRING_LIMIT);
        coverage.addProperty("string_character_limit", 1024);
        coverage.addProperty("string_budget_characters", 1048576);
        coverage.addProperty("name_character_limit", NAME_LIMIT);
        coverage.addProperty("pseudocode_character_limit", TEXT_LIMIT);
        coverage.addProperty("analysis_timed_out", analysisTimeoutOccurred());
        coverage.addProperty("function_scan_limit", 50000);
        coverage.addProperty("function_scan_timeout_seconds", 10);
        coverage.addProperty("decompile_payload_limit_mib", 8);
        coverage.addProperty("decompile_instruction_limit", 100000);
        limitations.add("Pseudocode is an approximation, not recovered original source or an equivalence proof.");
        limitations.add("CFGs are optimized Ghidra high-pcode basic blocks, not source-level control flow.");
        limitations.add("Indirect calls, unanalyzed code and runtime-loaded libraries may be absent; external libraries were not imported.");
        limitations.add("Export caps and per-function truncation flags are reported in coverage and function records.");

        FunctionManager manager = currentProgram.getFunctionManager();
        Comparator<Function> order = Comparator.comparingInt((Function f) -> priority(f))
            .thenComparing(f -> f.getEntryPoint());
        PriorityQueue<Function> chosen = new PriorityQueue<>(FUNCTION_LIMIT, order.reversed());
        FunctionIterator iterator = manager.getFunctions(true);
        long scanDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        int scanned = 0;
        while (iterator.hasNext() && scanned < 50000 && System.nanoTime() < scanDeadline) {
            monitor.checkCancelled();
            Function f = iterator.next(); scanned++;
            if (chosen.size() < FUNCTION_LIMIT) chosen.add(f);
            else if (order.compare(f, chosen.peek()) < 0) { chosen.poll(); chosen.add(f); }
        }
        List<Function> selected = new ArrayList<>(chosen);
        selected.sort(order);
        coverage.addProperty("functions_total", manager.getFunctionCount());
        coverage.addProperty("functions_scanned", scanned);
        coverage.addProperty("function_scan_truncated", iterator.hasNext());
        coverage.addProperty("functions_exported", selected.size());
        coverage.addProperty("functions_truncated", manager.getFunctionCount() > selected.size());
        Map<Function, JsonObject> records = new LinkedHashMap<>();
        for (Function f : selected) {
            JsonObject item = functionRecord(f); records.put(f, item); functions.add(item);
        }

        DecompInterface decompiler = new DecompInterface();
        TaskMonitorAdapter decompileMonitor = new TaskMonitorAdapter();
        ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
        timer.schedule(() -> decompileMonitor.cancel(), 40, TimeUnit.SECONDS);
        long started = System.nanoTime();
        int attempted = 0, completed = 0;
        try {
            DecompileOptions options = new DecompileOptions();
            options.setMaxPayloadMBytes(8);
            options.setMaxInstructions(100000);
            decompiler.setOptions(options);
            if (!decompiler.openProgram(currentProgram)) {
                limitations.add("Decompiler initialization failed: " + decompiler.getLastMessage());
            } else for (Function f : selected) {
                monitor.checkCancelled();
                if (f.isExternal() || f.isThunk()) continue;
                if (attempted >= DECOMPILE_LIMIT || decompileMonitor.isCancelled()) break;
                int remaining = (int)(40 - TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - started));
                if (remaining < 1) break;
                attempted++;
                println("Decompiling " + bounded(f.getName(), NAME_LIMIT) + " at " + addr(f.getEntryPoint()));
                JsonObject item = records.get(f);
                DecompileResults result = decompiler.decompileFunction(f, Math.min(3, remaining), decompileMonitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String code = result.getDecompiledFunction().getC();
                    item.addProperty("pseudocode", bounded(code, TEXT_LIMIT));
                    item.addProperty("pseudocode_truncated", code.length() > TEXT_LIMIT);
                    item.addProperty("decompile_status", "ok");
                    if (result.getHighFunction() != null) cfg(item, result.getHighFunction());
                    completed++;
                } else {
                    item.addProperty("decompile_status", result.isTimedOut() ? "timeout" : "error");
                    item.addProperty("decompile_error", bounded(result.getErrorMessage(), 2048));
                }
            }
        } finally {
            decompiler.dispose(); timer.shutdownNow();
        }
        coverage.addProperty("functions_decompile_attempted", attempted);
        coverage.addProperty("functions_decompiled", completed);
        coverage.addProperty("decompile_elapsed_seconds", (System.nanoTime() - started) / 1e9);
        coverage.addProperty("decompile_budget_exhausted", decompileMonitor.isCancelled() || System.nanoTime() - started >= TimeUnit.SECONDS.toNanos(40));
        long eligible = selected.stream().filter(f -> !f.isExternal() && !f.isThunk()).count();
        coverage.addProperty("decompile_truncated", attempted < eligible || scanned < manager.getFunctionCount());

        long auxiliaryDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        int callsScanned = 0;
        outer: for (Function f : selected) {
            if (System.nanoTime() >= auxiliaryDeadline || calls.size() >= CALL_LIMIT) break;
            monitor.checkCancelled(); callsScanned++;
            for (Function destination : f.getCalledFunctions(monitor)) {
                if (calls.size() >= CALL_LIMIT) break outer;
                JsonObject edge = new JsonObject();
                edge.addProperty("source", bounded(f.getName(), NAME_LIMIT));
                edge.addProperty("target", bounded(destination.getName(), NAME_LIMIT));
                edge.addProperty("source_address", addr(f.getEntryPoint()));
                edge.addProperty("target_address", addr(destination.getEntryPoint()));
                calls.add(edge);
            }
        }
        coverage.addProperty("call_source_functions_scanned", callsScanned);
        coverage.addProperty("call_edges_truncated", calls.size() >= CALL_LIMIT || callsScanned < selected.size());
        SymbolIterator symbolIterator = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbolIterator.hasNext() && symbols.size() < SYMBOL_LIMIT && System.nanoTime() < auxiliaryDeadline) {
            monitor.checkCancelled();
            Symbol symbol = symbolIterator.next();
            JsonObject item = new JsonObject();
            item.addProperty("name", bounded(symbol.getName(), NAME_LIMIT));
            item.addProperty("address", addr(symbol.getAddress()));
            item.addProperty("type", symbol.getSymbolType().toString());
            item.addProperty("external", symbol.isExternal());
            symbols.add(item);
        }
        coverage.addProperty("symbols_truncated", symbolIterator.hasNext());
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        int stringChars = 0;
        boolean stringsTruncated = false;
        while (dataIterator.hasNext() && strings.size() < STRING_LIMIT && System.nanoTime() < auxiliaryDeadline) {
            monitor.checkCancelled();
            Data data = dataIterator.next();
            if (!data.hasStringValue()) continue;
            String text = String.valueOf(data.getValue());
            if (text.length() > 1024) stringsTruncated = true;
            text = bounded(text, 1024);
            if (stringChars + text.length() > 1048576) { stringsTruncated = true; break; }
            strings.add(text); stringChars += text.length();
        }
        coverage.addProperty("strings_truncated", stringsTruncated || dataIterator.hasNext());
        coverage.addProperty("auxiliary_budget_seconds", 10);
        coverage.addProperty("symbols_exported", symbols.size());
        coverage.addProperty("strings_exported", strings.size());
        coverage.addProperty("call_edges_exported", calls.size());
        Path destination = Paths.get(args[0]);
        Path temporary = destination.resolveSibling(destination.getFileName() + ".partial");
        Files.writeString(temporary, new GsonBuilder().disableHtmlEscaping().create().toJson(root), StandardCharsets.UTF_8);
        Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        println("Exported " + functions.size() + " functions, " + completed + " pseudocode bodies, " + calls.size() + " call edges.");
    }
}
