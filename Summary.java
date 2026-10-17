import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;

public class Summary extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("output path required");
        }

        ArrayList<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        int external = 0;
        int thunk = 0;
        int named = 0;
        long largest = 0;

        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (function.isExternal()) {
                external++;
                continue;
            }
            if (function.isThunk()) {
                thunk++;
            }
            String name = function.getName();
            if (name != null && !name.matches("(?i)(FUN_|thunk_FUN_|LAB_|entry).*")) {
                named++;
            }
            long size = function.getBody().getNumAddresses();
            if (size > largest) {
                largest = size;
            }
            functions.add(function);
        }

        functions.sort(Comparator.comparingLong(
            (Function f) -> f.getBody().getNumAddresses()).reversed());

        int selected = Math.min(80, functions.size());
        int decompiled = 0;
        int nontrivial = 0;
        long pseudocodeBytes = 0;
        int calls = 0;
        int calledFrom = 0;
        Set<String> recoveredNames = new HashSet<>();

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        for (int i = 0; i < selected; i++) {
            Function function = functions.get(i);
            DecompileResults result = decompiler.decompileFunction(function, 2, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                continue;
            }
            decompiled++;
            String c = result.getDecompiledFunction().getC();
            if (c != null) {
                pseudocodeBytes += c.length();
                if (c.length() >= 256) {
                    nontrivial++;
                }
            }
            try {
                calls += function.getCalledFunctions(monitor).size();
            } catch (Exception ignored) {
            }
            try {
                calledFrom += function.getCallingFunctions(monitor).size();
            } catch (Exception ignored) {
            }
            String name = function.getName();
            if (name != null && !name.matches("(?i)(FUN_|thunk_FUN_|LAB_|entry).*")) {
                recoveredNames.add(name);
            }
        }

        decompiler.dispose();

        File output = new File(args[0]);
        File parent = output.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        try (FileWriter writer = new FileWriter(output)) {
            writer.write("{");
            writer.write("\"function_count\":" + functions.size() + ",");
            writer.write("\"external_function_count\":" + external + ",");
            writer.write("\"thunk_count\":" + thunk + ",");
            writer.write("\"semantic_name_count\":" + named + ",");
            writer.write("\"largest_function_bytes\":" + largest + ",");
            writer.write("\"selected_function_count\":" + selected + ",");
            writer.write("\"decompiled_function_count\":" + decompiled + ",");
            writer.write("\"nontrivial_decompilation_count\":" + nontrivial + ",");
            writer.write("\"pseudocode_bytes\":" + pseudocodeBytes + ",");
            writer.write("\"call_edges_observed\":" + calls + ",");
            writer.write("\"caller_edges_observed\":" + calledFrom + ",");
            writer.write("\"distinct_semantic_names_in_sample\":" + recoveredNames.size());
            writer.write("}");
        }
    }
}
