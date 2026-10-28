import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Random;
import java.util.Set;

public class Summary extends HeadlessScript {
    private static final int MAX_NODES = 120;
    private static final int MAX_EDGES = 240;
    private static final int MAX_PATHS = 30;
    private static final int MAX_BFS_PATHS = 12;
    private static final int MAX_DEPTH = 10;
    private String outputPath;
    private String imageLabel;
    private String passMode;
    private int budgetSeconds;
    private long startedAt;
    private long deadline;
    private long lastProgressLog;
    private final List<String> patterns = new ArrayList<>();
    private final List<String> anchors = new ArrayList<>();
    private final List<String> fallbackPatterns = new ArrayList<>();
    private String scoreNameRegex = "";
    private final List<Function> functions = new ArrayList<>();
    private final Map<String, Function> functionById = new HashMap<>();
    private final Map<String, Map<String, Object>> nodes = new LinkedHashMap<>();
    private final Map<String, Map<String, Object>> edges = new LinkedHashMap<>();
    private final List<Map<String, Object>> paths = new ArrayList<>();
    private final Set<String> pathKeys = new HashSet<>();
    private final Map<String, Set<String>> seedReasons = new HashMap<>();
    private final Map<String, Set<String>> anchorById = new HashMap<>();
    private final Set<String> unresolvedPatterns = new LinkedHashSet<>();
    private final Map<String, Double> scores = new HashMap<>();
    private final Set<String> attemptedFunctions = new HashSet<>();
    private final Set<String> decompiledFunctions = new HashSet<>();
    private final Set<String> nontrivialFunctions = new HashSet<>();
    private final Set<String> semanticFunctions = new HashSet<>();
    private final Set<String> recoveredSemanticNames = new HashSet<>();
    private final Random random = new Random(0L);
    private DecompInterface decompiler;
    private int analysisPasses;
    private int externalFunctionCount;
    private int thunkCount;
    private int semanticFunctionCount;
    private long largestFunctionBytes;
    private long pseudocodeBytes;
    private long callEdgesObserved;
    private long callerEdgesObserved;
    private final Set<String> callStatsCounted = new HashSet<>();
    private int decompilationAttempts;
    private int decompilationFailures;

    private static final class Candidate {
        final Function function;
        final String id;
        final String seedId;
        final int depth;
        final double priority;
        final List<String> path;

        Candidate(Function function, String id, String seedId, int depth, double priority, List<String> path) {
            this.function = function;
            this.id = id;
            this.seedId = seedId;
            this.depth = depth;
            this.priority = priority;
            this.path = path;
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 4) throw new IllegalArgumentException("Summary.java expects output path, image label, budget seconds, and pass mode.");
        outputPath = args[0];
        imageLabel = args[1];
        budgetSeconds = Math.max(60, Integer.parseInt(args[2]));
        passMode = args[3];
        boolean autoAnalysisTimedOut = analysisTimeoutOccurred();
        println("AUTO_ANALYSIS_RESULT timed_out=" + autoAnalysisTimedOut);
        parseAnalysisArgs(args);

        startedAt = System.currentTimeMillis();
        deadline = startedAt + budgetSeconds * 1000L;
        lastProgressLog = startedAt;
        random.setSeed(((long) imageLabel.hashCode() << 32) ^ currentProgram.getName().hashCode() ^ passMode.hashCode());

        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && withinBudget()) {
            Function function = iterator.next();
            if (function == null) continue;
            if (function.isExternal()) {
                externalFunctionCount++;
                continue;
            }
            if (function.isThunk()) thunkCount++;
            String functionName = function.getName();
            if (functionName != null && !functionName.matches("(?i)(FUN_|thunk_FUN_|LAB_|entry).*")) semanticFunctionCount++;
            largestFunctionBytes = Math.max(largestFunctionBytes, size(function));
            functions.add(function);
            functionById.put(id(function), function);
        }
        if (functions.isEmpty()) throw new IllegalStateException("Ghidra found no internal functions to analyze.");

        matchHighValueNames();
        scanStringAnchors();
        for (String pattern : patterns) {
            if (!withinBudget()) break;
            boolean matched = false;
            for (Function function : functions) {
                if (!withinBudget()) break;
                if (function.getName().toLowerCase(Locale.ROOT).contains(pattern.toLowerCase(Locale.ROOT))) {
                    matched = true;
                    break;
                }
            }
            if (!matched) unresolvedPatterns.add(pattern);
        }

        List<Function> seeds = chooseSeeds();
        buildCallGraph(seeds);
        runWeightedRollouts(seeds);

        decompiler = new DecompInterface();
        // Other analysis modes produce intermediate trees rather than valid C.
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        try {
            runDecompilationPasses();
        } finally {
            decompiler.dispose();
        }

        long elapsedSeconds = Math.max(0, (System.currentTimeMillis() - startedAt) / 1000L);
        boolean budgetReached = elapsedSeconds >= budgetSeconds && decompilationAttempts > 0;
        Map<String, Object> explorationSummary = new LinkedHashMap<>();
        explorationSummary.put("seed_count", seeds.size());
        explorationSummary.put("visited_function_count", nodes.size());
        explorationSummary.put("edge_count", edges.size());
        explorationSummary.put("path_count", paths.size());
        explorationSummary.put("decompiled_function_count", decompiledFunctions.size());
        explorationSummary.put("decompilation_attempt_count", decompilationAttempts);
        explorationSummary.put("decompilation_failure_count", decompilationFailures);
        explorationSummary.put("budget_reached", budgetReached);
        explorationSummary.put("auto_analysis_timed_out", autoAnalysisTimedOut);

        Map<String, Object> exploration = new LinkedHashMap<>();
        exploration.put("schema", 1);
        exploration.put("image_count", 1);
        exploration.put("budget_seconds", budgetSeconds);
        exploration.put("elapsed_seconds", elapsedSeconds);
        exploration.put("analysis_passes", analysisPasses);
        exploration.put("budget_reached", budgetReached);
        exploration.put("auto_analysis_timed_out", autoAnalysisTimedOut);
        exploration.put("nodes", new ArrayList<>(nodes.values()));
        exploration.put("edges", new ArrayList<>(edges.values()));
        exploration.put("paths", paths);
        exploration.put("unresolved_seed_patterns", new ArrayList<>(unresolvedPatterns));
        exploration.put("summary", explorationSummary);

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("schema", 2);
        row.put("image", imageLabel);
        row.put("analysis_status", budgetReached ? "completed" : "budget_not_reached");
        row.put("function_count", functions.size());
        row.put("external_function_count", externalFunctionCount);
        row.put("thunk_count", thunkCount);
        row.put("largest_function_bytes", largestFunctionBytes);
        row.put("selected_function_count", attemptedFunctions.size());
        row.put("decompiled_function_count", decompiledFunctions.size());
        row.put("nontrivial_decompilation_count", nontrivialFunctions.size());
        row.put("semantic_name_count", semanticFunctionCount);
        row.put("semantic_name_rate", functions.isEmpty() ? 0 : (double) semanticFunctionCount / (double) functions.size());
        row.put("pseudocode_bytes", pseudocodeBytes);
        row.put("call_edges_observed", callEdgesObserved);
        row.put("caller_edges_observed", callerEdgesObserved);
        row.put("distinct_semantic_names_in_sample", recoveredSemanticNames.size());
        row.put("analysis_budget_seconds", budgetSeconds);
        row.put("analysis_elapsed_seconds", elapsedSeconds);
        row.put("analysis_budget_reached", budgetReached);
        row.put("auto_analysis_timed_out", autoAnalysisTimedOut);
        byte[] autoAnalysisTiming = AutoAnalysisManager.getAnalysisManager(currentProgram)
            .getTaskTimesString().getBytes(StandardCharsets.UTF_8);
        int autoAnalysisTimingLength = Math.min(autoAnalysisTiming.length, 8192);
        while (autoAnalysisTimingLength < autoAnalysisTiming.length
                && (autoAnalysisTiming[autoAnalysisTimingLength] & 0xc0) == 0x80) {
            autoAnalysisTimingLength--;
        }
        row.put("auto_analysis_timing", new String(autoAnalysisTiming, 0,
            autoAnalysisTimingLength, StandardCharsets.UTF_8));
        row.put("analysis_pass_count", analysisPasses);
        row.put("decompilation_attempt_count", decompilationAttempts);
        row.put("decompilation_failure_count", decompilationFailures);
        row.put("exploration", exploration);
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(toJson(row));
        }
        println("PATH_EXPLORER_RESULT image=" + imageLabel + " elapsed=" + elapsedSeconds + "s budget=" + budgetSeconds + "s reached=" + budgetReached + " auto_analysis_timed_out=" + autoAnalysisTimedOut + " seeds=" + seeds.size() + " nodes=" + nodes.size() + " edges=" + edges.size() + " paths=" + paths.size() + " decompiled=" + decompiledFunctions.size());
    }

    private boolean withinBudget() {
        return !monitor.isCancelled() && System.currentTimeMillis() < deadline;
    }


    private void parseAnalysisArgs(String[] args) {
        String section = "";
        boolean sawScore = false;
        for (int i = 4; i < args.length; i++) {
            String arg = args[i] == null ? "" : args[i].trim();
            if (arg.equals("@anchors") || arg.equals("@fallback") || arg.equals("@score") || arg.equals("@patterns")) {
                section = arg;
                continue;
            }
            if (section.equals("@score")) {
                if (!arg.matches("[A-Za-z0-9_|]{1,200}")) throw new IllegalArgumentException("Summary.java configuration is incomplete.");
                scoreNameRegex = arg;
                sawScore = true;
                section = "";
                continue;
            }
            if (!arg.matches("[A-Za-z0-9_$.:/-]{1,80}")) continue;
            if (section.equals("@anchors") && anchors.size() < 40) anchors.add(arg);
            else if (section.equals("@fallback") && fallbackPatterns.size() < 8) fallbackPatterns.add(arg);
            else if (section.equals("@patterns") && patterns.size() < 40) patterns.add(arg);
        }
        if (anchors.isEmpty() || fallbackPatterns.isEmpty() || !sawScore) {
            throw new IllegalArgumentException("Summary.java configuration is incomplete.");
        }
        if (patterns.isEmpty()) patterns.addAll(fallbackPatterns);
    }

    private String id(Function function) {
        return imageLabel + "@" + function.getEntryPoint().toString();
    }

    private void matchHighValueNames() {
        for (Function function : functions) {
            if (!withinBudget()) break;
            String lower = function.getName().toLowerCase(Locale.ROOT);
            for (String pattern : patterns) {
                if (!withinBudget()) break;
                if (lower.contains(pattern.toLowerCase(Locale.ROOT))) {
                    addSeedReason(id(function), "function-name-pattern:" + pattern);
                }
            }
        }
    }

    private void scanStringAnchors() {
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        int examined = 0;
        while (dataIterator.hasNext() && examined < 250000 && withinBudget()) {
            Data data = dataIterator.next();
            examined++;
            Object value;
            try { value = data.getValue(); } catch (Throwable ignored) { continue; }
            if (!(value instanceof String)) continue;
            String text = ((String) value).trim();
            if (text.length() < 4 || text.length() > 2048) continue;
            String lower = text.toLowerCase(Locale.ROOT);
            Set<String> matchedTerms = new LinkedHashSet<>();
            for (String term : anchors) if (lower.contains(term)) matchedTerms.add(term);
            if (matchedTerms.isEmpty()) continue;

            ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
            int referenceCount = 0;
            while (references.hasNext() && referenceCount++ < 32 && withinBudget()) {
                Reference reference = references.next();
                Function function = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
                if (function == null || function.isExternal()) continue;
                String functionId = id(function);
                for (String term : matchedTerms) {
                    anchorById.computeIfAbsent(functionId, key -> new LinkedHashSet<>()).add(term);
                    addSeedReason(functionId, "string-reference:" + term);
                }
            }
        }
    }

    private void addSeedReason(String functionId, String reason) {
        seedReasons.computeIfAbsent(functionId, key -> new LinkedHashSet<>()).add(reason);
    }

    private List<Function> chooseSeeds() {
        List<Function> seeds = new ArrayList<>();
        if (!withinBudget()) return seeds;
        for (Function function : functions) if (seedReasons.containsKey(id(function))) seeds.add(function);
        seeds.sort(Comparator.comparingDouble(this::score).reversed().thenComparing(function -> function.getEntryPoint().toString()));
        if (seeds.isEmpty()) {
            List<Function> fallback = new ArrayList<>(functions);
            fallback.sort(Comparator.comparingLong(this::size).reversed().thenComparing(function -> function.getEntryPoint().toString()));
            for (int i = 0; i < Math.min(5, fallback.size()); i++) {
                Function function = fallback.get(i);
                addSeedReason(id(function), "fallback:largest-functions-no-seed-match");
                seeds.add(function);
            }
        }
        if (seeds.size() > 24) return new ArrayList<>(seeds.subList(0, 24));
        return seeds;
    }

    private void buildCallGraph(List<Function> seeds) {
        PriorityQueue<Candidate> frontier = new PriorityQueue<>((left, right) -> {
            int byPriority = Double.compare(right.priority, left.priority);
            return byPriority != 0 ? byPriority : left.id.compareTo(right.id);
        });
        Map<String, Integer> bestDepth = new HashMap<>();
        for (Function seed : seeds) {
            String seedId = id(seed);
            addNode(seed, 0, true);
            frontier.add(new Candidate(seed, seedId, seedId, 0, score(seed), Collections.singletonList(seedId)));
        }
        while (!frontier.isEmpty() && nodes.size() < MAX_NODES && edges.size() < MAX_EDGES && withinBudget()) {
            Candidate candidate = frontier.poll();
            if (candidate.depth > MAX_DEPTH) continue;
            Integer oldDepth = bestDepth.get(candidate.id);
            if (oldDepth != null && oldDepth <= candidate.depth) continue;
            bestDepth.put(candidate.id, candidate.depth);
            Set<Function> called;
            try { called = candidate.function.getCalledFunctions(monitor); }
            catch (Throwable ignored) { continue; }
            List<Function> callees = new ArrayList<>();
            for (Function callee : called) if (callee != null && !callee.isExternal()) callees.add(callee);
            callees.sort(Comparator.comparingDouble(this::score).reversed().thenComparing(function -> function.getEntryPoint().toString()));
            if (callees.size() > 48) callees = new ArrayList<>(callees.subList(0, 48));
            updateCallCounts(candidate.id, called.size(), safeCallerCount(candidate.function));

            for (Function callee : callees) {
                if (!withinBudget() || nodes.size() >= MAX_NODES || edges.size() >= MAX_EDGES) break;
                String childId = id(callee);
                addNode(callee, candidate.depth + 1, seedReasons.containsKey(childId));
                addEdge(candidate.id, childId);
                List<String> nextPath = new ArrayList<>(candidate.path);
                if (nextPath.contains(childId)) continue;
                nextPath.add(childId);
                if (paths.size() < MAX_BFS_PATHS && nextPath.size() >= 2 && isCorePoint(callee)) {
                    addPath(candidate.seedId, childId, nextPath,
                        "Reachable core point ranked by function-name match, string-reference anchors, and function complexity.",
                        "core_point_reached");
                }
                if (candidate.depth + 1 < MAX_DEPTH) {
                    double priority = score(callee) - (candidate.depth + 1) * 2.5 + random.nextDouble() * 1.5;
                    frontier.add(new Candidate(callee, childId, candidate.seedId, candidate.depth + 1, priority, nextPath));
                }
            }
        }
    }

    private void runWeightedRollouts(List<Function> seeds) {
        int seedLimit = Math.min(12, seeds.size());
        for (int seedIndex = 0; seedIndex < seedLimit && paths.size() < MAX_PATHS && withinBudget(); seedIndex++) {
            Function seed = seeds.get(seedIndex);
            for (int attempt = 0; attempt < 3 && paths.size() < MAX_PATHS && withinBudget(); attempt++) {
                List<String> path = new ArrayList<>();
                Function current = seed;
                String seedId = id(seed);
                path.add(seedId);
                String stopReason = "no_callees";
                for (int depth = 0; depth < MAX_DEPTH && withinBudget(); depth++) {
                    Set<Function> called;
                    try { called = current.getCalledFunctions(monitor); }
                    catch (Throwable ignored) { stopReason = "call_graph_error"; break; }
                    List<Function> candidates = new ArrayList<>();
                    for (Function candidate : called) {
                        if (candidate == null || candidate.isExternal() || path.contains(id(candidate))) continue;
                        candidates.add(candidate);
                    }
                    candidates.sort(Comparator.comparing(function -> function.getEntryPoint().toString()));
                    if (candidates.isEmpty()) break;
                    Function next = chooseWeighted(candidates);
                    String currentId = id(current);
                    String nextId = id(next);
                    String edgeKey = currentId + "->" + nextId;
                    boolean missingNode = !nodes.containsKey(nextId);
                    boolean missingEdge = !edges.containsKey(edgeKey);
                    if (missingNode && nodes.size() >= MAX_NODES) {
                        stopReason = "node_limit";
                        break;
                    }
                    if (missingEdge && edges.size() >= MAX_EDGES) {
                        stopReason = "edge_limit";
                        break;
                    }
                    addNode(next, depth + 1, seedReasons.containsKey(nextId));
                    addEdge(currentId, nextId);
                    if (!nodes.containsKey(nextId) || !edges.containsKey(edgeKey)) {
                        stopReason = !nodes.containsKey(nextId) ? "node_limit" : "edge_limit";
                        break;
                    }
                    path.add(nextId);
                    current = next;
                    if (isCorePoint(current)) {
                        stopReason = "core_point_reached";
                        if (path.size() >= 2) break;
                    } else if (depth == MAX_DEPTH - 1) {
                        stopReason = "depth_limit";
                    }
                }
                if (path.size() >= 2) {
                    addPath(seedId, path.get(path.size() - 1), path,
                        "Deterministic weighted Monte Carlo rollout; child selection favors named targets, string anchors, and larger functions.",
                        stopReason);
                }
            }
        }
    }

    private Function chooseWeighted(List<Function> candidates) {
        double total = 0;
        for (Function function : candidates) total += Math.max(1.0, score(function) + 12.0);
        double pick = random.nextDouble() * total;
        for (Function function : candidates) {
            pick -= Math.max(1.0, score(function) + 12.0);
            if (pick <= 0) return function;
        }
        return candidates.get(candidates.size() - 1);
    }

    private void addNode(Function function, int depth, boolean seed) {
        String functionId = id(function);
        Map<String, Object> node = nodes.get(functionId);
        if (node == null) {
            if (nodes.size() >= MAX_NODES) return;
            node = new LinkedHashMap<>();
            node.put("id", functionId);
            node.put("image", imageLabel);
            node.put("name", function.getName());
            node.put("address", function.getEntryPoint().toString());
            node.put("size", size(function));
            node.put("depth", depth);
            node.put("score", score(function));
            node.put("seed", seed);
            node.put("seed_reason", seedReasons.containsKey(functionId) ? String.join("; ", seedReasons.get(functionId)) : null);
            node.put("anchor_terms", new ArrayList<>(anchorById.getOrDefault(functionId, Collections.emptySet())));
            node.put("called_count", null);
            node.put("caller_count", null);
            node.put("decompiled", false);
            node.put("pseudocode_excerpt", null);
            nodes.put(functionId, node);
        } else {
            int oldDepth = node.get("depth") instanceof Number ? ((Number) node.get("depth")).intValue() : depth;
            if (depth < oldDepth) node.put("depth", depth);
            if (seed) node.put("seed", true);
            if (seedReasons.containsKey(functionId)) node.put("seed_reason", String.join("; ", seedReasons.get(functionId)));
        }
    }

    private void updateCallCounts(String functionId, int calledCount, int callerCount) {
        Map<String, Object> node = nodes.get(functionId);
        if (node != null) {
            node.put("called_count", calledCount);
            node.put("caller_count", callerCount);
        }
    }

    private void addEdge(String from, String to) {
        if (from.equals(to) || edges.size() >= MAX_EDGES) return;
        String key = from + "->" + to;
        if (edges.containsKey(key)) return;
        Map<String, Object> edge = new LinkedHashMap<>();
        edge.put("from", from);
        edge.put("to", to);
        edge.put("kind", "call");
        edge.put("weight", 1);
        edges.put(key, edge);
    }

    private void addPath(String seed, String target, List<String> nodeIds, String reason, String stopReason) {
        if (paths.size() >= MAX_PATHS || nodeIds.size() < 2) return;
        List<String> bounded = new ArrayList<>(nodeIds.subList(0, Math.min(16, nodeIds.size())));
        String key = String.join(">", bounded);
        if (!pathKeys.add(key)) return;
        Map<String, Object> path = new LinkedHashMap<>();
        path.put("id", "path-" + (paths.size() + 1));
        path.put("seed", seed);
        path.put("target", target);
        path.put("node_ids", bounded);
        double pathScore = 0;
        for (String nodeId : bounded) pathScore += scores.getOrDefault(nodeId, 0.0);
        path.put("score", bounded.isEmpty() ? 0 : pathScore / bounded.size());
        path.put("reason", reason);
        path.put("stop_reason", stopReason);
        paths.add(path);
    }

    private boolean isCorePoint(Function function) {
        String functionId = id(function);
        if (seedReasons.containsKey(functionId) || anchorById.containsKey(functionId)) return true;
        long functionSize = size(function);
        try {
            return function.getCalledFunctions(monitor).size() >= 6 && functionSize >= 128;
        } catch (Throwable ignored) {
            return functionSize >= 1024;
        }
    }

    private void runDecompilationPasses() {
        if (!withinBudget()) return;
        List<Function> ranked = new ArrayList<>(functions);
        ranked.sort((left, right) -> {
            boolean leftInGraph = nodes.containsKey(id(left));
            boolean rightInGraph = nodes.containsKey(id(right));
            if (leftInGraph != rightInGraph) return leftInGraph ? -1 : 1;
            int scoreOrder = Double.compare(score(right), score(left));
            if (scoreOrder != 0) return scoreOrder;
            return Long.compare(size(right), size(left));
        });
        long iteration = 0;
        while (withinBudget() && !ranked.isEmpty()) {
            int functionIndex = (int) (iteration % ranked.size());
            Function function = ranked.get(functionIndex);
            String functionId = id(function);
            attemptedFunctions.add(functionId);
            decompilationAttempts++;
            try {
                DecompileResults result = decompiler.decompileFunction(function, 6, monitor);
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String c = result.getDecompiledFunction().getC();
                    if (c == null) c = "";
                    boolean firstSuccessfulDecompile = decompiledFunctions.add(functionId);
                    if (firstSuccessfulDecompile) {
                        pseudocodeBytes += c.length();
                        if (c.trim().length() >= 256) nontrivialFunctions.add(functionId);
                        if (!function.getName().matches("(?i)(FUN_|thunk_FUN_|LAB_|entry).*")) {
                            semanticFunctions.add(functionId);
                            recoveredSemanticNames.add(function.getName());
                        }
                    }
                    if (firstSuccessfulDecompile && callStatsCounted.add(functionId)) {
                        try { callEdgesObserved += function.getCalledFunctions(monitor).size(); } catch (Throwable ignored) { }
                        try { callerEdgesObserved += function.getCallingFunctions(monitor).size(); } catch (Throwable ignored) { }
                    }
                    Map<String, Object> node = nodes.get(functionId);
                    if (node != null) {
                        node.put("decompiled", true);
                        if (!(node.get("pseudocode_excerpt") instanceof String) || ((String) node.get("pseudocode_excerpt")).isEmpty()) {
                            node.put("pseudocode_excerpt", c.length() > 1200 ? c.substring(0, 1200) : c);
                        }
                    }
                } else {
                    decompilationFailures++;
                }
            } catch (Throwable ignored) {
                decompilationFailures++;
            }
            iteration++;
            if (iteration > 0 && iteration % Math.max(1, ranked.size()) == 0) analysisPasses++;
            long now = System.currentTimeMillis();
            if (now - lastProgressLog >= 300000L) {
                long elapsed = Math.max(0, (now - startedAt) / 1000L);
                println("PATH_EXPLORER_PROGRESS image=" + imageLabel + " mode=" + passMode + " elapsed=" + elapsed + "s budget=" + budgetSeconds + "s functions=" + attemptedFunctions.size() + " decompiled=" + decompiledFunctions.size() + " paths=" + paths.size());
                lastProgressLog = now;
            }
        }
        analysisPasses = Math.max(analysisPasses, (int) (iteration / Math.max(1, ranked.size())));
    }

    private double score(Function function) {
        String functionId = id(function);
        Double cached = scores.get(functionId);
        if (cached != null) return cached;
        double score = Math.log1p(Math.max(0, size(function))) * 3.0;
        if (seedReasons.containsKey(functionId)) score += 24.0;
        Set<String> anchors = anchorById.get(functionId);
        if (anchors != null) score += Math.min(16.0, anchors.size() * 4.0);
        String lower = function.getName().toLowerCase(Locale.ROOT);
        for (String pattern : patterns) if (lower.contains(pattern.toLowerCase(Locale.ROOT))) score += 18.0;
        if (lower.matches(".*(" + scoreNameRegex + ").*")) score += 8.0;
        scores.put(functionId, score);
        return score;
    }

    private long size(Function function) {
        try { return function.getBody().getNumAddresses(); }
        catch (Throwable ignored) { return 0; }
    }

    private int safeCallerCount(Function function) {
        try { return function.getCallingFunctions(monitor).size(); }
        catch (Throwable ignored) { return 0; }
    }

    private static String toJson(Object value) {
        StringBuilder out = new StringBuilder();
        appendJson(out, value);
        return out.toString();
    }

    private static void appendJson(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String) {
            out.append('"').append(escapeJson((String) value)).append('"');
        } else if (value instanceof Number || value instanceof Boolean) {
            out.append(value.toString());
        } else if (value instanceof Map) {
            out.append('{');
            boolean first = true;
            for (Object entryObject : ((Map<?, ?>) value).entrySet()) {
                Map.Entry<?, ?> entry = (Map.Entry<?, ?>) entryObject;
                if (!first) out.append(',');
                first = false;
                appendJson(out, String.valueOf(entry.getKey()));
                out.append(':');
                appendJson(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof Iterable) {
            out.append('[');
            boolean first = true;
            for (Object item : (Iterable<?>) value) {
                if (!first) out.append(',');
                first = false;
                appendJson(out, item);
            }
            out.append(']');
        } else {
            appendJson(out, String.valueOf(value));
        }
    }

    private static String escapeJson(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.toString();
    }
}
