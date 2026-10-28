import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawn } from "node:child_process";
import test from "node:test";

const directory = await mkdtemp(join(tmpdir(), "runner-check-"));
const previousTemp = process.env.RUNNER_TEMP;
process.env.RUNNER_TEMP = directory;
const { analysisWindow, analysisResult, mergeExplorations, download, runStreaming } = await import("./runner.mjs");
if (previousTemp === undefined) delete process.env.RUNNER_TEMP;
else process.env.RUNNER_TEMP = previousTemp;
test.after(() => rm(directory, { recursive: true, force: true }));

const minute = 60 * 1000;
const deadline = 360 * minute;

test("automatic analysis has its own allowance outside the full active budget", () => {
  const window = analysisWindow(deadline, 20 * minute, 180 * minute, 3, 60 * 60);
  assert.equal(window.activeSeconds, 3600);
  assert.equal(window.autoAnalysisSeconds, 2840);
  assert.equal(window.timeoutMs, 6500 * 1000);
});

test("all image allowances fit the job while preserving active analysis and finalization", () => {
  for (const imageCount of [1, 3, 12]) {
    let now = 20 * minute;
    let activeRemaining = 180 * minute;
    let activeTotal = 0;
    for (let remainingImages = imageCount; remainingImages > 0; remainingImages--) {
      const window = analysisWindow(deadline, now, activeRemaining, remainingImages,
        Math.ceil(180 / imageCount) * 60);
      assert.ok(window.autoAnalysisSeconds >= 60);
      const preparationRemaining = deadline - now - activeRemaining - 15 * minute;
      assert.ok((window.autoAnalysisSeconds + 60) * 1000 * remainingImages <= preparationRemaining);
      now += window.timeoutMs;
      activeRemaining -= window.activeSeconds * 1000;
      activeTotal += window.activeSeconds;
    }
    assert.equal(activeTotal, 180 * 60);
    assert.ok(now + 15 * minute <= deadline);
  }
});

test("unused preparation time is shared fairly with the remaining images", () => {
  const first = analysisWindow(deadline, 20 * minute, 180 * minute, 3, 3600);
  const second = analysisWindow(deadline, 86 * minute, 120 * minute, 2, 3600);
  assert.equal(first.autoAnalysisSeconds, 2840);
  assert.equal(second.autoAnalysisSeconds, 4110);
  assert.equal(second.activeSeconds, 3600);
  const single = analysisWindow(deadline, 20 * minute, 180 * minute, 1, 180 * 60);
  assert.equal(single.autoAnalysisSeconds, 144 * 60);
});

test("slow preparation cannot consume reserved active analysis", () => {
  assert.throws(() => analysisWindow(deadline, 170 * minute, 180 * minute, 3, 3600),
    /insufficient analysis preparation time/);
  const lateWindow = analysisWindow(deadline, 150 * minute, 180 * minute, 3, 3600);
  assert.equal(lateWindow.autoAnalysisSeconds, 240);
  assert.equal(lateWindow.activeSeconds, 3600);
});

test("a missing report cannot turn preparation wall time into active exploration", () => {
  const result = analysisResult(null, 1, "process_timeout", "image-0");
  const partial = mergeExplorations([result], 10800);
  assert.equal(partial.elapsed_seconds, 0);
  assert.equal(partial.budget_reached, false);
  const early = analysisWindow(deadline, 20 * minute, 180 * minute, 3, 3600);
  const late = analysisWindow(deadline, 150 * minute, 180 * minute, 3, 3600);
  assert.equal(late.activeSeconds, early.activeSeconds);
  assert.ok(late.autoAnalysisSeconds < early.autoAnalysisSeconds);
});

function completedRow(image = "image-0", seconds = 3600) {
  return {
    image, analysis_budget_reached: true, auto_analysis_timed_out: false,
    decompiled_function_count: 1,
    exploration: {
      elapsed_seconds: seconds, analysis_passes: 1, nodes: [], edges: [], paths: [],
      summary: { decompilation_attempt_count: 1, decompilation_failure_count: 0 },
    },
  };
}

test("completed automatic analysis and all active image budgets are required", () => {
  const rows = [0, 1, 2].map(index => analysisResult(completedRow("image-" + index), 0, null, "image-" + index));
  assert.equal(mergeExplorations(rows, 10800).budget_reached, true);
  rows[1] = analysisResult({ ...completedRow("image-1"), auto_analysis_timed_out: true }, 0, null, "image-1");
  assert.equal(rows[1].error_code, "auto_analysis_timeout");
  const partial = mergeExplorations(rows, 10800);
  assert.equal(partial.elapsed_seconds, 10800);
  assert.equal(partial.budget_reached, false);
});

test("partial, invalid and terminated reports remain failures", () => {
  for (const [row, status, cause, expected] of [
    [completedRow(), 1, "process_timeout", "process_timeout"],
    [completedRow(), 1, null, "process_failed_after_partial_report"],
    [null, 0, null, "summary_invalid"],
    [null, 1, "insufficient_preparation_time", "insufficient_preparation_time"],
    [{ ...completedRow(), analysis_budget_reached: false }, 0, null, "analysis_budget_not_reached"],
  ]) {
    const result = analysisResult(row, status, cause, "image-0");
    assert.equal(result.analysis_status, "failed");
    assert.equal(result.error_code, expected);
    assert.equal(mergeExplorations([result], 3600).budget_reached, false);
  }
  assert.equal(mergeExplorations([], 3600).budget_reached, false);
});

test("archive download backpressure does not accumulate error listeners", async () => {
  await mkdir(join(directory, "q7m"), { recursive: true });
  const originalFetch = globalThis.fetch;
  const warnings = [];
  const onWarning = warning => warnings.push(warning);
  process.on("warning", onWarning);
  const chunk = new Uint8Array(512 * 1024).fill(23);
  let remaining = 32;
  globalThis.fetch = async () => ({
    ok: true, url: "https://example.invalid/archive", headers: new Headers(),
    body: new ReadableStream({
      pull(controller) {
        if (remaining-- > 0) controller.enqueue(chunk);
        else controller.close();
      },
    }),
  });
  try {
    const path = await download("https://example.invalid/archive");
    assert.equal((await readFile(path)).length, 32 * chunk.length);
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(warnings.filter(warning => warning.name === "MaxListenersExceededWarning"), []);
  } finally {
    globalThis.fetch = originalFetch;
    process.off("warning", onWarning);
  }
});

test("failed and empty archive streams are removed", async () => {
  await mkdir(join(directory, "q7m"), { recursive: true });
  const originalFetch = globalThis.fetch;
  try {
    for (const failed of [false, true]) {
      let emitted = false;
      globalThis.fetch = async () => ({
        ok: true, url: "https://example.invalid/archive", headers: new Headers(),
        body: new ReadableStream({
          pull(controller) {
            if (failed && !emitted) {
              emitted = true;
              controller.enqueue(new Uint8Array(512 * 1024));
            } else if (failed) controller.error(new Error("interrupted stream"));
            else controller.close();
          },
        }),
      });
      await assert.rejects(download("https://example.invalid/archive"),
        failed ? /interrupted stream/ : /archive is empty or invalid/);
      await assert.rejects(readFile(join(directory, "q7m", "build-artifact")), { code: "ENOENT" });
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

async function streamingHarness() {
  const { runStreaming } = await import("./runner.mjs");
  const marker = process.argv[1];
  const mode = process.argv[2];
  function descendant() {
    if (process.argv[2] !== "signal") process.on("SIGTERM", () => {});
    require("node:fs").writeFileSync(process.argv[1], process.ppid + " " + process.pid);
    process.stderr.write("private marker\n");
    process.stdout.write(process.argv[2] === "overflow" ? Buffer.alloc(32768, 23) : "private payload\n");
    setInterval(() => {}, 1000);
  }
  function wrapper() {
    require("node:child_process").spawn(process.execPath,
      ["-e", process.argv[1], process.argv[2], process.argv[3]],
      { stdio: ["ignore", "inherit", "inherit"] });
    setInterval(() => {}, 1000);
  }
  let failure;
  try {
    await runStreaming([process.execPath, "-e", "(" + wrapper.toString() + ")()",
      "(" + descendant.toString() + ")()", marker, mode], {
      timeout: mode === "timeout" ? 1000 : 15000,
      captureStdout: mode === "overflow", maxCaptureBytes: 1024,
      logPath: marker + ".log",
    });
  } catch (error) { failure = { message: error.message, code: error.code }; }
  process.stdout.write(JSON.stringify({ failure,
    interruptListeners: process.listenerCount("SIGINT"),
    terminateListeners: process.listenerCount("SIGTERM"),
  }));
}

for (const trigger of ["timeout", "overflow", "SIGINT", "SIGTERM"]) {
  test(`streaming ${trigger} stops a descendant holding the output pipe`, async () => {
    const marker = join(directory, "streaming-" + trigger);
    const signal = trigger.startsWith("SIG") ? trigger : null;
    const runner = spawn(process.execPath, ["--input-type=module", "-e", "(" + streamingHarness.toString() + ")()",
      marker, signal ? "signal" : trigger], { cwd: new URL(".", import.meta.url), stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    let errors = "";
    runner.stdout.on("data", chunk => { output += chunk; });
    runner.stderr.on("data", chunk => { errors += chunk; });
    const closed = new Promise((resolve, reject) => {
      runner.once("error", reject);
      runner.once("close", (code, receivedSignal) => resolve({ code, receivedSignal }));
    });
    const timer = setTimeout(() => runner.kill("SIGKILL"), 9000);
    const started = Date.now();
    let descendants = [];
    try {
      while (descendants.length === 0 && Date.now() - started < 3000) {
        try { descendants = (await readFile(marker, "utf8")).trim().split(" ").map(Number); } catch {}
        if (!descendants.length) await new Promise(resolve => setTimeout(resolve, 20));
      }
      assert.equal(descendants.length, 2);
      if (signal) {
        let recorded = "";
        while (!recorded.includes("private marker") && Date.now() - started < 3000) {
          try { recorded = await readFile(marker + ".log", "utf8"); } catch {}
          if (!recorded.includes("private marker")) await new Promise(resolve => setTimeout(resolve, 20));
        }
        assert.match(recorded, /private marker/);
        runner.kill(signal);
      }
      assert.deepEqual(await closed, { code: 0, receivedSignal: null });
      assert.ok(Date.now() - started < 8500, "wrapper and descendant must stop within the bound");
      assert.equal(errors, "");
      const received = JSON.parse(output);
      assert.match(received.failure.message, signal ? /analysis process interrupted/
        : trigger === "timeout" ? /analysis process timeout/ : /analysis output size limit exceeded/);
      if (signal) assert.equal(received.failure.code, "ANALYSIS_INTERRUPTED");
      assert.equal(received.interruptListeners, 0);
      assert.equal(received.terminateListeners, 0);
      assert.match(await readFile(marker + ".log", "utf8"), /private marker/);
      for (const pid of descendants) {
        let status = "";
        try { status = execFileSync("ps", ["-p", String(pid), "-o", "stat="],
          { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch {}
        assert.ok(!status || status.startsWith("Z"), "descendant must no longer be running");
      }
    } finally {
      clearTimeout(timer);
      if (runner.exitCode === null && runner.signalCode === null) runner.kill("SIGKILL");
      if (descendants[0]) {
        try { process.kill(-descendants[0], "SIGKILL"); } catch {}
      }
    }
  });
}

test("automatic-analysis boundary bypasses ordinary throttling but retains its rate limit", async () => {
  const originalFetch = globalThis.fetch;
  const names = ["ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
  const previous = names.map(name => process.env[name]);
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = "https://example.actions.githubusercontent.com/token";
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "test-request";
  const messages = [];
  globalThis.fetch = async (url, options) => {
    if (String(url).includes("actions.githubusercontent.com")) return Response.json({ value: "test-identity" });
    messages.push(JSON.parse(options.body).message);
    return Response.json({ ok: true });
  };
  try {
    const lines = ["Analysis preparing", ...Array(20).fill("INFO Summary.java> AUTO_ANALYSIS_RESULT timed_out=false (GhidraScript)")];
    await runStreaming([process.execPath, "-e", "process.stdout.write(" + JSON.stringify(lines.join("\n") + "\n") + ")"],
      { logPath: join(directory, "boundary.log") });
    const until = Date.now() + 1000;
    while (messages.length < 13 && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(messages.filter(message => message.includes("AUTO_ANALYSIS_RESULT timed_out=false")).length, 12);
  } finally {
    globalThis.fetch = originalFetch;
    names.forEach((name, index) => {
      if (previous[index] === undefined) delete process.env[name];
      else process.env[name] = previous[index];
    });
  }
});
