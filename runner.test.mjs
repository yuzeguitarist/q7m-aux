import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const directory = await mkdtemp(join(tmpdir(), "runner-check-"));
const previousTemp = process.env.RUNNER_TEMP;
process.env.RUNNER_TEMP = directory;
const { analysisWindow, analysisResult, mergeExplorations, download } = await import("./runner.mjs");
if (previousTemp === undefined) delete process.env.RUNNER_TEMP;
else process.env.RUNNER_TEMP = previousTemp;
test.after(() => rm(directory, { recursive: true, force: true }));

const minute = 60 * 1000;
const deadline = 360 * minute;

test("automatic analysis has its own allowance outside the full active budget", () => {
  const window = analysisWindow(deadline, 20 * minute, 180 * minute, 3, 60 * 60);
  assert.equal(window.activeSeconds, 3600);
  assert.equal(window.autoAnalysisSeconds, 1800);
  assert.equal(window.timeoutMs, 91 * minute);
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
      assert.ok(window.autoAnalysisSeconds <= 1800);
      now += window.timeoutMs;
      activeRemaining -= window.activeSeconds * 1000;
      activeTotal += window.activeSeconds;
    }
    assert.equal(activeTotal, 180 * 60);
    assert.ok(now + 15 * minute <= deadline);
  }
});

test("slow preparation cannot consume reserved active analysis", () => {
  assert.throws(() => analysisWindow(deadline, 170 * minute, 180 * minute, 3, 3600),
    /insufficient analysis preparation time/);
  const lateWindow = analysisWindow(deadline, 150 * minute, 180 * minute, 3, 3600);
  assert.equal(lateWindow.autoAnalysisSeconds, 240);
  assert.equal(lateWindow.activeSeconds, 3600);
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
  await mkdir(join(directory, "q7m"));
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
