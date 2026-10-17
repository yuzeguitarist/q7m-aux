#!/usr/bin/env node
import { createHash, createCipheriv, randomBytes, publicEncrypt, constants } from "node:crypto";
import { mkdir, readFile, writeFile, rm, readdir } from "node:fs/promises";
import { existsSync, createReadStream, createWriteStream, openSync, closeSync, readSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { gzipSync } from "node:zlib";

const env = process.env;
const outDir = resolve(env.GITHUB_WORKSPACE || process.cwd(), "out");
const tmpDir = resolve(env.RUNNER_TEMP || "/tmp", "q7m");
const publicRepo = env.GITHUB_REPOSITORY;
const publicSha = env.GITHUB_SHA;

await mkdir(outDir, { recursive: true });
await mkdir(tmpDir, { recursive: true });

function safeJson(value) {
  return JSON.stringify(value, null, 2) + "\n";
}

async function status(kind, extra = {}) {
  await writeFile(join(outDir, "status.json"), safeJson({
    schema: 1,
    status: kind,
    ...extra
  }));
}

function required(name) {
  const value = env[name];
  if (!value) throw new Error("missing configuration");
  return value;
}

function configuredOrigin() {
  let url;
  try { url = new URL(required("STUDIO_ORIGIN")); } catch { throw new Error("missing configuration"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error("missing configuration");
  }
  return url.origin;
}

function configuredAudience() {
  const value = required("STUDIO_AUDIENCE");
  if (!/^[A-Za-z0-9._:-]{8,80}$/.test(value)) throw new Error("missing configuration");
  return value;
}

const STUDIO_ORIGIN = configuredOrigin();
const STUDIO_AUDIENCE = configuredAudience();
const PUBLIC_KEY_SHA256 = "4d7e08a1421e286e080dd7fba1b99b17696f38dba23ddcd2e0e402d10002c74a";
let studioSeq = 0;
let studioEventQueue = Promise.resolve();
let pendingStudioLogs = 0;
let currentPhase = "checking";

function workflowRunId() {
  const id = required("GITHUB_RUN_ID");
  const attempt = env.GITHUB_RUN_ATTEMPT || "1";
  if (!/^\d{1,30}$/.test(id) || !/^\d{1,3}$/.test(attempt)) throw new Error("invalid workflow identity");
  return id + ":" + attempt;
}

async function githubOidcToken() {
  const requestUrl = required("ACTIONS_ID_TOKEN_REQUEST_URL");
  const requestToken = required("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
  const url = new URL(requestUrl);
  if (url.protocol !== "https:" || !url.hostname.endsWith(".actions.githubusercontent.com") || url.username || url.password) {
    throw new Error("studio authentication unavailable");
  }
  url.searchParams.set("audience", STUDIO_AUDIENCE);
  const response = await fetch(url, {
    headers: { Authorization: "Bearer " + requestToken, Accept: "application/json" },
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error("studio authentication unavailable");
  const data = await response.json();
  if (!data?.value || typeof data.value !== "string") throw new Error("studio authentication unavailable");
  return data.value;
}

async function studioFetch(path, options = {}, maxAttempts = 3) {
  let lastError;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const token = await githubOidcToken();
      const response = await fetch(STUDIO_ORIGIN + path, {
        ...options,
        signal: options.signal || AbortSignal.timeout(15000),
        headers: {
          Accept: "application/json",
          Authorization: "Bearer " + token,
          ...(options.headers || {}),
        },
      });
      if (response.ok) return response;
      const requestError = new Error("studio request failed (" + response.status + ") for " + path);
      if (response.status < 500) {
        requestError.name = "NonRetryableStudioError";
        throw requestError;
      }
      if (attempt === maxAttempts - 1) throw requestError;
      lastError = requestError;
    } catch (error) {
      lastError = error;
      if (attempt === maxAttempts - 1 || (error instanceof Error && error.name === "NonRetryableStudioError")) throw error;
    }
    await new Promise(resolve => setTimeout(resolve, 1500 * (attempt + 1)));
  }
  throw lastError || new Error("studio request failed");
}

async function studioState() {
  const response = await studioFetch("/api/redteam/state");
  return response.json();
}

async function studioSourceSnapshot() {
  const response = await studioFetch("/api/redteam/source", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  const data = await response.json();
  if (!data || !/^[0-9a-f]{40}$/i.test(String(data.latest || "")) || typeof data.shouldRun !== "boolean"
    || !Array.isArray(data.changedFiles) || !data.analysis || typeof data.analysis !== "object") {
    throw new Error("source snapshot invalid");
  }
  return {
    latest: String(data.latest).toLowerCase(),
    baseline: typeof data.baseline === "string" ? data.baseline.toLowerCase() : null,
    shouldRun: data.shouldRun,
    changedFiles: data.changedFiles.filter(path => typeof path === "string").slice(0, 300),
    compareUncertain: data.compareUncertain === true,
    analysis: data.analysis,
  };
}

function studioEvent(kind, extra = {}, requiredDelivery = true) {
  const payload = { ...extra, kind, runner_sha: publicSha, seq: ++studioSeq };
  const send = async () => {
    try {
      await studioFetch("/api/redteam/ingest", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }, requiredDelivery ? 3 : 1);
    } catch (error) {
      if (requiredDelivery) throw error;
    }
  };
  const pending = studioEventQueue.then(send, send);
  studioEventQueue = pending.catch(() => {});
  return pending;
}

async function studioLog(phase, message, progress, status = undefined) {
  currentPhase = phase;
  if (pendingStudioLogs >= 5) return;
  pendingStudioLogs++;
  try {
    await studioEvent("log", { phase, message, progress, status }, false);
  } finally {
    pendingStudioLogs--;
  }
}

async function studioPhase(phase, message, progress, status) {
  currentPhase = phase;
  await studioEvent("phase", { phase, message, progress, status }, false);
}

function commitShaFrom(value) {
  const sourceCommit = value?.attributes?.sourceCommit;
  const candidates = [
    value?.commitSha,
    value?.sha,
    typeof sourceCommit === "string" ? sourceCommit : null,
    sourceCommit?.commitSha,
    sourceCommit?.sha,
    value?.data?.attributes?.sourceCommit?.commitSha,
    value?.data?.attributes?.sourceCommit?.sha,
  ];
  return candidates.find(candidate => typeof candidate === "string" && /^[0-9a-f]{40}$/i.test(candidate))?.toLowerCase() || null;
}

function completion(value) {
  return String(value?.attributes?.completionStatus || "").toUpperCase();
}

function progress(value) {
  return String(value?.attributes?.executionProgress || "").toUpperCase();
}

function terminal(value) {
  const state = completion(value);
  return ["SUCCEEDED", "SUCCESS", "SUCCEEDED_WITH_WARNINGS", "FAILED", "ERRORED", "CANCELED", "CANCELLED", "SKIPPED"].includes(state)
    || ["COMPLETE", "COMPLETED", "FINISHED"].includes(progress(value));
}

function successful(value) {
  return ["SUCCEEDED", "SUCCESS", "SUCCEEDED_WITH_WARNINGS"].includes(completion(value));
}

async function fetchPublicFile(name) {
  const url = "https://raw.githubusercontent.com/" + publicRepo + "/" + publicSha + "/" + name;
  const response = await fetch(url, { signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw new Error("runner component unavailable");
  return response.text();
}

function childEnvironment() {
  const childEnv = { ...env };
  for (const key of Object.keys(childEnv)) {
    if (["ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "GITHUB_TOKEN", "GH_TOKEN", "CLOUDFLARE_API_TOKEN"].includes(key)
      || /(?:^|_)(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY)(?:_|$)/i.test(key)) {
      delete childEnv[key];
    }
  }
  return childEnv;
}

function run(argv, options = {}) {
  const result = spawnSync(argv[0], argv.slice(1), {
    cwd: options.cwd || process.cwd(),
    env: childEnvironment(),
    stdio: options.capture === false ? "inherit" : ["ignore", "pipe", "pipe"],
    timeout: options.timeout || 120000,
    maxBuffer: 8 * 1024 * 1024
  });
  if (result.error) throw result.error;
  return result;
}

function cleanLogLine(value) {
  return String(value)
    .replace(/https?:\/\/\S+/gi, "[url]")
    .replace(/bearer\s+[^\s]+/gi, "Bearer [redacted]")
    .replace(/(token|secret|password|private key)\s*[:=]\s*\S+/gi, "$1=[redacted]")
    .replace(/[\t\r]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 480);
}

async function runStreaming(argv, options = {}) {
  const phase = options.phase || "analysis";
  const progressValue = options.progress ?? 60;
  const statusValue = options.status || "analyzing";
  const timeoutMs = options.timeout || 120000;
  const logPath = options.logPath || join(tmpDir, "stream-" + Date.now() + ".log");
  const captureStdout = options.captureStdout === true;
  const maxCaptureBytes = options.maxCaptureBytes || 12 * 1024 * 1024;
  const stdoutChunks = [];
  let stdoutBytes = 0;
  let captureOverflow = false;
  const logStream = createWriteStream(logPath, { flags: "w", mode: 0o600 });
  const child = spawn(argv[0], argv.slice(1), {
    cwd: options.cwd || process.cwd(),
    env: childEnvironment(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  let lastEventAt = 0;
  let lineEventCount = 0;
  let heartbeatCount = 0;
  let outputPaused = false;
  const buffers = { stdout: "", stderr: "" };

  const emitLine = (line) => {
    const safe = cleanLogLine(line);
    if (!safe || lineEventCount >= 40) return;
    const now = Date.now();
    const important = /error|fatal|warn|fail|exception|complete|decompil|analysis|import|processing|program|function/i.test(safe);
    if (!important || now - lastEventAt < 2000) return;
    lastEventAt = now;
    lineEventCount++;
    void studioLog(phase, safe, progressValue, statusValue);
  };

  const consume = (name, chunk) => {
    if (name === "stdout" && captureStdout) {
      if (stdoutBytes + chunk.length > maxCaptureBytes) {
        captureOverflow = true;
        child.kill("SIGTERM");
      } else {
        stdoutChunks.push(Buffer.from(chunk));
        stdoutBytes += chunk.length;
      }
    }
    const shouldWriteLog = !(name === "stdout" && captureStdout);
    if (shouldWriteLog && !logStream.write(chunk) && !outputPaused) {
      outputPaused = true;
      child.stdout.pause();
      child.stderr.pause();
      logStream.once("drain", () => {
        outputPaused = false;
        child.stdout.resume();
        child.stderr.resume();
      });
    }
    if (name === "stdout" && captureStdout) return;
    const lines = (buffers[name] + chunk.toString("utf8")).split(/[\r\n]+/);
    buffers[name] = lines.pop() || "";
    for (const line of lines) emitLine(line);
    if (buffers[name].length > 2048) {
      emitLine(buffers[name].slice(0, 2048));
      buffers[name] = "";
    }
  };

  child.stdout.on("data", chunk => consume("stdout", chunk));
  child.stderr.on("data", chunk => consume("stderr", chunk));
  const heartbeat = setInterval(() => {
    if (heartbeatCount >= 20 || Date.now() - lastEventAt < 14000) return;
    lastEventAt = Date.now();
    heartbeatCount++;
    const name = String(argv[0]).split(/[\\/]/).pop() || "process";
    void studioLog(phase, "Still running: " + name + ".", progressValue, statusValue);
  }, 15000);

  let timedOut = false;
  let forceKill;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGTERM");
    forceKill = setTimeout(() => child.kill("SIGKILL"), 5000);
  }, timeoutMs);

  const outcome = await new Promise(resolvePromise => {
    child.once("error", error => resolvePromise({ status: 1, error }));
    child.once("close", (code, signal) => resolvePromise({ status: code ?? 1, signal }));
  });

  clearTimeout(timer);
  clearTimeout(forceKill);
  clearInterval(heartbeat);
  for (const name of ["stdout", "stderr"]) {
    if (!(name === "stdout" && captureStdout) && buffers[name]) emitLine(buffers[name]);
  }
  await new Promise((resolvePromise, rejectPromise) => {
    logStream.once("error", rejectPromise);
    logStream.end(resolvePromise);
  });
  if (timedOut) throw new Error("analysis process timeout");
  if (captureOverflow) throw new Error("analysis output size limit exceeded");
  if (outcome.error) throw outcome.error;
  return { ...outcome, stdout: Buffer.concat(stdoutChunks) };
}

async function treeFind(root, predicate, limit = 2000) {
  const found = [];
  async function walk(dir) {
    if (found.length >= limit) return;
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (found.length >= limit) return;
      if (entry.name === ".DS_Store" || entry.name === "__MACOSX") continue;
      const path = join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (predicate(path, entry)) found.push(path);
      if (entry.isDirectory()) await walk(path);
    }
  }
  await walk(root);
  return found;
}

async function installTools() {
  let javaText = "";
  try {
    const java = run(["java", "-version"], { timeout: 15000 });
    javaText = (java.stderr || Buffer.alloc(0)).toString();
  } catch {}

  if (!/version\s+"21\./.test(javaText)) {
    await studioLog("dependencies", "Installing Java 21 and LLVM analysis tools.", 53, "analyzing");
    const update = await runStreaming(["sudo", "apt-get", "update", "-qq"], {
      phase: "dependencies", progress: 53, timeout: 180000, logPath: join(tmpDir, "apt-update.log")
    });
    if (update.status !== 0) throw new Error("dependency update failed");
    const install = await runStreaming(["sudo", "apt-get", "install", "-y", "-qq", "openjdk-21-jdk-headless", "llvm", "unzip"], {
      phase: "dependencies", progress: 54, timeout: 300000, logPath: join(tmpDir, "apt-install.log")
    });
    if (install.status !== 0) throw new Error("dependency installation failed");
    return;
  }

  let llvmReady = false;
  try {
    const llvm = run(["llvm-objdump", "--version"], { timeout: 15000 });
    llvmReady = !llvm.error && llvm.status === 0;
  } catch {}
  if (!llvmReady) {
    await studioLog("dependencies", "Installing LLVM analysis tools.", 54, "analyzing");
    const update = await runStreaming(["sudo", "apt-get", "update", "-qq"], {
      phase: "dependencies", progress: 54, timeout: 180000, logPath: join(tmpDir, "apt-update.log")
    });
    if (update.status !== 0) throw new Error("dependency update failed");
    const install = await runStreaming(["sudo", "apt-get", "install", "-y", "-qq", "llvm", "unzip"], {
      phase: "dependencies", progress: 55, timeout: 300000, logPath: join(tmpDir, "apt-install.log")
    });
    if (install.status !== 0) throw new Error("dependency installation failed");
  }
}

async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function installGhidra() {
  const archive = join(tmpDir, "ghidra.zip");
  const root = join(tmpDir, "ghidra_12.1.4_PUBLIC");
  if (!existsSync(root)) {
    const url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip";
    await studioLog("ghidra_install", "Downloading the pinned Ghidra release.", 55, "analyzing");
    const response = await fetch(url, { signal: AbortSignal.timeout(15 * 60 * 1000) });
    if (!response.ok || !response.body) throw new Error("analysis tool download failed");
    const expectedLength = Number(response.headers.get("content-length") || 0);
    const maxGhidraBytes = 1024 * 1024 * 1024;
    if (expectedLength > maxGhidraBytes) throw new Error("analysis tool download size limit exceeded");
    const stream = createWriteStream(archive, { flags: "w", mode: 0o600 });
    let downloaded = 0;
    let lastProgress = Date.now();
    await new Promise(async (resolvePromise, rejectPromise) => {
      try {
        const reader = response.body.getReader();
        stream.on("error", rejectPromise);
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          downloaded += value.byteLength;
          if (downloaded > maxGhidraBytes) {
            await reader.cancel();
            throw new Error("analysis tool download size limit exceeded");
          }
          if (!stream.write(Buffer.from(value))) await new Promise(r => stream.once("drain", r));
          if (Date.now() - lastProgress >= 15000) {
            const mb = (downloaded / (1024 * 1024)).toFixed(0);
            const total = expectedLength ? " / " + (expectedLength / (1024 * 1024)).toFixed(0) + " MB" : " MB downloaded";
            await studioLog("ghidra_install", "Ghidra download: " + mb + total + ".", 56, "analyzing");
            lastProgress = Date.now();
          }
        }
        stream.end(resolvePromise);
      } catch (error) {
        stream.destroy();
        rejectPromise(error);
      }
    });
    const digest = await sha256(archive);
    if (digest !== "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db") {
      throw new Error("analysis tool integrity check failed");
    }
    await studioLog("ghidra_install", "Archive checksum verified. Extracting Ghidra.", 58, "analyzing");
    const unpack = await runStreaming(["unzip", "-q", archive, "-d", tmpDir], {
      phase: "ghidra_install", progress: 58, timeout: 180000, logPath: join(tmpDir, "ghidra-unzip.log")
    });
    if (unpack.status !== 0) throw new Error("analysis tool extraction failed");
  }
  return join(root, "support", "analyzeHeadless");
}

async function studioCloud(action, extra = {}) {
  const response = await studioFetch("/api/redteam/cloud", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, ...extra }),
  }, action === "start" ? 1 : 3);
  return response.json();
}

async function cloudRuns() {
  const data = await studioCloud("runs");
  return Array.isArray(data?.data) ? data.data : [];
}

async function buildRun(id) {
  const data = await studioCloud("build", { id });
  return data?.data;
}

async function startBuild() {
  const data = await studioCloud("start");
  if (!data?.data?.id) throw new Error("cloud build could not be started");
  return data.data;
}

async function getArchive(id) {
  const data = await studioCloud("archive", { id });
  const url = data?.artifact?.downloadUrl;
  if (typeof url !== "string") throw new Error("archive download unavailable");
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) throw new Error("archive URL rejected");
  return parsed.toString();
}

async function waitForBuild(id, expectedSha) {
  let current = await buildRun(id);
  if (!current) throw new Error("cloud build unavailable");
  const deadline = Date.now() + 3 * 60 * 60 * 1000;
  while (!terminal(current) && Date.now() < deadline) {
    await new Promise(resolvePromise => setTimeout(resolvePromise, 60000));
    current = await buildRun(id);
    if (!current) throw new Error("cloud build unavailable");
    const state = progress(current) || completion(current) || "RUNNING";
    const pct = ["COMPLETE", "COMPLETED", "FINISHED"].includes(state) ? 48 : 10;
    await studioLog("cloud_build", "Xcode Cloud: " + state.toLowerCase() + ".", pct, "waiting_build");
  }
  if (!terminal(current)) throw new Error("cloud build timeout");
  const actualSha = commitShaFrom(current);
  if (!successful(current)) throw new Error("cloud build failed");
  if (!actualSha) throw new Error("cloud build source commit unavailable");
  if (actualSha !== expectedSha.toLowerCase()) throw new Error("cloud build commit mismatch");
  await studioLog("cloud_build", "Release build completed for the expected source commit.", 48, "analyzing");
  return { run: current, actualSha };
}

const MAX_ARCHIVE_BYTES = 1536 * 1024 * 1024;

async function download(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) throw new Error("archive URL rejected");
  const response = await fetch(parsed, { redirect: "follow", signal: AbortSignal.timeout(20 * 60 * 1000) });
  if (!response.ok || !response.body) throw new Error("archive download failed");
  const finalUrl = new URL(response.url || parsed.toString());
  if (finalUrl.protocol !== "https:" || finalUrl.username || finalUrl.password) throw new Error("archive redirect rejected");
  const contentLength = Number(response.headers.get("content-length") || 0);
  if (contentLength > MAX_ARCHIVE_BYTES) throw new Error("archive exceeds size limit");

  const destination = join(tmpDir, "build-artifact");
  const stream = createWriteStream(destination, { flags: "w", mode: 0o600 });
  const reader = response.body.getReader();
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_ARCHIVE_BYTES) {
        await reader.cancel();
        throw new Error("archive exceeds size limit");
      }
      if (!stream.write(Buffer.from(value))) {
        await new Promise((resolvePromise, rejectPromise) => {
          stream.once("drain", resolvePromise);
          stream.once("error", rejectPromise);
        });
      }
    }
    await new Promise((resolvePromise, rejectPromise) => {
      stream.once("error", rejectPromise);
      stream.once("finish", resolvePromise);
      stream.end();
    });
  } catch (error) {
    stream.destroy();
    await rm(destination, { force: true }).catch(() => {});
    throw error;
  }
  if (total < 4) throw new Error("archive is empty or invalid");
  return destination;
}

async function extract(archive) {
  const dir = join(tmpDir, "extracted");
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  const script = String.raw`import os, pathlib, stat, sys, tarfile, zipfile
src, dst = sys.argv[1], sys.argv[2]
limit = 8 * 1024 * 1024 * 1024

def safe_name(name):
    if not name or name.startswith(("/", chr(92))) or chr(92) in name:
        raise ValueError("unsafe archive path")
    parts = name.split("/")
    if any(part == ".." for part in parts) or (parts and ":" in parts[0]):
        raise ValueError("unsafe archive path")

if zipfile.is_zipfile(src):
    with zipfile.ZipFile(src) as z:
        total = 0
        for item in z.infolist():
            safe_name(item.filename)
            mode = (item.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError("archive symlinks are not accepted")
            total += item.file_size
            if total > limit:
                raise ValueError("archive expansion limit exceeded")
        z.extractall(dst)
elif tarfile.is_tarfile(src):
    with tarfile.open(src, "r:*") as t:
        total = 0
        for item in t.getmembers():
            safe_name(item.name)
            if not (item.isfile() or item.isdir()):
                raise ValueError("archive links and special files are not accepted")
            total += max(0, item.size)
            if total > limit:
                raise ValueError("archive expansion limit exceeded")
        t.extractall(dst)
else:
    raise ValueError("unsupported archive format")
`;
  const result = await runStreaming(["python3", "-c", script, archive, dir], {
    phase: "archive", progress: 54, timeout: 300000, logPath: join(tmpDir, "archive-extract.log")
  });
  if (result.status !== 0) throw new Error("archive extraction failed");
  return dir;
}

function publicSummary(publicAudit, ghidraRows, sourceChanged, actualSha) {
  const p = publicAudit.public;
  const g = ghidraRows.filter(Boolean);
  const totalFunctions = g.reduce((n, row) => n + (row.function_count || 0), 0);
  const selected = g.reduce((n, row) => n + (row.selected_function_count || 0), 0);
  const decompiled = g.reduce((n, row) => n + (row.decompiled_function_count || 0), 0);
  const nontrivial = g.reduce((n, row) => n + (row.nontrivial_decompilation_count || 0), 0);
  const semantic = g.reduce((n, row) => n + (row.semantic_name_count || 0), 0);
  const ghidraFailures = g.filter(row => row.analysis_status === "failed").length;
  const risks = [];
  if (p.encrypted_flags) risks.push("encrypted-input");
  if (p.debug_sections || p.llvm_sections) risks.push("build-metadata-exposure");
  if (p.writable_executable_segments) risks.push("writable-executable-memory");
  if (p.test_framework_links) risks.push("test-framework-link");
  if (p.absolute_path_strings || p.debug_path_strings) risks.push("host-path-exposure");
  if (p.secret_shapes) risks.push("secret-shaped-material");
  if (p.string_scan_truncated_count) risks.push("string-scan-truncated");
  if (p.tool_failure_count) risks.push("binary-tool-failure");
  if (p.export_commands && p.defined_symbols) risks.push("symbol-surface");
  if (ghidraFailures) risks.push("ghidra-analysis-incomplete");
  const decompRate = selected ? decompiled / selected : 0;
  const semanticRate = totalFunctions ? semantic / totalFunctions : 0;
  return {
    schema: 1,
    source_changed: sourceChanged,
    images: p.image_count,
    image_bytes: p.total_image_bytes,
    swift_sections: p.swift_sections,
    objc_metadata_sections: p.objc_metadata_sections,
    debug_sections: p.debug_sections,
    llvm_sections: p.llvm_sections,
    function_start_commands: p.function_start_commands,
    export_commands: p.export_commands,
    code_signature_commands: p.code_signature_commands,
    encryption_commands: p.encryption_commands,
    encrypted_flags: p.encrypted_flags,
    rpaths: p.rpaths,
    test_framework_links: p.test_framework_links,
    writable_executable_segments: p.writable_executable_segments,
    defined_symbols: p.defined_symbols,
    undefined_symbols: p.undefined_symbols,
    strings: p.strings,
    url_strings: p.url_strings,
    absolute_path_strings: p.absolute_path_strings,
    debug_path_strings: p.debug_path_strings,
    string_scan_truncated_count: p.string_scan_truncated_count || 0,
    string_scan_failed_count: p.string_scan_failed_count || 0,
    tool_failure_count: p.tool_failure_count || 0,
    secret_shapes: p.secret_shapes,
    ghidra_images: g.length,
    ghidra_analyzed_images: g.length - ghidraFailures,
    ghidra_failed_images: ghidraFailures,
    ghidra_functions: totalFunctions,
    ghidra_selected_functions: selected,
    ghidra_decompiled_functions: decompiled,
    ghidra_nontrivial_decompilations: nontrivial,
    ghidra_decompilation_rate: Number(decompRate.toFixed(4)),
    ghidra_semantic_name_count: semantic,
    ghidra_semantic_name_rate: Number(semanticRate.toFixed(4)),
    risk_flags: risks,
    engine: "macho-release-v1"
  };
}

async function encryptPrivate(path, runId) {
  const publicKey = await fetchPublicFile("tools/redteam-report-public.pem");
  if (createHash("sha256").update(publicKey).digest("hex") !== PUBLIC_KEY_SHA256) {
    throw new Error("report key integrity check failed");
  }
  const plaintext = await readFile(path);
  if (plaintext.length > 16 * 1024 * 1024) throw new Error("report exceeds plaintext size limit");
  const compressed = gzipSync(plaintext);
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);
  const aad = Buffer.from("redteam:" + runId, "utf8");
  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const tag = cipher.getAuthTag();
  const wrappedKey = publicEncrypt({
    key: publicKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
  }, aesKey);
  const envelope = Buffer.from(JSON.stringify({
    v: 1,
    alg: "RSA-OAEP-256/AES-256-GCM",
    compression: "gzip",
    key: wrappedKey.toString("base64url"),
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    aad: aad.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  }) + "\n", "utf8");
  if (envelope.length > 25 * 1024 * 1024) throw new Error("report exceeds upload size limit");
  const encrypted = join(outDir, "details.enc");
  await writeFile(encrypted, envelope);
  return { path: encrypted, sha256: createHash("sha256").update(envelope).digest("hex"), bytes: envelope.length };
}

async function uploadPrivateReport(encrypted) {
  const body = await readFile(encrypted.path);
  const response = await studioFetch("/api/redteam/ingest", {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Run-Id": required("GITHUB_RUN_ID"),
      "X-Runner-Sha": publicSha,
      "X-Report-SHA256": encrypted.sha256,
    },
    body,
  });
  return response.json();
}

function failureMessage(error) {
  const message = error instanceof Error ? error.message : "";
  if (message.includes("for /api/redteam/source")) return "Studio could not resolve the private source snapshot or red-team policy.";
  if (message.includes("source snapshot invalid")) return "Studio returned an invalid private-source snapshot.";
  if (message.includes("for /api/redteam/cloud")) return "Studio could not complete the Xcode Cloud API request. Check App Store Connect credentials and Release workflow selection.";
  if (message.includes("for /api/redteam/ingest") && message.includes("(422)")) return "Studio rejected the encrypted report. Check the report-key match, source-commit binding, and report schema.";
  if (message.includes("for /api/redteam/ingest") && message.includes("(413)")) return "The encrypted report exceeded Studio’s request-size limit.";
  if (message.includes("studio request failed (401)") || message.includes("studio request failed (403)")) return "Studio rejected the workflow identity or report request.";
  if (message.includes("studio request failed")) return "Studio did not accept a workflow update (HTTP " + ((message.match(/\((\d{3})\)/) || [])[1] || "unknown") + ").";
  if (message.includes("cloud build timeout")) return "Xcode Cloud did not finish within the three-hour wait window.";
  if (message.includes("cloud build commit mismatch")) return "Xcode Cloud built a different source commit; the report was not accepted.";
  if (message.includes("cloud build failed")) return "The Xcode Cloud Release build failed.";
  if (message.includes("archive download failed") || message.includes("archive download unavailable")) return "The Xcode Cloud archive download failed.";
  if (message.includes("archive URL rejected") || message.includes("archive redirect rejected")) return "Xcode Cloud returned an archive URL that did not pass the HTTPS safety check.";
  if (message.includes("cloud build unavailable")) return "Xcode Cloud returned no build details for the requested run.";
  if (message.includes("analysis tool download failed")) return "The pinned Ghidra release could not be downloaded.";
  if (message.includes("archive extraction failed")) return "The downloaded archive was invalid or exceeded safe extraction limits.";
  if (message.includes("archive exceeds size limit")) return "The downloaded archive exceeded the configured size limit.";
  if (message.includes("analysis tool integrity check failed")) return "The Ghidra archive did not match the pinned release checksum.";
  if (message.includes("analysis tool download size limit")) return "The Ghidra download exceeded the configured size limit.";
  if (message.includes("cloud build source commit unavailable")) return "Xcode Cloud did not expose a verifiable source commit for the build.";
  if (message.includes("report key integrity check failed")) return "The report encryption key fingerprint does not match.";
  if (message.includes("report exceeds")) return "The detailed report exceeded the safe upload size limit.";
  if (message.includes("binary audit failed")) return "The Mach-O audit did not produce a valid result.";
  if (message.includes("dependency update failed") || message.includes("dependency installation failed")) return "The analysis tool dependencies could not be installed.";
  if (message.includes("analysis process timeout")) return "A long-running analysis process exceeded its time limit.";
  if (message.includes("analysis output size limit exceeded")) return "The binary-audit output exceeded the safe size limit; no partial report was accepted.";
  if (message.includes("no Mach-O images found")) return "No Mach-O executable images were found in the extracted Release app."; 
  if (message.includes("analysis tool extraction failed")) return "The verified Ghidra archive could not be extracted.";
  return "The run failed during " + currentPhase.replace(/_/g, " ") + ". Check the detailed run log.";
}

async function main() {
  let studioStarted = false;
  try {
    const state = await studioState();
    await studioEvent("start", {
      phase: "checking",
      progress: 1,
      message: "Nightly baseline check started.",
    });
    studioStarted = true;

    if (state?.active) {
      await studioEvent("skip", {
        phase: "checking",
        progress: 100,
        message: "Another baseline run is already active.",
      });
      await status("already_running", { reason: "another_run_active" });
      return 0;
    }

    const source = await studioSourceSnapshot();
    const latest = source.latest;
    const changedFiles = source.changedFiles;
    const policy = { analysis: source.analysis };
    await studioEvent("start", {
      source_commit: latest,
      phase: "checking",
      progress: 2,
      message: "Source commit and audit policy resolved by Studio.",
    });

    if (!source.shouldRun) {
      await studioEvent("skip", {
        source_commit: latest,
        phase: "baseline",
        progress: 100,
        message: source.baseline === latest
          ? "The latest completed baseline already matches this App commit."
          : "No App or Release-build input changed since the last baseline.",
      });
      await status("no_change", { reason: source.baseline === latest ? "baseline_current" : "no_app_code_change" });
      return 0;
    }

    if (source.compareUncertain) {
      await studioLog("baseline", "Source comparison was incomplete; running the audit conservatively.", 4, "checking");
    } else if (source.baseline) {
      await studioLog("baseline", "App or Release-build inputs changed since the last completed baseline.", 4, "checking");
    }

    const runs = await cloudRuns();
    const active = runs.find(row => commitShaFrom(row) === latest && !terminal(row));
    let runRow = active;
    if (!runRow) runRow = await startBuild();
    const buildId = runRow.id;
    await studioPhase("cloud_build", active ? "Reusing the active Xcode Cloud Release build." : "Started an Xcode Cloud Release build.", 8, "waiting_build");
    const completed = await waitForBuild(buildId, latest);
    const actualSha = completed.actualSha;
    await studioPhase("archive", "Release build completed. Retrieving the archive.", 48, "analyzing");
    const archiveUrl = await getArchive(buildId);
    const archive = await download(archiveUrl);
    await studioLog("archive", "Archive retrieved.", 52);
    const extracted = await extract(archive);

    const apps = await treeFind(extracted, (path, entry) =>
      entry.isDirectory() && path.endsWith(".app"), 100);
    if (!apps.length) throw new Error("app bundle unavailable");
    const preferred = apps.find(path => /Products[\\/]Applications[\\/]/.test(path)) || apps[0];

    await installTools();
    await studioPhase("binary_audit", "Running the Mach-O release audit.", 56, "analyzing");
    const auditSource = await fetchPublicFile("audit.py");
    const summarySource = await fetchPublicFile("Summary.java");
    const auditPath = join(tmpDir, "audit.py");
    const summaryPath = join(tmpDir, "Summary.java");
    await writeFile(auditPath, auditSource);
    await writeFile(summaryPath, summarySource);

    const auditResult = await runStreaming(["python3", auditPath, preferred], {
      phase: "binary_audit",
      progress: 56,
      timeout: 900000,
      captureStdout: true,
      maxCaptureBytes: 12 * 1024 * 1024,
      logPath: join(tmpDir, "binary-audit.log")
    });
    if (auditResult.status !== 0) throw new Error("binary audit failed");
    const auditPayload = JSON.parse(auditResult.stdout.toString("utf8"));

    const ghidra = await installGhidra();
    const machos = [];
    for (const path of await treeFind(preferred, (path, entry) => entry.isFile(), 4000)) {
      const fd = openSync(path, "r");
      const header = Buffer.alloc(4);
      let bytesRead = 0;
      try { bytesRead = readSync(fd, header, 0, header.length, 0); } catch {} finally { closeSync(fd); }
      const head = header.subarray(0, bytesRead);
      if ([Buffer.from([0xcf,0xfa,0xed,0xfe]), Buffer.from([0xfe,0xed,0xfa,0xcf]),
           Buffer.from([0xca,0xfe,0xba,0xbe]), Buffer.from([0xbe,0xba,0xfe,0xca])].some(m => head.equals(m))) {
        machos.push(path);
      }
    }
    if (!machos.length) throw new Error("no Mach-O images found");
    const configuredMaxImages = Number(policy.analysis?.maxMachOImages);
    const maxImages = Number.isFinite(configuredMaxImages) && configuredMaxImages > 0
      ? Math.min(12, Math.max(1, Math.floor(configuredMaxImages)))
      : 12;
    const selectedMachos = machos.slice(0, maxImages);
    const ghidraRows = [];

    for (let i = 0; i < selectedMachos.length; i++) {
      const input = selectedMachos[i];
      await studioPhase("ghidra", "Analyzing Mach-O image " + (i + 1) + " of " + selectedMachos.length + ".", 60 + Math.floor((i / Math.max(1, selectedMachos.length)) * 30), "analyzing");
      const projectDir = join(tmpDir, "g-" + i);
      await mkdir(projectDir, { recursive: true });
      const rowPath = join(tmpDir, "g-" + i + ".json");
      const logPath = join(tmpDir, "g-" + i + ".log");
      const configuredMinutes = Number(policy.analysis?.maxGhidraMinutesPerImage);
      const maxGhidraMinutes = Number.isFinite(configuredMinutes) && configuredMinutes > 0
        ? Math.min(7, Math.max(1, configuredMinutes))
        : 5;
      const relativeImage = input.slice(preferred.length).replace(/^\/+/, "") || input.split("/").pop() || "unknown-image";
      let result = { status: 1 };
      let processErrorCode = null;
      try {
        result = await runStreaming([ghidra, projectDir, "p" + i, "-import", input,
          "-scriptPath", tmpDir, "-postScript", "Summary.java", rowPath,
          "-analysisTimeoutPerFile", String(maxGhidraMinutes * 60),
          "-deleteProject"], {
          phase: "ghidra",
          progress: 60 + Math.floor((i / Math.max(1, selectedMachos.length)) * 30),
          timeout: 8 * 60 * 1000,
          logPath
        });
      } catch (error) {
        processErrorCode = error instanceof Error && error.message.includes("timeout") ? "process_timeout" : "process_error";
      }

      let row = null;
      if (result.status === 0 && existsSync(rowPath)) {
        try {
          const parsed = JSON.parse(await readFile(rowPath, "utf8"));
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) row = parsed;
        } catch {}
      }
      if (row) {
        row.image = relativeImage;
        row.analysis_status = "completed";
        ghidraRows.push(row);
      } else {
        ghidraRows.push({
          image: relativeImage,
          analysis_status: "failed",
          error_code: processErrorCode || (result.status === 0 ? "summary_invalid" : "process_failed"),
          function_count: 0,
          selected_function_count: 0,
          decompiled_function_count: 0,
          nontrivial_decompilation_count: 0,
          semantic_name_count: 0
        });
      }
    }

    await studioPhase("report", "Building and encrypting the detailed report.", 94, "finalizing");
    const summary = publicSummary(auditPayload, ghidraRows, true, actualSha);
    const privateReport = {
      schema: 1,
      observed_at: new Date().toISOString(),
      source_commit: actualSha,
      detected_latest_commit: latest,
      changed_files: changedFiles,
      build_run_id: buildId,
      audit: auditPayload.private,
      ghidra: ghidraRows,
      summary
    };

    const privatePath = join(tmpDir, "details.json");
    await writeFile(privatePath, safeJson(privateReport));
    const encrypted = await encryptPrivate(privatePath, workflowRunId());
    const uploaded = await uploadPrivateReport(encrypted);
    await rm(privatePath, { force: true });

    await writeFile(join(outDir, "summary.json"), safeJson(summary));
    await writeFile(join(outDir, "status.json"), safeJson({
      schema: 1,
      status: "completed",
      encrypted_details: true,
      report_uploaded: Boolean(uploaded?.ok),
      ghidra_images: ghidraRows.length,
      risk_flags: summary.risk_flags
    }));

    return 0;
  } catch (error) {
    if (studioStarted) {
      try {
        await studioEvent("fail", {
          phase: "failed",
          progress: 100,
          message: failureMessage(error),
        }, false);
      } catch {}
    }
    await status("failed", { reason: "run_failed" });
    return 1;
  }
}

process.exitCode = await main();
