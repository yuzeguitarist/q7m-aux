import json
import os
from pathlib import Path
import subprocess
import sys
import time

config = json.loads(Path("fixture-config.json").read_text())
checks = []


def require(name, condition):
    if not condition:
        raise RuntimeError("assertion failed: " + name)
    checks.append(name)


def command(args, timeout=180):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def succeeds(args, timeout=180):
    result = command(args, timeout)
    require("command " + Path(args[0]).name, result.returncode == 0)
    return result.stdout


for name in os.environ:
    require("filtered environment", not name.startswith(("GITHUB", "ACTIONS", "RUNNER", "CI_RELAY",
            "CI_SOURCE_READ", "CI_CALLBACK", "CI_RESULT", "ISOLATION_SMOKE_PARENT_CANARY")))
canary = "ISOLATION_SMOKE_PARENT_CANARY=synthetic-public-fixture-not-a-secret"
result = {"platform": sys.argv[1], "uid": os.getuid(), "home": os.environ["HOME"]}
require("host file denied", not os.access(config["hostCanary"], os.R_OK))
try:
    write_probe = Path("workspace-write-probe")
    write_probe.write_text("synthetic-value-not-a-secret")
    write_probe.unlink()
    checks.append("workspace write and delete")
except PermissionError as error:
    raise RuntimeError("workspace write denied: uid=" + str(os.getuid())
                       + " owner=" + str(Path.cwd().stat().st_uid)) from error

if sys.argv[1] == "macos":
    require("different uid", os.getuid() != config["hostUid"])
    require("different home", os.environ["HOME"] != config["hostHome"])
    require("owned home", Path.home().stat().st_uid == os.getuid())
    require("non-admin", "admin" not in succeeds(["/usr/bin/id", "-Gn"]).split())
    require("no sudo", command(["/usr/bin/sudo", "-n", "/usr/bin/id", "-u"]).returncode != 0)
    require("parent environment denied", canary not in command(
        ["/bin/ps", "eww", "-p", str(config["parentPid"])]).stdout)
    own = succeeds(["/usr/bin/security", "default-keychain", "-d", "user"]).strip().strip('"')
    require("own default keychain", own == str(Path.home() / "Library/Keychains/login.keychain-db"))
    succeeds(["/usr/bin/security", "add-generic-password", "-U", "-a", "synthetic", "-s", "smoke-own",
              "-w", "synthetic-value-not-a-secret", own])
    require("own keychain readback", succeeds(["/usr/bin/security", "find-generic-password", "-a", "synthetic",
            "-s", "smoke-own", "-w", own]).strip() == "synthetic-value-not-a-secret")
    require("host keychain denied", command(["/usr/bin/security", "find-generic-password", "-a", "synthetic",
            "-s", "smoke-host", "-w", config["hostKeychain"]]).returncode != 0)
    if config["mode"] == "success":
        succeeds(["/usr/bin/xcrun", "swiftc", "keychain-probe.swift", "-o", "keychain-probe"])
        succeeds([str(Path.cwd() / "keychain-probe")])
        devices = json.loads(succeeds(["/usr/bin/xcrun", "simctl", "list", "devices", "--json"]))
        ids = [d["udid"] for group in devices["devices"].values() for d in group]
        require("host simulator invisible", config["hostSimulator"] not in ids)
        simulator = succeeds(["/usr/bin/xcrun", "simctl", "create", "Isolation child fixture",
                              config["simulatorType"], config["simulatorRuntime"]]).strip()
        succeeds(["/usr/bin/xcrun", "simctl", "boot", simulator])
        succeeds(["/usr/bin/xcrun", "simctl", "bootstatus", simulator, "-b"])
        require("own simulator set", (Path.home() / "Library/Developer/CoreSimulator/Devices" / simulator).exists())
        result["simulator"] = simulator
else:
    require("checkout owner uid", os.getuid() == config["hostUid"])
    require("disposable home", os.environ["HOME"] == "/tmp")
    require("different pid namespace", os.readlink("/proc/self/ns/pid") != config["hostPidNamespace"])
    require("different mount namespace", os.readlink("/proc/self/ns/mnt") != config["hostMountNamespace"])
    require("no docker socket", not Path("/var/run/docker.sock").exists())
    status = Path("/proc/self/status").read_text().splitlines()
    fields = dict(line.split(":", 1) for line in status if ":" in line)
    require("all capabilities dropped", int(fields["CapEff"].strip(), 16) == 0)
    require("no new privileges", fields["NoNewPrivs"].strip() == "1")
    require("memory limit", Path("/sys/fs/cgroup/memory.max").read_text().strip() == str(6 * 1024**3))
    require("pid limit", Path("/sys/fs/cgroup/pids.max").read_text().strip() == "512")
    quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
    require("cpu limit", quota != "max" and int(quota) == 2 * int(period))
    for process in Path("/proc").glob("[0-9]*/environ"):
        try:
            require("parent environment invisible", canary.encode() not in process.read_bytes())
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass

# A deliberately surviving subprocess tests teardown rather than shell exit alone.
background = subprocess.Popen(["/bin/sleep", "600"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
result["backgroundPid"] = background.pid
result["checks"] = sorted(set(checks))
print("SMOKE_JSON:" + json.dumps(result), flush=True)
if config["mode"] == "hold":
    Path(config["readyPath"]).write_text(json.dumps(result))
    while True:
        time.sleep(1)
sys.exit(17 if config["mode"] == "failure" else 0)

