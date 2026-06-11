import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import net from "node:net";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const nextBin = path.join(projectRoot, "node_modules", "next", "dist", "bin", "next");
const port = process.env.PORT || "3001";
const devDir = path.join(projectRoot, ".next-dev");
const pidFile = path.join(devDir, "dev-server.pid");
const reset = process.argv.includes("--reset");

function removePidFile() {
  try {
    fs.rmSync(pidFile, { force: true });
  } catch {
    // ignore cleanup failures
  }
}

function isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function isPortOpen(host, openPort) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port: Number(openPort) });

    const finish = (result) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(400);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

if (reset) {
  fs.rmSync(path.join(projectRoot, ".next"), { recursive: true, force: true });
  fs.rmSync(devDir, { recursive: true, force: true });
}

fs.mkdirSync(devDir, { recursive: true });

if (fs.existsSync(pidFile)) {
  const existingPid = Number(fs.readFileSync(pidFile, "utf8").trim());
  if (Number.isFinite(existingPid) && isProcessAlive(existingPid)) {
    console.log(`Dev server already running on http://localhost:${port} (pid ${existingPid}).`);
    process.exit(0);
  }
  removePidFile();
}

if (await isPortOpen("127.0.0.1", port) || await isPortOpen("::1", port)) {
  console.log(`Dev server already available on http://localhost:${port}.`);
  process.exit(0);
}

const child = spawn(process.execPath, [nextBin, "dev", "-p", String(port)], {
  cwd: projectRoot,
  env: process.env,
  stdio: "inherit",
});

fs.writeFileSync(pidFile, `${child.pid}\n`, "utf8");

const shutdown = (signal) => {
  removePidFile();
  if (!child.killed) {
    child.kill(signal);
  }
};

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

child.on("exit", (code, signal) => {
  removePidFile();
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});