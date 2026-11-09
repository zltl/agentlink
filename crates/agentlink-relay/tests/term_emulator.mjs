#!/usr/bin/env node
// Regression: dashboard createTerm must not print charset designators.
// Run from repo root or crate root; path is resolved relative to this file.
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";

const here = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(here, "../src/dashboard.html");
const html = fs.readFileSync(htmlPath, "utf8");
const start = html.indexOf("function createTerm(el)");
const end = html.indexOf("async function startTerminal");
if (start < 0 || end < 0) {
  console.error("createTerm not found in dashboard.html");
  process.exit(1);
}
const fnSrc = html.slice(start, end).trim();

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

globalThis.window = { ResizeObserver: null };
const probe = { getBoundingClientRect() { return { width: 8.4, height: 19 }; } };
globalThis.document = {
  getElementById(id) {
    return id === "term-probe" ? probe : null;
  },
};
// eslint-disable-next-line no-eval
eval(fnSrc + "\n; globalThis.__createTerm = createTerm;");

function screenText(el) {
  return el.innerHTML
    .split(/<\/div>/)
    .map((l) =>
      l
        .replace(/<[^>]+>/g, "")
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
    )
    .join("\n");
}

function freshEl() {
  return {
    scrollTop: 0,
    scrollHeight: 2000,
    clientHeight: 24 * 19,
    innerHTML: "",
    getBoundingClientRect() {
      return { width: 80 * 8.4 + 24, height: 24 * 19 + 20 };
    },
  };
}

{
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  t.write(new TextEncoder().encode("\x1b[2J\x1b[H\x1b(Bhello\x1b(B world"));
  const first = screenText(el)
    .split("\n")
    .find((l) => l.trim().length);
  if (!first || !first.includes("hello world") || first.includes("Bhello")) {
    console.error("charset unit failed:", JSON.stringify(first));
    process.exit(1);
  }
}

{
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  t.write(new TextEncoder().encode("\x1b[2J\x1b[H\x1b[7mX\x1b[0m"));
  if (!/background:#241814/.test(el.innerHTML)) {
    console.error("reverse video failed:", el.innerHTML.slice(0, 240));
    process.exit(1);
  }
}

// 256-color SGR: 38;5;196 is the pure-red cube entry. The palette index and
// selector must not leak through as lone SGR codes (e.g. underline).
{
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  t.write(new TextEncoder().encode("\x1b[2J\x1b[H\x1b[38;5;196mX\x1b[0mZ"));
  if (!/<span[^>]*style="[^"]*color:#ff0000;[^"]*"[^>]*>X<\/span>/.test(el.innerHTML)) {
    console.error("256-color fg failed:", el.innerHTML.slice(0, 400));
    process.exit(1);
  }
  if (!/<span>Z<\/span>/.test(el.innerHTML)) {
    console.error("256-color reset leaked:", el.innerHTML.slice(0, 400));
    process.exit(1);
  }
}

// 256-color background: 48;5;196.
{
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  t.write(new TextEncoder().encode("\x1b[2J\x1b[H\x1b[48;5;196mX\x1b[0m"));
  if (!/<span[^>]*style="[^"]*background:#ff0000;[^"]*"[^>]*>X<\/span>/.test(el.innerHTML)) {
    console.error("256-color bg failed:", el.innerHTML.slice(0, 400));
    process.exit(1);
  }
}

// Truecolor SGR: ESC[38;2;255;128;0m is orange (#ff8000).
{
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  t.write(new TextEncoder().encode("\x1b[2J\x1b[H\x1b[38;2;255;128;0mY\x1b[0m"));
  if (!/<span[^>]*style="[^"]*color:#ff8000;[^"]*"[^>]*>Y<\/span>/.test(el.innerHTML)) {
    console.error("truecolor fg failed:", el.innerHTML.slice(0, 400));
    process.exit(1);
  }
}

// Synthetic stream matching procps top: ESC ( B before every SGR reset.
{
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  const sample =
    "\x1b[?1h\x1b[?25l\x1b[H\x1b[2J\x1b[7m%Cpu\x1b[27m\x1b(B\x1b[m" +
    "\x1b(B\x1b[m line\r\n" +
    "\x1b(B\x1b[1mPID\x1b(B\x1b[m USER\r\n" +
    "\x1b(B\x1b[m  123 root\x1b[K\r\n";
  t.write(new TextEncoder().encode(sample));
  const text = screenText(el);
  const lines = text.split("\n").map((l) => l.replace(/\s+$/, ""));
  const junk = lines.filter((l) => /^B\s/.test(l) || l.trim() === "B");
  if (junk.length) {
    console.error("synthetic top charset junk:", junk.slice(0, 5), lines.slice(0, 8));
    process.exit(1);
  }
  if (!text.includes("%Cpu") || !text.includes("PID USER")) {
    console.error("synthetic top content missing", lines.slice(0, 8));
    process.exit(1);
  }
}

// Optional live top on Unix when python3+pty+top exist.
const py = spawnSync(
  "python3",
  [
    "-c",
    `
import os, shutil, sys
if os.name != "posix" or not shutil.which("top"):
    sys.exit(0)
import pty, select, time, fcntl, struct, termios
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    fcntl.ioctl(1, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    os.execvp("top", ["top", "-n", "1"])
data = b""
end = time.time() + 1.5
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if fd in r:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    w = os.waitpid(pid, os.WNOHANG)
    if w[0] != 0 and not r:
        break
sys.stdout.buffer.write(data)
`,
  ],
  { encoding: null, maxBuffer: 10_000_000 }
);
if (!py.error && py.status === 0 && py.stdout && py.stdout.length > 0) {
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  t.write(py.stdout);
  const text = screenText(el);
  const lines = text.split("\n");
  const junk = lines.filter((l) => /^B\s+\d+/.test(l) || /^ B\s*$/.test(l));
  if (junk.length) {
    console.error("live top charset junk:", junk.slice(0, 5));
    process.exit(1);
  }
  if (!/(Tasks:|%Cpu|PID USER|top -)/.test(text)) {
    console.error("live top content missing");
    process.exit(1);
  }
}


// ESC 7 / ESC 8 — DECSC / DECRC save and restore cursor (+ attrs).
{
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  t.write(new TextEncoder().encode("\x1b[2J\x1b[H\x1b[1;3HAB\x1b7\x1b[5;10HXY\x1b8Z"));
  const row0 = t.screen[0].map((c) => c.ch).join("").replace(/\s+$/, "");
  if (!row0.includes("ABZ")) {
    console.error("ESC 7/8 restore failed row0:", JSON.stringify(row0), "x,y=", t.x, t.y);
    process.exit(1);
  }
  // After restore + Z: cursor sits just past ABZ on row 0.
  if (t.y !== 0 || t.x !== 5) {
    console.error("ESC 8 cursor pos:", t.y, t.x);
    process.exit(1);
  }
  const row4 = t.screen[4].map((c) => c.ch).join("");
  if (row4.includes("Z")) {
    console.error("ESC 8 left Z on row4:", JSON.stringify(row4));
    process.exit(1);
  }
}

// CSI S — scroll up moves top screen line into scrollback; cursor stays.
{
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  t.write(new TextEncoder().encode("\x1b[2J\x1b[Hline1\r\nline2\r\nline3"));
  const yBefore = t.y;
  t.write(new TextEncoder().encode("\x1b[1S"));
  const top = t.screen[0].map((c) => c.ch).join("").replace(/\s+$/, "");
  const sb = t.scrollback.map((line) => line.map((c) => c.ch).join("").replace(/\s+$/, ""));
  if (top !== "line2") {
    console.error("CSI S screen[0] expected line2 got:", JSON.stringify(top));
    process.exit(1);
  }
  if (!sb.includes("line1")) {
    console.error("CSI S scrollback missing line1:", sb.slice(-3));
    process.exit(1);
  }
  if (t.y !== yBefore) {
    console.error("CSI S moved cursor:", yBefore, "->", t.y);
    process.exit(1);
  }
}

// CSI T — scroll down pulls from scrollback back onto the screen.
{
  const el = freshEl();
  const t = globalThis.__createTerm(el);
  t.write(new TextEncoder().encode("\x1b[2J\x1b[Hline1\r\nline2\r\nline3\x1b[1S\x1b[1T"));
  const top = t.screen[0].map((c) => c.ch).join("").replace(/\s+$/, "");
  if (top !== "line1") {
    console.error("CSI T screen[0] expected line1 got:", JSON.stringify(top));
    process.exit(1);
  }
}

console.log("term_emulator.mjs OK");
