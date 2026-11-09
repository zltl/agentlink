import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const AgentlinkPointer = require(path.join(here, "../src/pointer.js"));

test("matching 16:9 element and video has no letterbox", () => {
  const el = { left: 0, top: 0, width: 1600, height: 900 };
  const box = AgentlinkPointer.contentRect(el, 1920, 1080);
  assert.deepEqual(box, { left: 0, top: 0, width: 1600, height: 900 });
  const mid = AgentlinkPointer.toFraction(
    { clientX: 800, clientY: 450 },
    el,
    1920,
    1080
  );
  assert.deepEqual(mid, { x: 0.5, y: 0.5 });
});

test("matching element and content size is a linear map", () => {
  // Element size == content size → toFraction is a plain linear map (no letterbox).
  const el = { left: 40, top: 20, width: 400, height: 300 };
  const box = AgentlinkPointer.contentRect(el, 400, 300);
  assert.deepEqual(box, { left: 40, top: 20, width: 400, height: 300 });
  assert.deepEqual(
    AgentlinkPointer.toFraction({ clientX: 40, clientY: 20 }, el, 400, 300),
    { x: 0, y: 0 }
  );
  assert.deepEqual(
    AgentlinkPointer.toFraction({ clientX: 240, clientY: 170 }, el, 400, 300),
    { x: 0.5, y: 0.5 }
  );
  assert.deepEqual(
    AgentlinkPointer.toFraction({ clientX: 440, clientY: 320 }, el, 400, 300),
    { x: 1, y: 1 }
  );
  assert.deepEqual(
    AgentlinkPointer.toFraction({ clientX: 140, clientY: 95 }, el, 400, 300),
    { x: 0.25, y: 0.25 }
  );
});

test("letterbox top black-bar click clamps y to 0", () => {
  // Element 800x800, video 16:9 → content 800x450 with top bar starting at y=175.
  const el = { left: 0, top: 0, width: 800, height: 800 };
  const box = AgentlinkPointer.contentRect(el, 1920, 1080);
  assert.equal(box.top, 175);
  const frac = AgentlinkPointer.toFraction(
    { clientX: 0.5 * 800, clientY: 0.02 * 800 },
    el,
    1920,
    1080
  );
  assert.equal(frac.x, 0.5);
  assert.equal(frac.y, 0);
});

test("wider video letterboxes top/bottom; center click is 0.5,0.5", () => {
  // Element 800x800, video 16:9 → content 800x450 centered vertically.
  const el = { left: 0, top: 0, width: 800, height: 800 };
  const box = AgentlinkPointer.contentRect(el, 1920, 1080);
  assert.equal(box.width, 800);
  assert.equal(box.height, 450);
  assert.equal(box.left, 0);
  assert.equal(box.top, 175);
  const mid = AgentlinkPointer.toFraction(
    { clientX: 400, clientY: 400 },
    el,
    1920,
    1080
  );
  assert.deepEqual(mid, { x: 0.5, y: 0.5 });
});

test("narrower video pillarboxes; corner click outside content clamps", () => {
  // Element 800x450, video 9:16 → content 253.125x450 centered horizontally.
  const el = { left: 10, top: 20, width: 800, height: 450 };
  const box = AgentlinkPointer.contentRect(el, 1080, 1920);
  assert.ok(Math.abs(box.width - 253.125) < 1e-9);
  assert.equal(box.height, 450);
  assert.ok(Math.abs(box.left - (10 + (800 - 253.125) / 2)) < 1e-9);
  assert.equal(box.top, 20);
  // Click the element's top-left corner (in the left pillarbox).
  const corner = AgentlinkPointer.toFraction(
    { clientX: 10, clientY: 20 },
    el,
    1080,
    1920
  );
  assert.equal(corner.x, 0);
  assert.equal(corner.y, 0);
});

test("non-zero element offset is preserved", () => {
  const el = { left: 100, top: 50, width: 1600, height: 900 };
  const box = AgentlinkPointer.contentRect(el, 1920, 1080);
  assert.deepEqual(box, { left: 100, top: 50, width: 1600, height: 900 });
  const mid = AgentlinkPointer.toFraction(
    { clientX: 900, clientY: 500 },
    el,
    1920,
    1080
  );
  assert.deepEqual(mid, { x: 0.5, y: 0.5 });
});

test("zero media or element size falls back to the element rect", () => {
  const el = { left: 12, top: 34, width: 100, height: 80 };
  assert.deepEqual(AgentlinkPointer.contentRect(el, 0, 1080), {
    left: 12,
    top: 34,
    width: 100,
    height: 80,
  });
  assert.deepEqual(AgentlinkPointer.contentRect(el, 1920, 0), {
    left: 12,
    top: 34,
    width: 100,
    height: 80,
  });
  const empty = { left: 5, top: 6, width: 0, height: 0 };
  assert.deepEqual(AgentlinkPointer.contentRect(empty, 1920, 1080), {
    left: 5,
    top: 6,
    width: 0,
    height: 0,
  });
});

test("wheelNotches truncates pixel deltas to WHEEL_DELTA notches", () => {
  assert.equal(AgentlinkPointer.wheelNotches(0), 0);
  assert.equal(AgentlinkPointer.wheelNotches(50), 1);
  assert.equal(AgentlinkPointer.wheelNotches(-50), -1);
  assert.equal(AgentlinkPointer.wheelNotches(120), 1);
  assert.equal(AgentlinkPointer.wheelNotches(240), 2);
  assert.equal(AgentlinkPointer.wheelNotches(-119), -1);
});
