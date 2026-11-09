/**
 * Pointer coordinate helpers for the remote viewer.
 *
 * object-fit: contain letterboxes the media inside its element. Click and
 * overlay math must use the content rectangle, not the full element box.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.AgentlinkPointer = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  function contentRect(elRect, videoW, videoH) {
    var left = elRect.left || 0;
    var top = elRect.top || 0;
    var width = elRect.width || 0;
    var height = elRect.height || 0;
    if (!videoW || !videoH || !width || !height) {
      return { left: left, top: top, width: width, height: height };
    }
    var mediaAspect = videoW / videoH;
    var boxAspect = width / height;
    if (mediaAspect > boxAspect) {
      // Media is wider: letterbox top/bottom.
      var fittedH = width / mediaAspect;
      return {
        left: left,
        top: top + (height - fittedH) / 2,
        width: width,
        height: fittedH,
      };
    }
    // Media is taller/narrower: pillarbox left/right.
    var fittedW = height * mediaAspect;
    return {
      left: left + (width - fittedW) / 2,
      top: top,
      width: fittedW,
      height: height,
    };
  }

  function clamp01(value) {
    if (value < 0) return 0;
    if (value > 1) return 1;
    return value;
  }

  function toFraction(ev, elRect, videoW, videoH) {
    var box = contentRect(elRect, videoW, videoH);
    var spanX = box.width || 1;
    var spanY = box.height || 1;
    return {
      x: clamp01((ev.clientX - box.left) / spanX),
      y: clamp01((ev.clientY - box.top) / spanY),
    };
  }

  /**
   * Convert a browser/trackpad pixel wheel delta into scroll notches.
   * Protocol unit is WHEEL_DELTA (120): trunc(delta/120), at least ±1.
   */
  function wheelNotches(delta) {
    if (!delta) return 0;
    var n = Math.trunc(delta / 120);
    if (n === 0) n = delta > 0 ? 1 : -1;
    return n;
  }

  return {
    contentRect: contentRect,
    toFraction: toFraction,
    wheelNotches: wheelNotches,
  };
});
