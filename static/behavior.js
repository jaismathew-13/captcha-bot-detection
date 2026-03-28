/**
 * behavior.js
 * Tracks mouse, scroll, keystroke, and focus behavior.
 * Sends data to /behavior on form submit.
 * Sets human_token field when real mouse/touch interaction detected.
 */
(function () {
  "use strict";

  const state = {
    mousePoints: [],          // [{x, y, t}]
    scrollEvents: 0,
    keyTimestamps: [],        // timestamps of keydown in CAPTCHA field
    captchaFillStart: null,   // when first key pressed in captcha field
    captchaFillEnd: null,     // when last key pressed in captcha field
    focusCount: 0,
    pageLoadTime: Date.now(),
    humanInteracted: false,
  };

  // ── Mouse tracking ──────────────────────────────────────────────────────
  document.addEventListener("mousemove", (e) => {
    // Sample every 100ms max to avoid flooding
    const now = Date.now();
    const last = state.mousePoints[state.mousePoints.length - 1];
    if (!last || now - last.t > 80) {
      state.mousePoints.push({ x: e.clientX, y: e.clientY, t: now });
    }

    if (!state.humanInteracted) {
      state.humanInteracted = true;
      const field = document.getElementById("human_token");
      if (field) field.value = "1";
    }
  });

  document.addEventListener("touchstart", () => {
    state.humanInteracted = true;
    const field = document.getElementById("human_token");
    if (field) field.value = "1";
  }, { passive: true });

  // ── Scroll tracking ─────────────────────────────────────────────────────
  window.addEventListener("scroll", () => {
    state.scrollEvents++;
  }, { passive: true });

  // ── Keystroke tracking on CAPTCHA input ─────────────────────────────────
  document.addEventListener("DOMContentLoaded", () => {
    const captchaInput = document.getElementById("captcha_response");
    if (!captchaInput) return;

    captchaInput.addEventListener("keydown", () => {
      const now = Date.now();
      if (!state.captchaFillStart) state.captchaFillStart = now;
      state.captchaFillEnd = now;
      state.keyTimestamps.push(now);
    });

    captchaInput.addEventListener("focus", () => {
      state.focusCount++;
    });
  });

  // ── Linearity check ─────────────────────────────────────────────────────
  function isLinearPath(points) {
    if (points.length < 4) return true; // too few to tell
    // Check if all points lie on approximately the same line
    const first = points[0];
    const last = points[points.length - 1];
    const dx = last.x - first.x;
    const dy = last.y - first.y;
    const len = Math.sqrt(dx * dx + dy * dy);
    if (len < 1) return true;

    let maxDeviation = 0;
    for (let i = 1; i < points.length - 1; i++) {
      // Perpendicular distance from point to line
      const d = Math.abs(dy * points[i].x - dx * points[i].y + last.x * first.y - last.y * first.x) / len;
      if (d > maxDeviation) maxDeviation = d;
    }
    // If max deviation < 5px the path is basically a straight line
    return maxDeviation < 5;
  }

  function getIntervalStats(timestamps) {
    if (timestamps.length < 2) return { min: 9999, avg: 9999 };
    const intervals = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }
    const min = Math.min(...intervals);
    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    return { min, avg };
  }

  // ── Send data on form submit ─────────────────────────────────────────────
  document.addEventListener("submit", async (e) => {
    const form = e.target;
    if (!form) return;

    // Don't delay the submit — fire and forget
    const captchaFillDuration =
      state.captchaFillStart && state.captchaFillEnd
        ? state.captchaFillEnd - state.captchaFillStart
        : 9999;

    const keystrokeStats = getIntervalStats(state.keyTimestamps);
    const timeToFirstKey = state.captchaFillStart
      ? state.captchaFillStart - state.pageLoadTime
      : 9999;

    const payload = {
      linear_mouse: isLinearPath(state.mousePoints),
      mouse_event_count: state.mousePoints.length,
      zero_scroll: state.scrollEvents === 0,
      instant_keystroke: keystrokeStats.min < 50,
      fast_captcha_fill: captchaFillDuration < 200,
      zero_focus: state.focusCount === 0,
      time_to_first_key: timeToFirstKey,
      captcha_fill_duration: captchaFillDuration,
    };

    try {
      await fetch("/behavior", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        keepalive: true,
      });
    } catch (err) {
      // Silent fail — don't block form submit
    }
  }, { capture: true });
})();
