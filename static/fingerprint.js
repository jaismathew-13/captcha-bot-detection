/**
 * fingerprint.js
 * Runs silently on page load, collects browser consistency signals,
 * POSTs them to /fingerprint, then updates the UI with the risk level.
 */
(function () {
  "use strict";

  async function md5Hash(str) {
    // Simple djb2 hash (no crypto needed, just for comparison)
    let h = 5381;
    for (let i = 0; i < str.length; i++) {
      h = ((h << 5) + h) + str.charCodeAt(i);
      h |= 0;
    }
    return Math.abs(h).toString(16).padStart(8, "0").repeat(4).slice(0, 32);
  }

  function getCanvasHash() {
    try {
      const canvas = document.createElement("canvas");
      canvas.width = 200;
      canvas.height = 50;
      const ctx = canvas.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("HoneyTrap fp 🛡️", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("HoneyTrap fp 🛡️", 4, 17);
      return canvas.toDataURL().slice(-40); // last 40 chars as fingerprint
    } catch (e) {
      return "canvas_error";
    }
  }

  function getWebGLRenderer() {
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return "no_webgl";
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      if (!ext) return "no_ext";
      return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "unknown";
    } catch (e) {
      return "webgl_error";
    }
  }

  function detectTimezoneMismatch() {
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      const lang = (navigator.language || "").toLowerCase();
      // Simple heuristic: if timezone is UTC and language is en-US, could be headless
      if (tz === "UTC" && lang === "en-us") return true;
      return false;
    } catch (e) {
      return false;
    }
  }

  function detectTouchUaMismatch() {
    const ua = navigator.userAgent.toLowerCase();
    const claimsMobile = /android|iphone|ipad/.test(ua);
    const hasTouch = navigator.maxTouchPoints > 0;
    return claimsMobile && !hasTouch;
  }

  async function collectFingerprint() {
    const canvasVal = getCanvasHash();
    const canvasHash = await md5Hash(canvasVal);

    const fp = {
      webdriver: !!navigator.webdriver,
      chrome_object: typeof window.chrome !== "undefined",
      screen_zero: screen.width === 0 || screen.height === 0,
      plugin_count: navigator.plugins ? navigator.plugins.length : 0,
      languages: navigator.languages && navigator.languages.length > 0,
      canvas_hash: canvasHash,
      webgl_renderer: getWebGLRenderer(),
      timezone_mismatch: detectTimezoneMismatch(),
      touch_ua_mismatch: detectTouchUaMismatch(),
      screen_width: screen.width,
      screen_height: screen.height,
      color_depth: screen.colorDepth,
      platform: navigator.platform,
      do_not_track: navigator.doNotTrack,
    };

    try {
      const resp = await fetch("/fingerprint", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(fp),
      });
      const data = await resp.json();
      // Dispatch event so UI can react
      window.dispatchEvent(new CustomEvent("fp_result", { detail: data }));
    } catch (e) {
      console.warn("[fp] Could not send fingerprint:", e);
    }
  }

  // Run immediately
  collectFingerprint();
})();
