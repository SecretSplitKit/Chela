// Load Mermaid (self-hosted under web/assets/js/) only on pages that contain a
// <pre class="mermaid"> block.
//
// Mermaid is vendored rather than CDN-loaded: SRI is silently ignored on inline
// scripts, and self-hosting removes the third-party runtime trust boundary.
// To bump Mermaid: re-download dist/mermaid.min.js from npm, verify SHA-256
// against the value below, and update both the bundle and this comment.
//
// Each Mermaid figure also carries an <img class="mermaid-fallback"> static SVG.
// The fallback is visible by default (CSS hides pre.mermaid); this script swaps
// the two only after Mermaid loads and renders, so readers without JavaScript
// (or with a broken Mermaid bundle) still see a diagram.
//
// Mermaid version: 10.9.1
// SHA-256(mermaid.min.js): 61b335a46df05a7ce1c98378f60e5f3e77a7fb608a1056997e8a649304a936d6
(function () {
  document.addEventListener("DOMContentLoaded", function () {
    if (!document.querySelector("pre.mermaid")) return;

    function showFallbacks() {
      document.querySelectorAll("img.mermaid-fallback").forEach(function (el) {
        el.style.display = "";
      });
      document.querySelectorAll("pre.mermaid").forEach(function (el) {
        el.style.display = "";
      });
    }

    const s = document.createElement("script");
    s.src = "assets/js/mermaid.min.js";
    s.async = false;
    s.onload = function () {
      if (typeof window.mermaid === "undefined") {
        console.error("mermaid-lazy.js: script loaded but window.mermaid is undefined");
        return;
      }
      document.querySelectorAll("img.mermaid-fallback").forEach(function (el) {
        el.style.display = "none";
      });
      document.querySelectorAll("pre.mermaid").forEach(function (el) {
        el.style.display = "block";
      });
      window.mermaid.initialize({ startOnLoad: false, theme: "neutral" });
      Promise.resolve(
        window.mermaid.run({ querySelector: "pre.mermaid" })
      ).catch(function (e) {
        console.error("mermaid-lazy.js: render failed, restoring static fallback", e);
        showFallbacks();
      });
    };
    s.onerror = function (e) {
      console.error("mermaid-lazy.js: failed to load mermaid.min.js", e);
    };
    document.body.appendChild(s);
  });
}());
