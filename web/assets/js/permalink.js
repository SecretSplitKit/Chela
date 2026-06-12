// Rewrite <a class="src" data-file data-lines> elements to absolute GitHub URLs
// at view-time, using the commit pinned in pinned-commit.json.
(function () {
  const REPO = "https://github.com/SecretSplitKit/Chela";

  document.addEventListener("DOMContentLoaded", function () {
    fetch("assets/pinned-commit.json", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (pin) {
        // Prefer a ref/tag (e.g. "main", or a release tag) over a raw SHA so the
        // source links resolve even before a release is cut.
        const sha = pin.tag || pin.sha;
        if (!sha) throw new Error("pinned-commit.json missing tag/sha");
        document.querySelectorAll("a.src").forEach(function (a) {
          const file = a.getAttribute("data-file");
          const lines = a.getAttribute("data-lines");
          if (!file) return;
          let url;
          if (file.endsWith("/")) {
            url = REPO + "/tree/" + sha + "/" + file.replace(/\/$/, "");
          } else {
            url = REPO + "/blob/" + sha + "/" + file;
            if (lines) {
              const m = lines.match(/^(\d+)(?:-(\d+))?$/);
              if (m) {
                url += "#L" + m[1];
                if (m[2]) url += "-L" + m[2];
              }
            }
          }
          a.setAttribute("href", url);
        });
      })
      .catch(function (e) {
        console.error("permalink.js: failed to load pinned-commit.json", e);
      });
  });
}());
