// Highlight the current page in the sidebar; toggle the mobile drawer.
(function () {
  document.addEventListener("DOMContentLoaded", function () {
    const current = location.pathname.replace(/\/$/, "").split("/").pop() || "index.html";
    document.querySelectorAll(".sidebar a").forEach(function (a) {
      const href = a.getAttribute("href");
      if (href === current) {
        a.classList.add("active");
      }
    });

    const hamburger = document.querySelector(".hamburger");
    const sidebar = document.querySelector(".sidebar");
    if (hamburger && sidebar) {
      sidebar.classList.add("collapsed");
      hamburger.addEventListener("click", function () {
        sidebar.classList.toggle("collapsed");
      });
    }
  });
}());
