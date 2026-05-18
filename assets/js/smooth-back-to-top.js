document.addEventListener("DOMContentLoaded", function () {
  const backToTop = document.getElementById("back-to-top");

  if (!backToTop) {
    return;
  }

  backToTop.addEventListener(
    "click",
    function (event) {
      event.preventDefault();

      if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        window.scrollTo(0, 0);
        return;
      }

      window.scrollTo({
        top: 0,
        left: 0,
        behavior: "smooth",
      });
    },
    false
  );
});
