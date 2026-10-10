// =============================================================================
// 文章图片宽度分级标注 / Article image width hints
// -----------------------------------------------------------------------------
// 目的: 主题会把正文图片统一撑满正文列(小图被放大、细节图被拉伸)。
//       这里只在"原图比正文列宽"时给图片加一个类, 由 CSS
//       (_single-reading.scss 第 8 节)等比缩到列宽;
//       其余图片不加类, 保持原始像素尺寸, 不被放大。
//
// 退化行为: 脚本未执行 / 执行失败 / JS 被禁用时, CSS 只限制 max-width: 100%,
//       图片按原尺寸显示, 超过列宽才缩小 —— 不会溢出正文列, 不会变形,
//       也不会遮挡内容。也就是说这纯粹是"渐进增强", 不是显示的前置条件。
// =============================================================================
(function () {
  "use strict";

  var WIDE = "__rd-img-wide";
  var PENDING = "data-rd-pending";

  function measure(container, img) {
    // 仍在显示 lazysizes 占位图时不能测量: 占位图尺寸很小,
    // 会被误判成"小图", 必须等真实图片加载完成后再量.
    var current = img.currentSrc || img.src || "";
    if (!img.complete || !current || current.indexOf("loading.min.svg") !== -1) {
      if (img.getAttribute(PENDING) === "1") return;
      img.setAttribute(PENDING, "1");
      img.addEventListener("load", function () {
        img.removeAttribute(PENDING);
        measure(container, img);
      }, { once: true });
      return;
    }

    var naturalWidth = img.naturalWidth || 0;
    var columnWidth = container.clientWidth;
    if (!naturalWidth || !columnWidth) return;

    img.removeAttribute(PENDING);
    var isWide = naturalWidth > columnWidth;
    if (img.classList.contains(WIDE) !== isWide) img.classList.toggle(WIDE, isWide);
  }

  function run() {
    var container = document.getElementById("content");
    if (!container) return;
    Array.prototype.forEach.call(container.querySelectorAll("img"), function (img) {
      measure(container, img);
    });
  }

  var timer = null;
  function schedule() {
    if (timer) window.clearTimeout(timer);
    timer = window.setTimeout(run, 80);
  }

  function boot() {
    run();
    // lazysizes 会在滚动/视口变化过程中持续把图片变成已加载, 每次完成后复测,
    // 保证"是否超过列宽"的判定始终与当前渲染一致.
    document.addEventListener("lazyloaded", schedule, true);
    window.addEventListener("load", schedule, { once: true });
    window.addEventListener("resize", schedule, false);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, false);
  } else {
    boot();
  }
})();
