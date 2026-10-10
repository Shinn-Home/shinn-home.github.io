// =============================================================================
// 目录 sticky 收尾限位 / Clamp the sticky table-of-contents range
// -----------------------------------------------------------------------------
// 问题: 自动目录用 position: sticky 跟随阅读位置, 而它的包含块是整个 <article>,
//       文章末尾的 .post-bottom-card(标签 / 上一篇下一篇)和评论区都在 <article>
//       内部且比目录更宽, 于是目录会一直贴到页面底部并压住这些内容。
//
// 做法: 目录外层 .toc-aside 是 absolute 容器(top:0 / bottom: var(--toc-limit)),
//       它的高度就是 sticky 的可用行程。把它的底边收到
//          "文末通栏内容顶边 - 目录高度 - 间距"
//       则目录滑到正文结束处就停住并随页面上移, 不再盖住下方卡片。
//
// 退化行为: 脚本不执行时 --toc-limit 默认 0px, 目录行为与修复前一致(可能压住),
//       不会导致目录消失、错位或不可点击。窗口尺寸变化 / 懒加载后会重新计算。
// =============================================================================
(function () {
  "use strict";

  var GAP = 24; // 目录与下方内容之间的呼吸间距

  function layout() {
    var article = document.querySelector(".page.single");
    if (!article) return;

    var aside = article.querySelector(".toc-aside");
    var toc = article.querySelector(".toc-aside > #toc-auto");
    if (!aside || !toc) return;

    var card = article.querySelector(".post-bottom-card");
    var comments = document.getElementById("comments");
    var next = card || comments;
    if (!next) {
      aside.style.removeProperty("--toc-limit");
      return;
    }

    // 目录自身高度(受 CSS max-height 约束), 它决定了目录"倒着量"能贴多低
    var tocHeight = toc.getBoundingClientRect().height;

    // 外层容器底边(相对 .page.single 的 padding box)
    var pageBox = article.getBoundingClientRect();
    var pagePaddingBottom = parseFloat(getComputedStyle(article).paddingBottom) || 0;
    var pageInnerBottom = pageBox.bottom - pagePaddingBottom;

    // 目标底边: 通栏内容顶边再往上退"目录高度 + 间距"
    var targetBottom = next.getBoundingClientRect().top - tocHeight - GAP;

    // bottom 内缩量 = 容器内底边 - 目标底边
    var limit = Math.max(0, Math.round(pageInnerBottom - targetBottom));
    aside.style.setProperty("--toc-limit", limit + "px");
  }

  var timer = null;
  function schedule() {
    if (timer) window.clearTimeout(timer);
    timer = window.setTimeout(layout, 100);
  }

  function boot() {
    layout();
    window.addEventListener("load", schedule, { once: true });
    window.addEventListener("resize", schedule, false);
    document.addEventListener("lazyloaded", schedule, true);
    // 懒加载图片会持续改变正文高度, 短时间内多算几次即可稳定
    var rounds = 0;
    var settle = window.setInterval(function () {
      rounds++;
      layout();
      if (rounds >= 15) window.clearInterval(settle);
    }, 400);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, false);
  } else {
    boot();
  }
})();
