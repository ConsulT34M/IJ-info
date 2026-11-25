/* 회사 홈페이지 상호작용.
 *
 * CSP에 'unsafe-inline'이 없으므로 inline <script>를 쓰지 않고 이 파일 하나로 둔다.
 * 자바스크립트가 꺼져 있어도 내용은 그대로 보여야 하므로, 등장 효과는 <html>에
 * .js 클래스가 붙었을 때만 적용한다(없으면 처음부터 보이는 상태).
 */
(function () {
  "use strict";

  var root = document.documentElement;
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced) return; // 움직임을 줄이기로 한 사용자에게는 아무것도 걸지 않는다

  root.classList.add("js");

  document.addEventListener("DOMContentLoaded", function () {
    revealOnScroll();
    shrinkHeaderOnScroll();
    trackScrollProgress();
    backToTop();
  });

  /* 화면에 들어오면 떠오르게 한다. 같은 묶음은 조금씩 시간차를 둔다. */
  function revealOnScroll() {
    var groups = [
      ".section-head",
      ".flowcard",
      ".card",
      ".stat",
      ".linklist li",
      ".table-plain",
      ".faq details",
      ".receipt",
      ".prose > h2",
      ".hero-cta"
    ];
    var targets = document.querySelectorAll(groups.join(","));
    if (!targets.length) return;

    if (!("IntersectionObserver" in window)) {
      // 지원하지 않는 브라우저에서는 바로 보여준다
      Array.prototype.forEach.call(targets, function (el) { el.classList.add("is-in"); });
      return;
    }

    Array.prototype.forEach.call(targets, function (el) { el.classList.add("reveal"); });

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var el = entry.target;
        el.style.transitionDelay = stagger(el) + "ms";
        el.classList.add("is-in");
        if (el.classList.contains("stat")) countUp(el);
        observer.unobserve(el);
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });

    Array.prototype.forEach.call(targets, function (el) { observer.observe(el); });
  }

  /* 형제 요소 중 몇 번째인지로 지연 시간을 만든다(최대 4칸). */
  function stagger(el) {
    var parent = el.parentNode;
    if (!parent) return 0;
    var index = Array.prototype.indexOf.call(parent.children, el);
    return Math.min(index, 4) * 70;
  }

  /* 지표 숫자를 0에서 올린다. "1,200만" 처럼 뒤에 붙은 단위는 그대로 둔다. */
  function countUp(stat) {
    var node = stat.querySelector("b");
    if (!node || node.dataset.counted) return;
    var parsed = /^([\d,.]+)(.*)$/.exec(node.textContent.trim());
    if (!parsed) return;

    var target = parseFloat(parsed[1].replace(/,/g, ""));
    if (isNaN(target)) return;
    var decimals = (parsed[1].split(".")[1] || "").length;
    var grouped = parsed[1].indexOf(",") !== -1;
    var suffix = parsed[2];
    node.dataset.counted = "1";

    var started = null;
    var duration = 1100;
    function frame(now) {
      if (started === null) started = now;
      var ratio = Math.min((now - started) / duration, 1);
      var eased = 1 - Math.pow(1 - ratio, 3);
      node.textContent = format(target * eased, decimals, grouped) + suffix;
      if (ratio < 1) window.requestAnimationFrame(frame);
    }
    window.requestAnimationFrame(frame);
  }

  function format(value, decimals, grouped) {
    var text = value.toFixed(decimals);
    if (!grouped) return text;
    var parts = text.split(".");
    parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    return parts.join(".");
  }

  /* 조금만 내려도 머리말을 얇게 만들고 그림자를 준다. */
  function shrinkHeaderOnScroll() {
    var head = document.querySelector(".site-head");
    if (!head) return;
    onScroll(function (y) { head.classList.toggle("is-stuck", y > 10); });
  }

  /* 머리말 아래 읽은 분량 막대. */
  function trackScrollProgress() {
    var bar = document.querySelector(".scroll-progress");
    if (!bar) return;
    onScroll(function (y) {
      var total = document.documentElement.scrollHeight - window.innerHeight;
      bar.style.transform = "scaleX(" + (total > 0 ? Math.min(y / total, 1) : 0) + ")";
    });
  }

  /* 한 화면 넘게 내려가면 맨 위로 버튼을 띄운다. */
  function backToTop() {
    var button = document.querySelector(".to-top");
    if (!button) return;
    onScroll(function (y) { button.classList.toggle("is-shown", y > window.innerHeight * 0.8); });
    button.addEventListener("click", function () {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  /* 스크롤 처리는 프레임당 한 번만 돌린다. */
  function onScroll(handler) {
    var waiting = false;
    function run() {
      waiting = false;
      handler(window.pageYOffset || document.documentElement.scrollTop);
    }
    window.addEventListener("scroll", function () {
      if (waiting) return;
      waiting = true;
      window.requestAnimationFrame(run);
    }, { passive: true });
    run();
  }
})();
