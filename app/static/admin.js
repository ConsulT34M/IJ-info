// 관리자 콘솔 — 손이 덜 가게 하는 것만. CSP가 inline script를 막으므로 전부 여기에 둔다.
(function () {
  "use strict";

  // 1) 표 행 아무 데나 눌러도 상세로 간다. '상세' 버튼은 그대로 두고 행에 덧붙이는 것이다.
  //    (링크·버튼을 누른 경우, 글자를 끌어 선택한 경우는 건드리지 않는다)
  document.querySelectorAll("tr[data-href]").forEach(function (row) {
    row.classList.add("ij-row-link");
    row.addEventListener("click", function (event) {
      if (event.target.closest("a, button, input, label")) return;
      if (window.getSelection && String(window.getSelection())) return;
      window.location.href = row.dataset.href;
    });
  });

  // 2) 목록 필터: 선택을 바꾸면 바로 조회한다. '조회' 버튼도 그대로 둔다.
  var filter = document.querySelector("form[data-autosubmit]");
  if (filter) {
    filter.querySelectorAll("select").forEach(function (select) {
      select.addEventListener("change", function () {
        filter.submit();
      });
    });
  }
})();
