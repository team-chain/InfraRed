// InfraRed Chrome Extension — Popup UI

const SEV_BADGE = { critical: "badge-critical", high: "badge-high", medium: "badge-medium", info: "badge-info" };
const ACTION_LABELS = { block_ip: "IP 차단", lock_account: "계정 잠금", escalate: "심각도 상향", notify: "알림" };

// ── 탭 전환 ─────────────────────────────────────────────────────────────── //
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.add("hidden"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.remove("hidden");
  });
});

// ── 설정 토글 ────────────────────────────────────────────────────────────── //
let settingsOpen = false;
document.getElementById("btn-settings").addEventListener("click", () => {
  settingsOpen = !settingsOpen;
  document.getElementById("section-settings").classList.toggle("hidden", !settingsOpen);
  document.getElementById("section-main").classList.toggle("hidden", settingsOpen);
  if (settingsOpen) loadSettingsInputs();
});

async function loadSettingsInputs() {
  const { apiBase = "", token = "" } = await chrome.storage.sync.get(["apiBase", "token"]);
  document.getElementById("input-api-base").value = apiBase;
  document.getElementById("input-token").value = token;
}

document.getElementById("btn-save-settings").addEventListener("click", async () => {
  const apiBase = document.getElementById("input-api-base").value.trim().replace(/\/$/, "");
  const token   = document.getElementById("input-token").value.trim();
  await chrome.storage.sync.set({ apiBase, token });
  settingsOpen = false;
  document.getElementById("section-settings").classList.add("hidden");
  document.getElementById("section-main").classList.remove("hidden");
  chrome.runtime.sendMessage({ type: "POLL_NOW" });
  renderFromCache();
});

// ── 새로고침 ─────────────────────────────────────────────────────────────── //
document.getElementById("btn-refresh").addEventListener("click", () => {
  const btn = document.getElementById("btn-refresh");
  btn.style.opacity = "0.4";
  chrome.runtime.sendMessage({ type: "POLL_NOW" }, () => {
    btn.style.opacity = "1";
    renderFromCache();
  });
});

// ── Incident 렌더링 ──────────────────────────────────────────────────────── //
function renderIncidents(incidents) {
  const el = document.getElementById("incidents-list");
  const open = incidents.filter(i => i.status === "open");
  if (!open.length) {
    el.innerHTML = '<div class="empty">열린 Incident가 없습니다.</div>';
    return;
  }
  el.innerHTML = open.slice(0, 20).map(inc => `
    <div class="incident-card">
      <div class="incident-header">
        <span class="badge ${SEV_BADGE[inc.severity] ?? ""}">${inc.severity}</span>
        <span class="incident-id">${inc.incident_id}</span>
      </div>
      <div class="incident-summary">${inc.asset_id} — ${inc.mitre_tactic ?? ""}</div>
      <div class="incident-meta">${inc.source_ip ?? "-"} · ${inc.username ?? "-"} · ${new Date(inc.created_at).toLocaleString("ko-KR")}</div>
    </div>
  `).join("");
}

// ── 승인 대기 렌더링 ─────────────────────────────────────────────────────── //
function renderPending(pending) {
  const el = document.getElementById("pending-list");
  const badge = document.getElementById("pending-badge");
  badge.textContent = pending.length > 0 ? String(pending.length) : "";
  badge.style.display = pending.length > 0 ? "inline-block" : "none";

  if (!pending.length) {
    el.innerHTML = '<div class="empty">승인 대기 중인 액션이 없습니다.</div>';
    return;
  }
  el.innerHTML = pending.map(action => `
    <div class="action-card" data-id="${action.action_id}">
      <div class="action-type">${ACTION_LABELS[action.action_type] ?? action.action_type}</div>
      <div class="action-target">${action.target}</div>
      <div class="action-meta">${action.incident_id ?? "-"} · ${new Date(action.created_at).toLocaleString("ko-KR")}</div>
      <div class="action-buttons">
        <button class="btn-approve" data-id="${action.action_id}">승인 → 실행</button>
        <button class="btn-reject"  data-id="${action.action_id}">거부</button>
      </div>
    </div>
  `).join("");

  el.querySelectorAll(".btn-approve").forEach(btn => {
    btn.addEventListener("click", async () => {
      btn.disabled = true; btn.textContent = "처리 중...";
      chrome.runtime.sendMessage({ type: "APPROVE_ACTION", actionId: btn.dataset.id }, () => renderFromCache());
    });
  });
  el.querySelectorAll(".btn-reject").forEach(btn => {
    btn.addEventListener("click", async () => {
      btn.disabled = true; btn.textContent = "처리 중...";
      chrome.runtime.sendMessage({ type: "REJECT_ACTION", actionId: btn.dataset.id }, () => renderFromCache());
    });
  });
}

// ── 캐시에서 렌더링 ──────────────────────────────────────────────────────── //
async function renderFromCache() {
  const { incidents = [], pending = [], lastUpdated } = await new Promise(resolve =>
    chrome.storage.local.get(["incidents", "pending", "lastUpdated"], resolve)
  );
  renderIncidents(incidents);
  renderPending(pending);
  if (lastUpdated) {
    document.getElementById("last-updated").textContent =
      `업데이트: ${new Date(lastUpdated).toLocaleTimeString("ko-KR")}`;
  }
}

// 팝업 열릴 때 즉시 렌더링
renderFromCache();
