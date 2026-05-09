// InfraRed Chrome Extension — Background Service Worker
// 30초마다 새 Incident를 polling하고 배지 + 알림을 업데이트합니다.

const POLL_INTERVAL_SEC = 30;

async function getConfig() {
  return new Promise(resolve => {
    chrome.storage.sync.get(["apiBase", "token"], resolve);
  });
}

async function fetchIncidents(apiBase, token) {
  const res = await fetch(`${apiBase}/incidents?limit=50`, {
    headers: { "Authorization": `Bearer ${token}` },
    credentials: "include",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  return data.items ?? [];
}

async function fetchPending(apiBase, token) {
  const res = await fetch(`${apiBase}/actions/pending`, {
    headers: { "Authorization": `Bearer ${token}` },
    credentials: "include",
  });
  if (!res.ok) return [];
  const data = await res.json();
  return data.items ?? [];
}

async function poll() {
  const { apiBase, token } = await getConfig();
  if (!apiBase || !token) return;

  try {
    const [incidents, pending] = await Promise.all([
      fetchIncidents(apiBase, token),
      fetchPending(apiBase, token),
    ]);

    const openCritical = incidents.filter(i =>
      i.status === "open" && (i.severity === "critical" || i.severity === "high")
    );
    const totalBadge = openCritical.length + pending.length;

    // 배지 업데이트
    chrome.action.setBadgeText({ text: totalBadge > 0 ? String(totalBadge) : "" });
    chrome.action.setBadgeBackgroundColor({
      color: openCritical.some(i => i.severity === "critical") ? "#CC2200" : "#FF6600",
    });

    // 새 Critical Incident 알림
    const { lastNotifiedIds = [] } = await new Promise(resolve =>
      chrome.storage.local.get(["lastNotifiedIds"], resolve)
    );
    const newCritical = openCritical.filter(
      i => i.severity === "critical" && !lastNotifiedIds.includes(i.incident_id)
    );
    for (const inc of newCritical.slice(0, 3)) {
      chrome.notifications.create(inc.incident_id, {
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: `[CRITICAL] ${inc.incident_id}`,
        message: `${inc.asset_id} — ${inc.mitre_tactic ?? ""} (${inc.source_ip ?? "-"})`,
        priority: 2,
      });
    }
    if (newCritical.length > 0) {
      chrome.storage.local.set({
        lastNotifiedIds: [...lastNotifiedIds, ...newCritical.map(i => i.incident_id)].slice(-50),
      });
    }

    // 팝업에서 읽을 수 있도록 캐시 저장
    chrome.storage.local.set({ incidents, pending, lastUpdated: Date.now() });

  } catch (err) {
    console.error("[InfraRed] poll failed:", err);
  }
}

// 알람 기반 주기적 polling
chrome.alarms.create("infrared-poll", { periodInMinutes: POLL_INTERVAL_SEC / 60 });
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "infrared-poll") poll();
});

// 확장 프로그램 설치/업데이트 시 즉시 실행
chrome.runtime.onInstalled.addListener(() => poll());
chrome.runtime.onStartup.addListener(() => poll());

// 팝업에서 수동 갱신 요청
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "POLL_NOW") {
    poll().then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === "APPROVE_ACTION") {
    getConfig().then(async ({ apiBase, token }) => {
      const res = await fetch(`${apiBase}/actions/${msg.actionId}/approve`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
        credentials: "include",
      });
      sendResponse({ ok: res.ok });
      poll();
    });
    return true;
  }
  if (msg.type === "REJECT_ACTION") {
    getConfig().then(async ({ apiBase, token }) => {
      const res = await fetch(`${apiBase}/actions/${msg.actionId}/reject`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
        credentials: "include",
      });
      sendResponse({ ok: res.ok });
      poll();
    });
    return true;
  }
});
