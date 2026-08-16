export async function safeFetchIndicators() {
  const fallback = [
    { id: "1", value: "CVE-2024-21413", type: "cve", severity_score: 98, confidence: 100, mitre_technique: "T1190", tags: "cisa_kev", status: "active" },
    { id: "2", value: "185.220.101.4", type: "ip", severity_score: 92, confidence: 95, mitre_technique: "T1071.001", tags: "feodo,c2", status: "active" },
    { id: "3", value: "45.142.214.22", type: "ip", severity_score: 95, confidence: 90, mitre_technique: "T1090.003", tags: "otx,pulse", status: "active" },
    { id: "4", value: "27.133.154.218", type: "ip", severity_score: 83, confidence: 90, mitre_technique: "T1071.001", tags: "emotet", status: "active" },
    { id: "5", value: "http://evil-payload-bank.xyz/drop.exe", type: "url", severity_score: 74, confidence: 85, mitre_technique: "T1566.002", tags: "payload", status: "active" }
  ];

  try {
    let res = null;
    try {
      res = await fetch("http://127.0.0.1:8000/api/v1/indicators", { cache: "no-store" });
    } catch {
      res = await fetch("http://localhost:8000/api/v1/indicators", { cache: "no-store" });
    }

    if (res && res.ok) {
      const json = await res.json();
      if (json.data && json.data.length > 0) return json.data;
    }
  } catch (err) {
    console.warn("Using local indicators fallback:", err);
  }
  return fallback;
}
