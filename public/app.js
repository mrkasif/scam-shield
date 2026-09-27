/* ScamShield frontend â€” calls the real FastAPI endpoint. No fake results. */
(function () {
  "use strict";

  const form = document.getElementById("scan-form");
  const input = document.getElementById("url-input");
  const button = document.getElementById("scan-btn");
  const btnText = button.querySelector(".btn-text");
  const errorEl = document.getElementById("form-error");
  const loadingEl = document.getElementById("loading");
  const resultEl = document.getElementById("result");
  const scoreRing = document.getElementById("score-ring");
  const scoreValue = document.getElementById("score-value");
  const riskBadge = document.getElementById("risk-badge");
  const categoryEl = document.getElementById("category");
  const recommendationEl = document.getElementById("recommendation");
  const reasonsEl = document.getElementById("reasons");
  const indicatorsEl = document.getElementById("indicators");
  const normalizedEl = document.getElementById("normalized");

  const RECOMMENDATIONS = {
    GREEN: "No risk indicators detected in this check. You may proceed, but always double-check the sender and the domain before entering credentials — no result guarantees safety.",
    YELLOW: "Caution: this link shows suspicious traits. Do not log in or pay through it. Verify via the official website or app instead.",
    RED: "Danger: this link shows strong phishing/malware traits. Do NOT visit it, do NOT enter credentials, and report/block the sender.",
  };

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = !message;
  }

  function setLoading(active) {
    loadingEl.hidden = !active;
    button.disabled = active;
    btnText.textContent = active ? "Scanningâ€¦" : "Scan";
  }

  function render(result) {
    resultEl.hidden = false;
    scoreValue.textContent = String(result.score);
    scoreRing.dataset.level = result.risk_level;
    riskBadge.textContent = result.risk_level;
    riskBadge.className = "risk-badge level-" + result.risk_level;
    categoryEl.textContent = (result.category || "unknown").replaceAll("_", " ");
    recommendationEl.textContent = RECOMMENDATIONS[result.risk_level] || "";

    reasonsEl.innerHTML = "";
    (result.reasons || []).forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      reasonsEl.appendChild(li);
    });

    indicatorsEl.innerHTML = "";
    const codes = result.detected_indicators || [];
    if (codes.length === 0) {
      const span = document.createElement("span");
      span.className = "chip none";
      span.textContent = "none detected";
      indicatorsEl.appendChild(span);
    } else {
      codes.forEach((code) => {
        const span = document.createElement("span");
        span.className = "chip";
        span.textContent = code;
        indicatorsEl.appendChild(span);
      });
    }

    normalizedEl.textContent = result.normalized_url || "";
    resultEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = input.value.trim();
    showError("");
    resultEl.hidden = true;

    if (!url) {
      showError("Please paste a URL to scan.");
      input.focus();
      return;
    }

    setLoading(true);
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = typeof data.detail === "string" ? data.detail : "Analysis failed.";
        throw new Error(detail);
      }
      render(data);
    } catch (err) {
      showError(err instanceof Error ? err.message : "Network error. Is the backend running?");
    } finally {
      setLoading(false);
    }
  });
})();

/* ScamShield QR scanner â€” uploads to POST /api/analyze/qr, never opens links. */
(function () {
  "use strict";

  const form = document.getElementById("qr-form");
  const fileInput = document.getElementById("qr-input");
  const preview = document.getElementById("qr-preview");
  const button = document.getElementById("qr-scan-btn");
  const btnText = button.querySelector(".btn-text");
  const errorEl = document.getElementById("qr-error");
  const loadingEl = document.getElementById("qr-loading");
  const resultEl = document.getElementById("qr-result");
  const payloadEl = document.getElementById("qr-payload");
  const typeEl = document.getElementById("qr-type");
  const classEl = document.getElementById("qr-class");
  const urlBlock = document.getElementById("qr-url-block");
  const noteBlock = document.getElementById("qr-note-block");
  const noteEl = document.getElementById("qr-note");
  const upiDl = document.getElementById("qr-upi-details");
  const scoreRing = document.getElementById("qr-score-ring");
  const scoreValue = document.getElementById("qr-score-value");
  const riskBadge = document.getElementById("qr-risk-badge");
  const categoryEl = document.getElementById("qr-category");
  const recommendationEl = document.getElementById("qr-recommendation");
  const reasonsEl = document.getElementById("qr-reasons");
  const indicatorsEl = document.getElementById("qr-indicators");
  let previewUrl = null;

  const RECOMMENDATIONS = {
    GREEN: "No risk indicators detected in this check. You may proceed, but always double-check the sender and the domain before entering credentials — no result guarantees safety.",
    YELLOW: "Caution: this link shows suspicious traits. Do not log in or pay through it. Verify via the official website or app instead.",
    RED: "Danger: this link shows strong phishing/malware traits. Do NOT visit it, do NOT enter credentials, and report/block the sender.",
  };

  const UPI_RECOMMENDATIONS = {
    GREEN: "No risk indicators detected in this check. Still verify the payee inside your own UPI app before paying.",
    YELLOW: "Caution: this payment request shows suspicious traits. Do not pay until you verify the payee independently.",
    RED: "Danger: this payment request shows strong scam traits. Do NOT pay. Block and report the sender.",
  };

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = !message;
  }

  function setLoading(active) {
    loadingEl.hidden = !active;
    button.disabled = active;
    btnText.textContent = active ? "Decodingâ€¦" : "Scan QR";
  }

  fileInput.addEventListener("change", () => {
    showError("");
    const file = fileInput.files[0];
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      previewUrl = null;
    }
    if (file) {
      previewUrl = URL.createObjectURL(file);
      preview.src = previewUrl;
      preview.hidden = false;
    } else {
      preview.hidden = true;
      preview.removeAttribute("src");
    }
  });

  function renderAnalysis(analysis, payloadType) {
    urlBlock.hidden = false;
    const guidance = payloadType === "upi" ? UPI_RECOMMENDATIONS : RECOMMENDATIONS;
    scoreValue.textContent = String(analysis.score);
    scoreRing.dataset.level = analysis.risk_level;
    riskBadge.textContent = analysis.risk_level;
    riskBadge.className = "risk-badge level-" + analysis.risk_level;
    categoryEl.textContent = (analysis.category || "unknown").replaceAll("_", " ");
    recommendationEl.textContent = guidance[analysis.risk_level] || "";
    reasonsEl.innerHTML = "";
    (analysis.reasons || []).forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      reasonsEl.appendChild(li);
    });
    indicatorsEl.innerHTML = "";
    const codes = analysis.detected_indicators || [];
    if (codes.length === 0) {
      const span = document.createElement("span");
      span.className = "chip none";
      span.textContent = "none detected";
      indicatorsEl.appendChild(span);
    } else {
      codes.forEach((code) => {
        const span = document.createElement("span");
        span.className = "chip";
        span.textContent = code;
        indicatorsEl.appendChild(span);
      });
    }
  }

  function render(result) {
    resultEl.hidden = false;
    payloadEl.textContent = result.payload || "(empty)";
    typeEl.textContent = result.type || "unknown";
    urlBlock.hidden = true;
    noteBlock.hidden = true;
    upiDl.hidden = true;
    upiDl.innerHTML = "";

    if (result.analysis && typeof result.analysis.score === "number") {
      classEl.textContent = result.classification ? "(" + result.classification.replaceAll("_", " ") + ")" : "";
      renderAnalysis(result.analysis, result.type);
      if (result.type === "upi") {
        // Show the parsed payment fields plus the static-analysis note
        // alongside the UPI score.
        noteBlock.hidden = false;
        noteEl.textContent = result.note || "";
        const components = result.analysis.components || {};
        const entries = Object.entries(components).filter(([, value]) => value !== null && value !== undefined && value !== "");
        upiDl.innerHTML = "";
        if (entries.length > 0) {
          upiDl.hidden = false;
          entries.forEach(([key, value]) => {
            const dt = document.createElement("dt");
            dt.textContent = key;
            const dd = document.createElement("dd");
            dd.textContent = value;
            upiDl.appendChild(dt);
            upiDl.appendChild(dd);
          });
        }
      }
    } else {
      classEl.textContent = result.classification ? "(" + result.classification.replaceAll("_", " ") + ")" : "";
      noteBlock.hidden = false;
      noteEl.textContent = result.note || "";
      const details = result.upi_details || {};
      if (Object.keys(details).length > 0) {
        upiDl.hidden = false;
        Object.entries(details).forEach(([label, value]) => {
          const dt = document.createElement("dt");
          dt.textContent = label;
          const dd = document.createElement("dd");
          dd.textContent = value;
          upiDl.appendChild(dt);
          upiDl.appendChild(dd);
        });
      }
    }
    resultEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showError("");
    resultEl.hidden = true;
    const file = fileInput.files[0];
    if (!file) {
      showError("Please choose a QR image first.");
      return;
    }
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch("/api/analyze/qr", { method: "POST", body: formData });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = typeof data.detail === "string" ? data.detail : "QR analysis failed.";
        throw new Error(detail);
      }
      render(data);
    } catch (err) {
      showError(err instanceof Error ? err.message : "Network error. Is the backend running?");
    } finally {
      setLoading(false);
    }
  });
})();

/* ScamShield UPI analyzer â€” POSTs to /api/analyze/upi. Static only. */
(function () {
  "use strict";

  const form = document.getElementById("upi-form");
  const input = document.getElementById("upi-input");
  const button = document.getElementById("upi-btn");
  const btnText = button.querySelector(".btn-text");
  const errorEl = document.getElementById("upi-error");
  const loadingEl = document.getElementById("upi-loading");
  const resultEl = document.getElementById("upi-result");
  const componentsEl = document.getElementById("upi-components");
  const scoreRing = document.getElementById("upi-score-ring");
  const scoreValue = document.getElementById("upi-score-value");
  const riskBadge = document.getElementById("upi-risk-badge");
  const categoryEl = document.getElementById("upi-category");
  const recommendationEl = document.getElementById("upi-recommendation");
  const reasonsEl = document.getElementById("upi-reasons");
  const indicatorsEl = document.getElementById("upi-indicators");

  const RECOMMENDATIONS = {
    GREEN: "No risk indicators detected in this check. Still verify the payee inside your own UPI app before paying.",
    YELLOW: "Caution: this payment request shows suspicious traits. Do not pay until you verify the payee independently.",
    RED: "Danger: this payment request shows strong scam traits. Do NOT pay. Block and report the sender.",
  };

  const COMPONENT_LABELS = {
    pa: "payee (pa)",
    pn: "payee name (pn)",
    am: "amount (am)",
    cu: "currency (cu)",
    tn: "note (tn)",
    mc: "merchant code (mc)",
    tr: "reference (tr)",
    tid: "transaction ID (tid)",
  };

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = !message;
  }

  function setLoading(active) {
    loadingEl.hidden = !active;
    button.disabled = active;
    btnText.textContent = active ? "Analyzingâ€¦" : "Analyze";
  }

  function render(result) {
    resultEl.hidden = false;

    componentsEl.innerHTML = "";
    const components = result.components || {};
    Object.entries(COMPONENT_LABELS).forEach(([key, label]) => {
      const value = components[key];
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = value === null || value === undefined || value === "" ? "â€”" : String(value);
      componentsEl.appendChild(dt);
      componentsEl.appendChild(dd);
    });

    scoreValue.textContent = String(result.score ?? 0);
    scoreRing.dataset.level = result.risk_level || "GREEN";
    riskBadge.textContent = result.risk_level || "GREEN";
    riskBadge.className = "risk-badge level-" + (result.risk_level || "GREEN");
    categoryEl.textContent = (result.category || "unknown").replaceAll("_", " ");
    recommendationEl.textContent = RECOMMENDATIONS[result.risk_level] || "";

    reasonsEl.innerHTML = "";
    (result.reasons || []).forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      reasonsEl.appendChild(li);
    });

    indicatorsEl.innerHTML = "";
    const codes = result.detected_indicators || [];
    if (codes.length === 0) {
      const span = document.createElement("span");
      span.className = "chip none";
      span.textContent = "none detected";
      indicatorsEl.appendChild(span);
    } else {
      codes.forEach((code) => {
        const span = document.createElement("span");
        span.className = "chip";
        span.textContent = code;
        indicatorsEl.appendChild(span);
      });
    }
    resultEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const uri = input.value.trim();
    showError("");
    resultEl.hidden = true;
    if (!uri) {
      showError("Please paste a UPI URI to analyze.");
      input.focus();
      return;
    }
    setLoading(true);
    try {
      const response = await fetch("/api/analyze/upi", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ upi_uri: uri }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = typeof data.detail === "string" ? data.detail : "UPI analysis failed.";
        throw new Error(detail);
      }
      render(data);
    } catch (err) {
      showError(err instanceof Error ? err.message : "Network error. Is the backend running?");
    } finally {
      setLoading(false);
    }
  });
})();

/* ScamShield Smart Scanner â€” auto-detects URL / UPI / QR and unifies results. */
(function () {
  "use strict";

  const form = document.getElementById("ss-form");
  const input = document.getElementById("ss-input");
  const fileInput = document.getElementById("ss-file");
  const preview = document.getElementById("ss-preview");
  const scanBtn = document.getElementById("ss-scan-btn");
  const clearBtn = document.getElementById("ss-clear-btn");
  const scanBtnText = scanBtn.querySelector(".btn-text");
  const errorEl = document.getElementById("ss-error");
  const loadingEl = document.getElementById("ss-loading");
  const resultEl = document.getElementById("ss-result");
  const typeEl = document.getElementById("ss-type");
  const payloadWrap = document.getElementById("ss-payload-wrap");
  const payloadEl = document.getElementById("ss-payload");
  const scoreWrap = document.getElementById("ss-score-wrap");
  const scoreRing = document.getElementById("ss-score-ring");
  const scoreValue = document.getElementById("ss-score-value");
  const riskBadge = document.getElementById("ss-risk-badge");
  const categoryEl = document.getElementById("ss-category");
  const recommendationEl = document.getElementById("ss-recommendation");
  const reasonsEl = document.getElementById("ss-reasons");
  const indicatorsEl = document.getElementById("ss-indicators");
  const upiWrap = document.getElementById("ss-upi-wrap");
  const upiDl = document.getElementById("ss-upi-components");
  const noteWrap = document.getElementById("ss-note-wrap");
  const noteEl = document.getElementById("ss-note");
  const intelBlock = document.getElementById("ss-intel-block");
  const intelList = document.getElementById("ss-intel-list");
  let previewUrl = null;

  const GUIDANCE = {
    url: {
      GREEN: "No risk indicators detected in this check. You may proceed, but always double-check the sender and the domain before entering credentials — no result guarantees safety.",
      YELLOW: "Caution: this link shows suspicious traits. Do not log in or pay through it. Verify via the official website or app instead.",
      RED: "Danger: this link shows strong phishing/malware traits. Do NOT visit it, do NOT enter credentials, and report/block the sender.",
    },
    upi: {
      GREEN: "No risk indicators detected in this check. Still verify the payee inside your own UPI app before paying.",
      YELLOW: "Caution: this payment request shows suspicious traits. Do not pay until you verify the payee independently.",
      RED: "Danger: this payment request shows strong scam traits. Do NOT pay. Block and report the sender.",
    },
  };

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = !message;
  }

  function setLoading(active) {
    loadingEl.hidden = !active;
    scanBtn.disabled = active;
    scanBtnText.textContent = active ? "Scanningâ€¦" : "Scan";
  }

  function fillList(el, items, emptyText) {
    el.innerHTML = "";
    if (!items || items.length === 0) {
      const li = document.createElement("li");
      li.className = "none-note";
      li.textContent = emptyText;
      el.appendChild(li);
      return;
    }
    items.forEach((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      el.appendChild(li);
    });
  }

  function fillChips(el, codes) {
    el.innerHTML = "";
    if (!codes || codes.length === 0) {
      const span = document.createElement("span");
      span.className = "chip none";
      span.textContent = "none detected";
      el.appendChild(span);
      return;
    }
    codes.forEach((code) => {
      const span = document.createElement("span");
      span.className = "chip";
      span.textContent = code;
      el.appendChild(span);
    });
  }

  function renderVerdict(verdict, kind) {
    scoreWrap.hidden = false;
    noteWrap.hidden = true;
    scoreValue.textContent = String(verdict.score ?? 0);
    scoreRing.dataset.level = verdict.risk_level || "GREEN";
    riskBadge.textContent = verdict.risk_level || "GREEN";
    riskBadge.className = "risk-badge level-" + (verdict.risk_level || "GREEN");
    categoryEl.textContent = (verdict.category || "unknown").replaceAll("_", " ");
    recommendationEl.textContent = (GUIDANCE[kind] || GUIDANCE.url)[verdict.risk_level] || "";
    fillList(reasonsEl, verdict.reasons, "No reasons reported.");
    fillChips(indicatorsEl, verdict.detected_indicators);
  }

  function renderUpiComponents(components) {
    const entries = Object.entries(components || {}).filter(([, v]) => v !== null && v !== undefined && v !== "");
    upiWrap.hidden = entries.length === 0;
    upiDl.innerHTML = "";
    entries.forEach(([key, value]) => {
      const dt = document.createElement("dt");
      dt.textContent = key;
      const dd = document.createElement("dd");
      dd.textContent = value;
      upiDl.appendChild(dt);
      upiDl.appendChild(dd);
    });
  }

  function findingRows(listEl, findings) {
    findings.slice(0, 5).forEach((finding) => {
      const fields = [
        ["indicator", finding.indicator || "â€”"],
        ["type", (finding.indicator_type || "â€”").replaceAll("_", " ")],
        ["category", (finding.category || "â€”").replaceAll("_", " ")],
        ["severity", finding.severity || "â€”"],
        ["confidence", typeof finding.confidence === "number"
          ? Math.round(finding.confidence * 100) + "%"
          : (finding.confidence === null || finding.confidence === undefined ? "â€”" : String(finding.confidence))],
        ["source", finding.source || "â€”"],
        ["description", finding.description || "â€”"],
      ];
      fields.forEach(([label, value]) => {
        const dt = document.createElement("dt");
        dt.textContent = label;
        const dd = document.createElement("dd");
        dd.textContent = value;
        listEl.appendChild(dt);
        listEl.appendChild(dd);
      });
    });
  }

  function renderIntel(threatIntel) {
    // Shown only when local intelligence matched or the external provider
    // was actually consulted. Never claims safety on a non-match.
    intelList.innerHTML = "";
    const local = (threatIntel && threatIntel.local) || { matched: false, findings: [] };
    const external = threatIntel && threatIntel.external;
    const showExternal = Boolean(external && external.configured);
    intelBlock.hidden = !(local.matched || showExternal);
    if (intelBlock.hidden) {
      return;
    }
    const localDt = document.createElement("dt");
    localDt.textContent = "local intelligence";
    const localDd = document.createElement("dd");
    localDd.textContent = local.matched ? "Match found" : "No known local indicator";
    intelList.appendChild(localDt);
    intelList.appendChild(localDd);
    if (local.matched) {
      findingRows(intelList, local.findings || []);
    }
    if (showExternal) {
      const extDt = document.createElement("dt");
      extDt.textContent = "external intelligence (urlhaus)";
      const extDd = document.createElement("dd");
      if (external.matched) {
        extDd.textContent = "Match found";
      } else if (external.available) {
        extDd.textContent = "Checked â€” no match. Local analysis still completed.";
      } else {
        extDd.textContent = "Not available â€” local analysis still completed.";
      }
      intelList.appendChild(extDt);
      intelList.appendChild(extDd);
      if (external.matched) {
        findingRows(intelList, external.findings || []);
      }
    }
  }

  function render(envelope) {
    resultEl.hidden = false;
    payloadWrap.hidden = true;
    upiWrap.hidden = true;
    intelBlock.hidden = true;

    const inputType = envelope.input_type || "unknown";
    const result = envelope.result || {};
    typeEl.textContent = inputType;

    if (inputType === "qr") {
      // Inner QR result keeps its own shape; surface payload + nested verdict.
      if (result.payload) {
        payloadWrap.hidden = false;
        payloadEl.textContent = result.payload;
      }
      if (result.analysis && typeof result.analysis.score === "number") {
        const kind = result.type === "upi" ? "upi" : "url";
        renderVerdict(result.analysis, kind);
        renderIntel(result.threat_intelligence);
        if (result.type === "upi") {
          renderUpiComponents(result.analysis.components);
        }
      } else {
        scoreWrap.hidden = true;
        noteWrap.hidden = false;
        noteEl.textContent = result.note || "No score applies to this content.";
      }
    } else if (inputType === "url" || inputType === "upi") {
      renderVerdict(result, inputType);
      renderIntel(result.threat_intelligence);
      if (inputType === "upi") {
        renderUpiComponents(result.components);
      }
    } else {
      // Plain text: show content + note, no fabricated score fields.
      scoreWrap.hidden = true;
      noteWrap.hidden = false;
      payloadWrap.hidden = false;
      payloadEl.textContent = result.content || "";
      noteEl.textContent = result.note || "";
    }
    resultEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  fileInput.addEventListener("change", () => {
    showError("");
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      previewUrl = null;
    }
    const file = fileInput.files[0];
    if (file) {
      previewUrl = URL.createObjectURL(file);
      preview.src = previewUrl;
      preview.hidden = false;
    } else {
      preview.hidden = true;
      preview.removeAttribute("src");
    }
  });

  clearBtn.addEventListener("click", () => {
    input.value = "";
    fileInput.value = "";
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      previewUrl = null;
    }
    preview.hidden = true;
    preview.removeAttribute("src");
    resultEl.hidden = true;
    showError("");
    input.focus();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showError("");
    resultEl.hidden = true;
    const file = fileInput.files[0];
    const text = input.value.trim();
    if (!file && !text) {
      showError("Paste a URL / UPI URI / text, or choose a QR image.");
      input.focus();
      return;
    }
    setLoading(true);
    try {
      let response;
      if (file) {
        const formData = new FormData();
        formData.append("file", file);
        response = await fetch("/api/scan", { method: "POST", body: formData });
      } else {
        response = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input: text }),
        });
      }
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = typeof data.detail === "string" ? data.detail : "Scan failed.";
        throw new Error(detail);
      }
      render(data);
      if (typeof window.refreshDashboard === "function") {
        window.refreshDashboard();
      }
    } catch (err) {
      showError(err instanceof Error ? err.message : "Network error. Is the backend running?");
    } finally {
      setLoading(false);
    }
  });
})();

/* ScamShield Security Dashboard â€” metadata only, rendered via textContent. */
(function () {
  "use strict";

  const totalEl = document.getElementById("dash-total");
  const threatsEl = document.getElementById("dash-threats");
  const safeEl = document.getElementById("dash-safe");
  const highEl = document.getElementById("dash-high");
  const riskEl = document.getElementById("dash-risk");
  const typesEl = document.getElementById("dash-types");
  const emptyEl = document.getElementById("dash-empty");
  const rowsEl = document.getElementById("dash-rows");
  const detailBox = document.getElementById("dash-detail");
  const detailList = document.getElementById("dash-detail-list");
  const refreshBtn = document.getElementById("dash-refresh-btn");
  const clearBtn = document.getElementById("dash-clear-btn");
  const errorEl = document.getElementById("dash-error");
  const persistEl = document.getElementById("dash-persistence");

  function showError(message) {
    errorEl.textContent = message;
    errorEl.hidden = !message;
  }

  function distRow(container, name, count, max, fillClass) {
    const row = document.createElement("div");
    row.className = "dist-row";
    const label = document.createElement("span");
    label.className = "dist-name";
    label.textContent = name;
    const bar = document.createElement("div");
    bar.className = "dist-bar";
    const fill = document.createElement("div");
    fill.className = "dist-fill " + fillClass;
    fill.style.width = max > 0 ? Math.round((count / max) * 100) + "%" : "0%";
    bar.appendChild(fill);
    const num = document.createElement("span");
    num.className = "dist-count";
    num.textContent = String(count);
    row.appendChild(label);
    row.appendChild(bar);
    row.appendChild(num);
    container.appendChild(row);
  }

  function cell(text) {
    const td = document.createElement("td");
    td.textContent = text;
    return td;
  }

  function showDetail(scan) {
    detailList.innerHTML = "";
    const fields = [
      ["time", scan.ts || "â€”"],
      ["type", scan.input_type || "â€”"],
      ["risk", scan.risk_level || "â€”"],
      ["score", scan.score === null || scan.score === undefined ? "â€”" : String(scan.score)],
      ["category", (scan.category || "â€”").replaceAll("_", " ")],
      ["preview", scan.preview || "â€”"],
    ];
    fields.forEach(([label, value]) => {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = value;
      detailList.appendChild(dt);
      detailList.appendChild(dd);
    });
    detailBox.hidden = false;
  }

  async function load() {
    showError("");
    try {
      const [statsRes, histRes] = await Promise.all([
        fetch("/api/history/stats"),
        fetch("/api/history?limit=50"),
      ]);
      if (!statsRes.ok || !histRes.ok) {
        throw new Error("Dashboard request failed.");
      }
      const stats = await statsRes.json();
      const history = await histRes.json();

      totalEl.textContent = String(stats.total || 0);
      threatsEl.textContent = String(stats.suspicious || 0);
      safeEl.textContent = String(stats.green || 0);
      highEl.textContent = String(stats.red || 0);
      persistEl.textContent = stats.persistent
        ? "Stored locally on this machine."
        : "Ephemeral on this server â€” history resets on restart.";

      riskEl.innerHTML = "";
      const riskMax = Math.max(stats.green || 0, stats.yellow || 0, stats.red || 0, 1);
      distRow(riskEl, "green", stats.green || 0, riskMax, "green");
      distRow(riskEl, "yellow", stats.yellow || 0, riskMax, "yellow");
      distRow(riskEl, "red", stats.red || 0, riskMax, "red");

      typesEl.innerHTML = "";
      const byType = stats.by_type || {};
      const typeMax = Math.max(byType.url || 0, byType.qr || 0, byType.upi || 0, byType.text || 0, 1);
      distRow(typesEl, "url", byType.url || 0, typeMax, "accent");
      distRow(typesEl, "qr", byType.qr || 0, typeMax, "accent");
      distRow(typesEl, "upi", byType.upi || 0, typeMax, "accent");
      distRow(typesEl, "text", byType.text || 0, typeMax, "accent");

      const scans = history.scans || [];
      rowsEl.innerHTML = "";
      detailBox.hidden = true;
      emptyEl.hidden = scans.length !== 0;
      scans.forEach((scan) => {
        const tr = document.createElement("tr");
        const time = document.createElement("td");
        time.textContent = (scan.ts || "").replace("T", " ").replace("+00:00", "Z");
        tr.appendChild(time);
        tr.appendChild(cell(scan.input_type || "â€”"));
        const riskTd = document.createElement("td");
        const pill = document.createElement("span");
        const level = scan.risk_level || "none";
        pill.className = "risk-pill " + (scan.risk_level || "none");
        pill.textContent = level;
        riskTd.appendChild(pill);
        tr.appendChild(riskTd);
        tr.appendChild(cell(scan.score === null || scan.score === undefined ? "â€”" : String(scan.score)));
        tr.appendChild(cell((scan.category || "â€”").replaceAll("_", " ")));
        tr.addEventListener("click", () => showDetail(scan));
        rowsEl.appendChild(tr);
      });
    } catch (err) {
      showError(err instanceof Error ? err.message : "Dashboard request failed.");
    }
  }

  refreshBtn.addEventListener("click", load);

  clearBtn.addEventListener("click", async () => {
    if (!window.confirm("Clear all stored scan history? This cannot be undone.")) {
      return;
    }
    showError("");
    try {
      const response = await fetch("/api/history", { method: "DELETE" });
      if (!response.ok) {
        throw new Error("Clear failed.");
      }
      await load();
    } catch (err) {
      showError(err instanceof Error ? err.message : "Clear failed.");
    }
  });

  window.refreshDashboard = load;
  document.addEventListener("DOMContentLoaded", load);
})();

/* ScamShield demo status + drag-and-drop upload (presentation only). */
(function () {
  "use strict";

  const statusEl = document.getElementById("sys-status");

  function setConsole(data) {
    const set = (id, text) => {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = text;
      }
    };
    const ok = data && data.scanner === "ready" && data.qr_engine === "ready";
    set("st-scanner", data && data.scanner === "ready" ? "Ready" : "Issue");
    set("st-qr", data && data.qr_engine === "ready" ? "Ready" : "Unavailable");
    set("st-intel", "Local · " + ((data && data.local_indicators) || "?") + " indicators");
    set("st-ext", data && data.external_intelligence === "configured" ? "Configured" : "Not configured");
    set("st-eval", ((data && data.evaluation_cases) || "?") + " cases");
    return ok;
  }

  async function refreshStatus() {
    if (!statusEl) {
      return;
    }
    try {
      const response = await fetch("/api/status");
      if (!response.ok) {
        throw new Error("status request failed");
      }
      const data = await response.json();
      // QR image decode is unavailable on slim hosts (e.g. Vercel free
      // tier, where OpenCV exceeds the function size limit). That is a
      // known, explicitly-reported degradation (tooltip + console readout
      // + clean 503 on upload), not an outage: the pill stays green while
      // the scanner itself is ready.
      const bad = data.scanner !== "ready";
      statusEl.textContent = bad ? "Systems degraded" : "Systems ready";
      statusEl.title = [
        data.scanner === "ready" ? "Scanner ready" : "Scanner issue",
        data.qr_engine === "ready" ? "QR ready" : "QR unavailable",
        "Intel local",
        data.external_intelligence === "configured" ? "Ext on" : "Ext off",
        "Eval " + (data.evaluation_cases || "?") + " cases",
      ].join(" · ");
      statusEl.classList.toggle("bad", bad);
      setConsole(data);
    } catch (err) {
      statusEl.textContent = "Status unavailable";
      statusEl.classList.add("bad");
      setConsole(null);
    }
  }

  function attachDrop(inputId) {
    const input = document.getElementById(inputId);
    if (!input) {
      return;
    }
    input.addEventListener("dragover", (event) => {
      event.preventDefault();
      input.classList.add("dragover");
    });
    input.addEventListener("dragleave", () => {
      input.classList.remove("dragover");
    });
    input.addEventListener("drop", (event) => {
      event.preventDefault();
      input.classList.remove("dragover");
      const files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length > 0) {
        input.files = files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    refreshStatus();
    attachDrop("ss-file");
    attachDrop("qr-input");
  });
})();

/* ScamShield theme toggle — presentation only. Stored choice wins;
   otherwise the OS prefers-color-scheme applies on first visit. */
(function () {
  "use strict";

  var STORAGE_KEY = "scamshield-theme";

  function readStored() {
    try {
      return window.localStorage.getItem(STORAGE_KEY);
    } catch (err) {
      return null;
    }
  }

  function storeChoice(theme) {
    try {
      window.localStorage.setItem(STORAGE_KEY, theme);
    } catch (err) {
      /* private mode etc. — theme simply won't persist */
    }
  }

  function applyTheme(theme, persist) {
    document.documentElement.dataset.theme = theme;
    const button = document.getElementById("theme-toggle");
    if (button) {
      button.textContent = theme === "light" ? "Dark" : "Light";
    }
    if (persist) {
      storeChoice(theme);
    }
  }

  function initialTheme() {
    const stored = readStored();
    if (stored === "light" || stored === "dark") {
      return stored;
    }
    if (window.matchMedia
      && window.matchMedia("(prefers-color-scheme: light)").matches) {
      return "light";
    }
    return "dark";
  }

  document.addEventListener("DOMContentLoaded", () => {
    applyTheme(initialTheme(), false);
    const button = document.getElementById("theme-toggle");
    if (button) {
      button.addEventListener("click", () => {
        const next = document.documentElement.dataset.theme === "light"
          ? "dark" : "light";
        applyTheme(next, true);
      });
    }
  });
})();

