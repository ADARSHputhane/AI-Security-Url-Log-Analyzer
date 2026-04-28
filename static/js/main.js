// Utility function to handle button loading states
function setLoading(buttonId, isLoading, originalText) {
  const btn = document.getElementById(buttonId);
  if (isLoading) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Analyzing...`;
  } else {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
}

// Utility function to format and display results
function displayResult(elementId, data, isError = false, isMalicious = false) {
  const div = document.getElementById(elementId);
  div.classList.remove("hidden", "status-safe", "status-danger");

  if (isError) {
    div.classList.add("status-danger");
    div.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <strong>Error:</strong> ${data}`;
    return;
  }

  if (isMalicious) {
    div.classList.add("status-danger");
    div.innerHTML = `<i class="fa-solid fa-circle-xmark"></i> <strong>Threat Detected:</strong> ${data.prediction} <br>
                         <span style="color: var(--text-secondary); font-size: 0.85em;">Confidence: ${data.confidence}%</span>`;
  } else {
    div.classList.add("status-safe");
    div.innerHTML = `<i class="fa-solid fa-circle-check"></i> <strong>Status:</strong> ${data.prediction} <br>
                         <span style="color: var(--text-secondary); font-size: 0.85em;">Confidence: ${data.confidence}%</span>`;
  }
}

async function analyzeURL() {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) return;

  setLoading("urlBtn", true, "Scan URL");

  try {
    const response = await fetch("/api/analyze-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await response.json();

    if (response.ok) {
      const isMalicious = data.prediction.toLowerCase().includes("malicious");
      displayResult("urlResult", data, false, isMalicious);
    } else {
      displayResult("urlResult", data.error, true);
    }
  } catch (err) {
    displayResult("urlResult", "Server connection failed.", true);
  } finally {
    setLoading("urlBtn", false, "Scan URL");
  }
}

async function analyzeLog() {
  const log = document.getElementById("logInput").value.trim();
  if (!log) return;

  setLoading("logBtn", true, "Analyze Log");

  try {
    const response = await fetch("/api/analyze-log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ log }),
    });
    const data = await response.json();

    if (response.ok) {
      const isAnomaly = data.prediction !== "Normal Web Traffic";
      displayResult("logResult", data, false, isAnomaly);
    } else {
      displayResult("logResult", data.error, true);
    }
  } catch (err) {
    displayResult("logResult", "Server connection failed.", true);
  } finally {
    setLoading("logBtn", false, "Analyze Log");
  }
}
