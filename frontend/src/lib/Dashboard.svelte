<script>
  import PipelineAnimation from './PipelineAnimation.svelte';
  import FindingCard from './FindingCard.svelte';
  import { API_URL, API_KEY } from './config.js';
  import { marked } from 'marked';

  export let isScanning = false;
  export let recentScan = null;
  
  let scanMode = 'repo'; // 'repo' or 'snippet'
  let targetUrl = './test-repos';
  let snippetCode = '';
  let snippetFilename = 'script.py';
  let errorMsg = '';
  let aiResults = {};
  let loadingAI = {};

  async function startScan() {
    if (!targetUrl) return;
    isScanning = true;
    errorMsg = '';
    recentScan = null;
    aiResults = {};
    loadingAI = {};

    try {
      let bodyData = { tools: 'semgrep,gitleaks,trivy', output: 'json' };
      if (scanMode === 'repo') {
        bodyData.target = targetUrl;
      } else {
        bodyData.target = '';
        bodyData.code_snippet = snippetCode;
        bodyData.filename = snippetFilename;
      }

      const scanPromise = fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify(bodyData)
      });

      // Let animation run for at least 8 seconds
      const [response, _] = await Promise.all([
        scanPromise,
        new Promise(r => setTimeout(r, 8000))
      ]);

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        throw new Error(errBody.detail || `API returned ${response.status}`);
      }

      recentScan = await response.json();
    } catch (err) {
      errorMsg = err.message || 'Failed to execute security pipeline.';
    } finally {
      isScanning = false;
    }
  }

  function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    snippetFilename = file.name;
    const reader = new FileReader();
    reader.onload = (e) => {
      snippetCode = e.target.result;
    };
    reader.readAsText(file);
  }

  async function generateAIBatch(category, findings) {
    if (loadingAI[category]) return;
    loadingAI[category] = true;
    loadingAI = { ...loadingAI };
    
    try {
      const res = await fetch(`${API_URL}/ai/remediate/category`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': API_KEY
        },
        body: JSON.stringify({ category, findings })
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.detail || "Failed to generate AI fix");
      }
      aiResults[category] = await res.json();
      aiResults = { ...aiResults };
    } catch (err) {
      console.error(err);
      alert("Error generating fix: " + err.message);
    } finally {
      loadingAI[category] = false;
      loadingAI = { ...loadingAI };
    }
  }

  function esc(str) {
    return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function severityBadge(sev) {
    const s = (sev || '').toUpperCase();
    const colors = { CRITICAL:'#dc2626', HIGH:'#e07020', MEDIUM:'#c59a1e', LOW:'#3b6fcf' };
    const bg     = { CRITICAL:'rgba(220,38,38,0.15)', HIGH:'rgba(224,112,32,0.15)', MEDIUM:'rgba(197,154,30,0.15)', LOW:'rgba(59,111,207,0.15)' };
    const txt    = { CRITICAL:'#f87171', HIGH:'#fb923c', MEDIUM:'#e2c54a', LOW:'#7ba8e0' };
    const border = colors[s] || '#6b7280';
    return `<span style="display:inline-block;padding:3px 10px;border-radius:4px;font-size:0.75rem;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:0.5px;border:1px solid ${border};background:${bg[s]||'rgba(107,114,128,0.15)'};color:${txt[s]||'#9ca3af'};">${esc(s || 'UNKNOWN')}</span>`;
  }

  function downloadReport() {
    if (!recentScan) return;
    const date = recentScan.completed_at || new Date().toISOString();

    // ── Build severity summary cards ──
    let sevCards = '';
    const sevOrder = ['CRITICAL','HIGH','MEDIUM','LOW'];
    const sevColors = { CRITICAL:'#f87171', HIGH:'#fb923c', MEDIUM:'#e2c54a', LOW:'#7ba8e0' };
    for (const s of sevOrder) {
      const count = (recentScan.severity_counts || {})[s] || 0;
      sevCards += `<div style="text-align:center;min-width:100px;"><div style="font-size:2.2rem;font-weight:700;font-family:'JetBrains Mono',monospace;color:${sevColors[s]};">${count}</div><div style="font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;color:#6b7280;margin-top:4px;">${s}</div></div>`;
    }

    // ── Build findings HTML ──
    let findingsHtml = '';
    if (recentScan.categorized_findings) {
      for (const [category, findings] of Object.entries(recentScan.categorized_findings)) {
        findingsHtml += `<div style="margin-bottom:36px;">`;
        findingsHtml += `<h2 style="font-family:'JetBrains Mono',monospace;font-size:1.15rem;color:#dde1e8;margin:0 0 6px 0;padding-bottom:10px;border-bottom:1px solid rgba(255,255,255,0.08);">${esc(category)} <span style="font-size:0.78rem;font-weight:400;background:rgba(255,255,255,0.08);color:#6b7280;padding:3px 10px;border-radius:12px;margin-left:10px;">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span></h2>`;

        // AI strategy block
        if (aiResults[category]?.category_explanation) {
          findingsHtml += `<div style="margin:14px 0 20px;padding:16px 20px;background:rgba(176,82,255,0.07);border:1px solid rgba(176,82,255,0.25);border-radius:8px;"><div style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;font-weight:600;color:#7c85c7;margin-bottom:10px;">✦ AI Security Strategy</div><div style="font-size:0.9rem;line-height:1.7;color:#c8cdd5;">${esc(aiResults[category].category_explanation)}</div></div>`;
        }

        for (let idx = 0; idx < findings.length; idx++) {
          const f = findings[idx];
          findingsHtml += `<div style="background:#111318;border:1px solid rgba(255,255,255,0.06);border-radius:8px;margin-bottom:14px;overflow:hidden;">`;

          // Header row
          findingsHtml += `<div style="padding:14px 18px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">`;
          findingsHtml += `<div style="display:flex;align-items:center;gap:10px;">${severityBadge(f.severity)}<span style="font-size:0.78rem;font-family:'JetBrains Mono',monospace;color:#7c85c7;border:1px solid rgba(176,82,255,0.3);padding:3px 8px;border-radius:4px;background:rgba(176,82,255,0.1);">${esc(f.tool)}</span></div>`;
          findingsHtml += `<div style="display:flex;align-items:center;gap:10px;font-family:'JetBrains Mono',monospace;font-size:0.82rem;color:#6b7280;">`;
          if (f.file) findingsHtml += `<span>${esc(f.file)}</span>`;
          if (f.line) findingsHtml += `<span style="background:rgba(56,189,248,0.15);color:#5eafd6;padding:2px 8px;border-radius:4px;border:1px solid rgba(56,189,248,0.3);font-size:0.78rem;">L${f.line}</span>`;
          findingsHtml += `</div></div>`;

          // Rule + CWE row
          findingsHtml += `<div style="padding:0 18px 10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">`;
          findingsHtml += `<strong style="font-size:1rem;color:#dde1e8;">${esc(f.rule)}</strong>`;
          if (f.cwe && f.cwe.length) {
            for (const cid of f.cwe) {
              findingsHtml += `<span style="font-size:0.7rem;font-family:'JetBrains Mono',monospace;color:#93c5fd;background:rgba(59,130,246,0.12);border:1px solid rgba(59,130,246,0.25);padding:2px 7px;border-radius:4px;">${esc(cid)}</span>`;
            }
          }
          findingsHtml += `</div>`;

          // Message
          if (f.message) {
            findingsHtml += `<div style="padding:0 18px 14px;font-size:0.9rem;color:#6b7280;line-height:1.5;">${esc(f.message)}</div>`;
          }

          // Code snippet
          if (f.snippet) {
            findingsHtml += `<div style="margin:0 18px 16px;border-radius:6px;overflow:hidden;border:1px solid rgba(239,68,68,0.25);background:rgba(0,0,0,0.4);">`;
            findingsHtml += `<div style="padding:8px 14px;font-family:'JetBrains Mono',monospace;font-size:0.72rem;font-weight:600;letter-spacing:0.5px;color:#fca5a5;background:rgba(239,68,68,0.08);border-bottom:1px solid rgba(239,68,68,0.15);text-transform:uppercase;">Detected Code${f.line ? ' — line ' + f.line : ''}</div>`;
            findingsHtml += `<pre style="margin:0;padding:12px 16px;font-family:'JetBrains Mono',monospace;font-size:0.85rem;white-space:pre-wrap;word-break:break-all;line-height:1.6;"><code><span style="display:block;padding:4px 8px;border-left:3px solid #dc2626;background:rgba(239,68,68,0.12);color:#fca5a5;">${esc(f.snippet)}</span></code></pre>`;
            findingsHtml += `</div>`;
          }

          // AI fix
          const fix = aiResults[category]?.fixes?.[idx];
          if (fix) {
            findingsHtml += `<div style="margin:0 18px 16px;border:1px solid rgba(56,189,248,0.2);border-radius:8px;overflow:hidden;">`;
            findingsHtml += `<div style="padding:10px 16px;font-family:'JetBrains Mono',monospace;font-size:0.78rem;font-weight:600;color:#5eafd6;background:#1a1d24;border-bottom:1px solid rgba(255,255,255,0.05);">AI Remediation (Gemini)</div>`;
            findingsHtml += `<div style="padding:14px 16px;background:rgba(0,0,0,0.3);">`;
            if (fix.explanation) {
              findingsHtml += `<div style="margin-bottom:12px;padding:10px 14px;font-size:0.88rem;line-height:1.5;color:#6b7280;background:rgba(0,0,0,0.15);border-radius:6px;border-left:3px solid #5eafd6;"><strong style="color:#5eafd6;">Why this is dangerous:</strong> ${esc(fix.explanation)}</div>`;
            }
            if (fix.vulnerable_code) {
              findingsHtml += `<div style="margin-bottom:10px;border-radius:6px;overflow:hidden;border:1px solid rgba(255,255,255,0.08);">`;
              findingsHtml += `<div style="padding:6px 14px;font-family:'JetBrains Mono',monospace;font-size:0.72rem;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;color:#fca5a5;background:rgba(239,68,68,0.08);border-bottom:1px solid rgba(239,68,68,0.15);">⛔ Vulnerable Code</div>`;
              findingsHtml += `<pre style="margin:0;padding:12px 16px;font-family:'JetBrains Mono',monospace;font-size:0.85rem;white-space:pre-wrap;"><code style="color:#fca5a5;">${esc(fix.vulnerable_code)}</code></pre></div>`;
            }
            findingsHtml += `<div style="border-radius:6px;overflow:hidden;border:1px solid rgba(255,255,255,0.08);">`;
            findingsHtml += `<div style="padding:6px 14px;font-family:'JetBrains Mono',monospace;font-size:0.72rem;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;color:#6ee7b7;background:rgba(16,185,129,0.08);border-bottom:1px solid rgba(16,185,129,0.15);">✅ Remediated Code</div>`;
            findingsHtml += `<pre style="margin:0;padding:12px 16px;font-family:'JetBrains Mono',monospace;font-size:0.85rem;white-space:pre-wrap;"><code style="color:#6ee7b7;">${esc(fix.remediated_code_snippet)}</code></pre></div>`;
            findingsHtml += `</div></div>`;
          }

          findingsHtml += `</div>`; // close finding card
        }
        findingsHtml += `</div>`; // close category group
      }
    }

    // ── Assemble full HTML document ──
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TraceHawk Security Report — ${esc(recentScan.scan_id)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: #08090d;
    color: #c8cdd5;
    min-height: 100vh;
    padding: 40px 20px;
    background-image:
      radial-gradient(circle at 20% 60%, rgba(92,88,160,0.025), transparent 30%),
      radial-gradient(circle at 80% 25%, rgba(94,175,214,0.02), transparent 30%);
  }
  .container { max-width: 960px; margin: 0 auto; }
  .report-header {
    text-align: center;
    margin-bottom: 40px;
    padding-bottom: 30px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
  }
  .report-header h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.8rem;
    font-weight: 700;
    background: linear-gradient(to right, #5eafd6, #7c85c7);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 16px;
  }
  .meta-grid {
    display: flex;
    justify-content: center;
    gap: 28px;
    flex-wrap: wrap;
    margin-top: 16px;
  }
  .meta-item {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: #6b7280;
  }
  .meta-item strong { color: #5eafd6; }
  .severity-bar {
    display: flex;
    justify-content: center;
    gap: 30px;
    flex-wrap: wrap;
    padding: 22px;
    margin-bottom: 36px;
    background: rgba(255,255,255,0.015);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px;
  }
  .total-badge {
    text-align: center;
    padding-right: 30px;
    border-right: 1px solid rgba(255,255,255,0.08);
    margin-right: 10px;
  }
  .total-badge .num {
    font-size: 2.6rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    color: #dde1e8;
  }
  .total-badge .lbl {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #6b7280;
    margin-top: 4px;
  }
  .footer {
    text-align: center;
    margin-top: 50px;
    padding-top: 24px;
    border-top: 1px solid rgba(255,255,255,0.06);
    font-size: 0.78rem;
    color: #4b5563;
    font-family: 'JetBrains Mono', monospace;
  }
  @media print {
    body { background: #08090d !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>
</head>
<body>
<div class="container">
  <div class="report-header">
    <h1>TRACEHAWK — Security Report</h1>
    <div class="meta-grid">
      <div class="meta-item"><strong>Target:</strong> ${esc(recentScan.target)}</div>
      <div class="meta-item"><strong>Scan ID:</strong> ${esc(recentScan.scan_id)}</div>
      <div class="meta-item"><strong>Date:</strong> ${esc(date)}</div>
    </div>
  </div>

  <div class="severity-bar">
    <div class="total-badge">
      <div class="num">${recentScan.total_findings}</div>
      <div class="lbl">Total Findings</div>
    </div>
    ${sevCards}
  </div>

  ${findingsHtml}

  <div class="footer">
    Report generated by TraceHawk DevSecOps Scanner &middot; ${esc(date)}
  </div>
</div>
</body>
</html>`;

    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tracehawk-report-${recentScan.scan_id}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

<div class="dashboard-wrapper">
  <div class="header-section">
    <h1>Security Dashboard</h1>
    <p class="subtitle">Shift-left continuous security analysis pipeline.</p>
  </div>

  <div class="trigger-card glass-panel">
    <div class="mode-toggle">
      <button class="toggle-btn {scanMode === 'repo' ? 'active' : ''}" on:click={() => scanMode = 'repo'}>Repository URL</button>
      <button class="toggle-btn {scanMode === 'snippet' ? 'active' : ''}" on:click={() => scanMode = 'snippet'}>Code Snippet</button>
    </div>

    {#if scanMode === 'repo'}
      <div class="input-group">
        <div class="field">
          <label for="target">Target Path / Git URL</label>
          <input 
            id="target" 
            type="text" 
            class="input-field" 
            bind:value={targetUrl} 
            disabled={isScanning}
            placeholder="e.g. ./test-repos or https://github.com/user/repo" 
          />
        </div>
        <button 
          class="btn btn-primary scan-btn {isScanning ? 'scanning' : ''}" 
          on:click={startScan} 
          disabled={isScanning}>
          {#if isScanning}
            <svg class="spin" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"></path></svg>
            Executing...
          {:else}
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
            Scan Repo
          {/if}
        </button>
      </div>
    {:else}
      <div class="snippet-warning">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        Snippet scanning officially supports Python (.py) and JavaScript (.js) only right now.
      </div>
      
      <div class="snippet-controls">
        <input 
          type="text" 
          class="input-field filename-input" 
          bind:value={snippetFilename} 
          placeholder="Filename (e.g. script.py)" 
          disabled={isScanning}
        />
        <input 
          type="file" 
          id="file-upload" 
          class="hidden" 
          accept=".py,.js,.ts" 
          on:change={handleFileUpload}
          disabled={isScanning}
        />
        <label for="file-upload" class="btn btn-outline file-upload-btn" class:disabled={isScanning}>Upload File</label>
        
        <button 
          class="btn btn-primary scan-btn {isScanning ? 'scanning' : ''}" 
          on:click={startScan} 
          disabled={isScanning || !snippetCode}>
          {#if isScanning}
            <svg class="spin" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"></path></svg>
            Analyzing...
          {:else}
            Analyze Snippet
          {/if}
        </button>
      </div>

      <textarea 
        class="input-field code-textarea" 
        bind:value={snippetCode} 
        placeholder="Paste your source code here..."
        disabled={isScanning}
        spellcheck="false"
      ></textarea>
    {/if}
    {#if errorMsg}
      <div class="error-banner">
        <strong>Error:</strong> {errorMsg}
      </div>
    {/if}
  </div>

  <div class="content-grid">
    <!-- Pipeline Animator logs output -->
    <div class="pipeline-section">
      <PipelineAnimation {isScanning} />
    </div>

    <!-- Results Section -->
    <div class="results-section">
      {#if isScanning}
        <div class="loading-state glass-panel">
          <h3>Analyzing Telemetry...</h3>
          <p>Please wait while TRACEHAWK sweeps the target for vulnerabilities and secrets.</p>
        </div>
      {:else if recentScan}
        <div class="summary-card glass-panel">
          <div class="stat">
            <span class="value">{recentScan.total_findings}</span>
            <span class="label">Total Alerts</span>
          </div>
          <div class="stat">
            <span class="value critical">{recentScan.severity_counts?.CRITICAL || 0}</span>
            <span class="label">Critical</span>
          </div>
          <div class="stat">
            <span class="value high">{recentScan.severity_counts?.HIGH || 0}</span>
            <span class="label">High</span>
          </div>
          <div class="stat">
            <span class="value medium">{recentScan.severity_counts?.MEDIUM || 0}</span>
            <span class="label">Medium</span>
          </div>
        </div>

        <div class="findings-list">
          <div class="findings-header">
            <h2 class="section-title">Detected Findings</h2>
            <button class="btn btn-outline download-btn" on:click={downloadReport}>
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
              Download Report (.html)
            </button>
          </div>
          {#if recentScan.categorized_findings && Object.keys(recentScan.categorized_findings).length > 0}
            {#each Object.entries(recentScan.categorized_findings) as [category, findings]}
              <div class="category-group">
                <div class="category-header">
                  <h3>{category} <span class="badge badge-count">{findings.length} findings</span></h3>
                  <button class="btn btn-outline ai-batch-btn" class:scanning={loadingAI[category]} on:click={() => generateAIBatch(category, findings)} disabled={loadingAI[category]}>
                    {#if loadingAI[category]}
                      ✨ Processing...
                    {:else}
                      ✨ Generate AI Strategy & Fixes
                    {/if}
                  </button>
                </div>
                
                {#if aiResults[category]}
                  <div class="ai-batch-result glass-panel">
                    <h4>✦ AI Security Strategy</h4>
                    <div class="ai-explanation">{@html marked(aiResults[category].category_explanation || '')}</div>
                  </div>
                {/if}

                {#each findings as finding}
                  <FindingCard {finding} aiFix={aiResults[category]?.fixes?.[findings.indexOf(finding)]} isLoadingAI={loadingAI[category]} />
                {/each}
              </div>
            {/each}
          {:else}
            <div class="all-clear glass-panel">
              <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
              <h3>Pipeline Secure</h3>
              <p>No vulnerabilities or secrets detected in the target branch.</p>
            </div>
          {/if}
        </div>
      {:else}
        <div class="empty-state glass-panel">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg>
          <h3>Awaiting Target Acquisition</h3>
          <p>Enter a target path and initialize the scan to begin security telemetry.</p>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .dashboard-wrapper {
    padding: 10px;
    max-width: 1200px;
    margin: 0 auto;
  }

  .header-section {
    margin-bottom: 30px;
  }
  
  .subtitle {
    color: var(--text-muted);
    font-size: 1.1rem;
    margin-top: 5px;
  }

  .trigger-card {
    padding: 25px;
    margin-bottom: 30px;
  }

  .input-group {
    display: flex;
    gap: 20px;
    align-items: flex-end;
  }

  /* Mode Toggle */
  .mode-toggle {
    display: flex;
    gap: 10px;
    margin-bottom: 25px;
    border-bottom: 1px solid var(--glass-border);
    padding-bottom: 15px;
  }

  .toggle-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    font-family: var(--font-mono);
    font-size: 0.9rem;
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
  }

  .toggle-btn.active {
    background: rgba(129, 140, 248, 0.15);
    color: var(--accent-purple);
  }

  .toggle-btn:hover:not(.active) {
    color: var(--text-main);
    background: rgba(255, 255, 255, 0.05);
  }

  /* Snippet Styles */
  .snippet-warning {
    display: flex;
    align-items: center;
    gap: 10px;
    color: #facc15;
    background: rgba(250, 204, 21, 0.1);
    padding: 10px 15px;
    border-radius: 6px;
    border: 1px solid rgba(250, 204, 21, 0.3);
    font-size: 0.85rem;
    margin-bottom: 20px;
  }

  .snippet-controls {
    display: flex;
    gap: 15px;
    margin-bottom: 15px;
    align-items: center;
  }

  .filename-input {
    flex: 1;
    padding: 10px;
  }

  .hidden {
    display: none;
  }

  .file-upload-btn {
    padding: 10px 20px;
    cursor: pointer;
    margin: 0;
  }
  
  .file-upload-btn.disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .code-textarea {
    min-height: 200px;
    font-family: var(--font-mono);
    resize: vertical;
    line-height: 1.5;
    background: var(--bg-base);
  }

  .field {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .field label {
    font-family: var(--font-mono);
    font-size: 0.85rem;
    color: var(--accent-cyan);
    letter-spacing: 1px;
    text-transform: uppercase;
  }

  .scan-btn {
    height: 48px;
    padding: 0 30px;
  }

  .spin {
    animation: spin 1.5s linear infinite;
  }

  @keyframes spin {
    100% { transform: rotate(360deg); }
  }

  .error-banner {
    margin-top: 15px;
    padding: 12px;
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--critical);
    border-radius: 6px;
    color: #fca5a5;
    font-size: 0.9rem;
  }

  /* Grid Layout */
  .content-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 30px;
  }

  .summary-card {
    display: flex;
    justify-content: space-around;
    padding: 20px;
    margin-bottom: 30px;
  }

  .stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 5px;
  }

  .value {
    font-size: 2.5rem;
    font-weight: 700;
    font-family: var(--font-mono);
  }
  .value.critical { color: var(--critical); }
  .value.high { color: var(--high); }
  .value.medium { color: var(--medium); }

  .label {
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 1px;
    color: var(--text-muted);
  }

  .section-title {
    font-size: 1.3rem;
    color: var(--accent-cyan);
  }

  .findings-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
  }

  .download-btn {
    font-size: 0.8rem;
    padding: 8px 16px;
    color: var(--accent-cyan);
    border-color: rgba(94, 175, 214, 0.3);
  }
  .download-btn:hover {
    background: rgba(94, 175, 214, 0.1);
  }

  .empty-state, .all-clear, .loading-state {
    padding: 60px 40px;
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 15px;
    color: var(--text-muted);
  }

  .empty-state h3, .all-clear h3, .loading-state h3 {
    margin: 0;
    font-size: 1.3rem;
  }

  .all-clear {
    border-color: rgba(129, 140, 248, 0.4);
    background: rgba(129, 140, 248, 0.05);
  }
  .all-clear h3 {
    color: var(--accent-purple);
  }

  .category-group {
    margin-bottom: 40px;
  }

  .category-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 1px solid rgba(255,255,255,0.1);
  }

  .category-header h3 {
    margin: 0;
    font-size: 1.2rem;
    color: var(--text-main);
    display: flex;
    align-items: center;
    gap: 15px;
  }

  .badge-count {
    background: rgba(255,255,255,0.1);
    color: var(--text-muted);
    font-size: 0.8rem;
    padding: 3px 8px;
    border-radius: 12px;
  }

  .ai-batch-btn {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    font-size: 0.9rem;
    color: var(--accent-cyan);
    border-color: rgba(0, 240, 255, 0.4);
    background: rgba(0, 240, 255, 0.05);
  }

  .ai-batch-btn:hover:not(:disabled) {
    background: rgba(0, 240, 255, 0.15);
  }

  .ai-batch-result {
    margin-bottom: 20px;
    padding: 15px 20px;
    background: rgba(176, 82, 255, 0.08);
    border-color: rgba(176, 82, 255, 0.3);
  }

  .ai-batch-result h4 {
    margin: 0 0 10px 0;
    color: var(--accent-purple);
  }

  .ai-explanation {
    margin: 0;
    line-height: 1.7;
    color: var(--text-main);
    font-size: 0.9rem;
  }
  .ai-explanation :global(p) {
    margin: 0 0 8px 0;
  }
  .ai-explanation :global(ul),
  .ai-explanation :global(ol) {
    margin: 8px 0;
    padding-left: 20px;
  }
  .ai-explanation :global(li) {
    margin-bottom: 4px;
  }
  .ai-explanation :global(strong) {
    color: #dde1e8;
  }
  .ai-explanation :global(code) {
    background: rgba(255,255,255,0.06);
    padding: 1px 5px;
    border-radius: 3px;
    font-family: var(--font-mono);
    font-size: 0.85em;
  }
  .ai-explanation :global(h2),
  .ai-explanation :global(h3) {
    font-size: 1rem;
    margin: 12px 0 6px 0;
    color: var(--accent-purple);
  }
</style>
