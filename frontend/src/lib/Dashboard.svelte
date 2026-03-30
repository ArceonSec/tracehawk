<script>
  import PipelineAnimation from './PipelineAnimation.svelte';
  import FindingCard from './FindingCard.svelte';

  export let isScanning = false;
  export let recentScan = null;
  
  let scanMode = 'repo'; // 'repo' or 'snippet'
  let targetUrl = './test-repos';
  let snippetCode = '';
  let snippetFilename = 'script.py';
  let errorMsg = '';

  async function startScan() {
    if (!targetUrl) return;
    isScanning = true;
    errorMsg = '';
    recentScan = null;

    try {
      let bodyData = { tools: 'semgrep,gitleaks,trivy', output: 'json' };
      if (scanMode === 'repo') {
        bodyData.target = targetUrl;
      } else {
        bodyData.target = '';
        bodyData.code_snippet = snippetCode;
        bodyData.filename = snippetFilename;
      }

      // Simulate delay for the pipeline UI if it resolves too quickly
      const scanPromise = fetch('http://localhost:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bodyData)
      });

      // Let animation run for at least 8 seconds
      const [response, _] = await Promise.all([
        scanPromise,
        new Promise(r => setTimeout(r, 8000))
      ]);

      if (!response.ok) {
        throw new Error('API Execution Failed');
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
          <h2 class="section-title">Detected Findings</h2>
          {#if recentScan.findings && recentScan.findings.length > 0}
            {#each recentScan.findings as finding}
              <FindingCard {finding} />
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
    background: #000;
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
    margin-bottom: 20px;
    font-size: 1.4rem;
    color: var(--accent-cyan);
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
</style>
