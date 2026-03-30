<script>
  import { onMount } from 'svelte';
  export let isScanning = false;
  
  let logs = [];
  const pipelineSteps = [
    { text: "[sys] Authenticating Docker Socket...", delay: 200 },
    { text: "[sys] Initializing isolated tracing container...", delay: 600 },
    { text: "[git] Expanding repository tree (/app/target)...", delay: 1200 },
    { text: "[sast] Loading Semgrep ruleset (p/security-audit)...", delay: 1800 },
    { text: "[sast] Analyzing AST logic patterns...", delay: 2800 },
    { text: "[gitleaks] Sweeping revision history for hardcoded tokens...", delay: 3600 },
    { text: "[gitleaks] Detecting AWS/GCP/Auth keys...", delay: 4200 },
    { text: "[trivy] Updating Vulnerability DB (fs)...", delay: 5000 },
    { text: "[trivy] Correlating package signatures against CVE lists...", delay: 6500 },
    { text: "[sys] Aggregating final findings payload...", delay: 7500 }
  ];

  let timeouts = [];

  $: if (isScanning && logs.length === 0) {
    logs = [];
    startAnimation();
  }

  $: if (!isScanning && timeouts.length > 0) {
    timeouts.forEach(clearTimeout);
    timeouts = [];
    if (logs.length > 0) {
      logs = [...logs, { text: "[sys] Scan Terminated. Awaiting next command.", severity: "success" }];
    }
  }

  function startAnimation() {
    pipelineSteps.forEach((step, index) => {
      const t = setTimeout(() => {
        logs = [...logs, step];
        scrollToBottom();
      }, step.delay);
      timeouts.push(t);
    });
  }

  function scrollToBottom() {
    const term = document.getElementById('terminal-view');
    if (term) {
      term.scrollTop = term.scrollHeight;
    }
  }
</script>

<div class="pipeline-card glass-panel">
  <div class="card-header">
    <div class="dots">
      <span class="dot red"></span>
      <span class="dot yellow"></span>
      <span class="dot green"></span>
    </div>
    <span class="title">TRACEHAWK /// Execution Pipeline</span>
    <div class="badge {isScanning ? 'scanning' : 'idle'}">
      {isScanning ? 'SCAN IN PROGRESS' : 'IDLE'}
    </div>
  </div>

  <div class="terminal" id="terminal-view">
    {#if logs.length === 0 && !isScanning}
      <p class="placeholder">Awaiting target parameters...</p>
    {/if}
    
    {#each logs as log}
      <div class="log-line">
        <span class="prompt">$</span> 
        <span class="text {log.severity === 'success' ? 'success' : ''}">{log.text}</span>
      </div>
    {/each}
    
    {#if isScanning}
      <div class="log-line typing">
        <span class="prompt">$</span> 
        <span class="cursor">_</span>
      </div>
    {/if}
  </div>
</div>

<style>
  .pipeline-card {
    height: 350px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .card-header {
    background: rgba(0, 0, 0, 0.5);
    padding: 12px 20px;
    display: flex;
    align-items: center;
    border-bottom: 1px solid var(--glass-border);
  }

  .dots {
    display: flex;
    gap: 8px;
    margin-right: 20px;
  }
  .dot { width: 12px; height: 12px; border-radius: 50%; }
  .dot.red { background: #ef4444; }
  .dot.yellow { background: #facc15; }
  .dot.green { background: #22c55e; }

  .title {
    font-family: var(--font-mono);
    color: var(--text-muted);
    font-size: 0.85rem;
    flex: 1;
    letter-spacing: 1px;
  }

  .badge {
    font-family: var(--font-mono);
    font-size: 0.7rem;
    padding: 4px 10px;
    border-radius: 20px;
    font-weight: 700;
  }
  .badge.idle { background: rgba(255, 255, 255, 0.1); color: var(--text-muted); }
  .badge.scanning { 
    background: rgba(99, 102, 241, 0.1); 
    color: var(--accent-purple);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
  }

  .terminal {
    flex: 1;
    background: #0f172a; /* Slate 900 */
    padding: 20px;
    font-family: var(--font-mono);
    font-size: 0.9rem;
    color: #4ade80; /* Softer terminal green */
    overflow-y: auto;
    scroll-behavior: smooth;
  }

  .placeholder {
    color: var(--text-muted);
    font-style: italic;
    opacity: 0.5;
  }

  .log-line {
    margin-bottom: 8px;
    display: flex;
    gap: 12px;
  }

  .prompt {
    color: var(--accent-pink);
    font-weight: 700;
  }

  .text.success {
    color: var(--accent-cyan);
    font-weight: bold;
  }

  .cursor {
    animation: blink 1s step-end infinite;
    color: white;
  }

  @keyframes blink {
    50% { opacity: 0; }
  }
</style>
