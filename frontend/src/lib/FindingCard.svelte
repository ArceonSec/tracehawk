<script>
  export let finding;
  export let aiFix = null;
  export let isLoadingAI = false;
  
  let isExpanded = false;

  function toggleExpand() {
    isExpanded = !isExpanded;
  }

  function severityLabel(sev) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return '⛔ CRITICAL';
    if (s === 'HIGH') return '🔴 HIGH';
    if (s === 'MEDIUM') return '🟡 MEDIUM';
    if (s === 'WARNING') return '🟡 WARNING';
    if (s === 'LOW') return '🔵 LOW';
    return s;
  }

  function toolIcon(tool) {
    if (tool === 'semgrep') return '🔍';
    if (tool === 'gitleaks') return '🔑';
    if (tool === 'trivy') return '📦';
    return '🛡️';
  }
</script>

<div class="finding-card glass-card" class:expanded={isExpanded}>
  <!-- Clickable Header Row -->
  <div class="header" on:click={toggleExpand}>
    <div class="header-left">
      <span class="badge badge-{(finding.severity || 'low').toLowerCase()}">{severityLabel(finding.severity)}</span>
      <span class="tool-tag">{toolIcon(finding.tool)} {finding.tool}</span>
    </div>
    <div class="header-right">
      <span class="file-path">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>
        {finding.file || 'unknown'}
      </span>
      {#if finding.line}
        <span class="line-badge">L{finding.line}</span>
      {/if}
      <svg class="chevron {isExpanded ? 'open' : ''}" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
    </div>
  </div>

  <!-- Rule Name + Category + CWE -->
  <div class="rule-row">
    <h3 class="rule-name">{finding.rule}</h3>
    {#if finding.category}
      <span class="category-tag">{finding.category}</span>
    {/if}
    {#if finding.cwe && finding.cwe.length > 0}
      {#each finding.cwe as cweId}
        <span class="cwe-tag">{cweId}</span>
      {/each}
    {/if}
  </div>

  <!-- Why It Was Detected -->
  <div class="detection-reason">
    <div class="reason-icon">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
    </div>
    <p>{finding.message}</p>
  </div>

  <!-- Snippet Preview (always visible if present) -->
  {#if finding.snippet}
    <div class="snippet-preview">
      <div class="snippet-label">
        <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
        Detected Code / Leak
        {#if finding.line}
          <span class="snippet-line">at line {finding.line}</span>
        {/if}
      </div>
      <pre class="snippet-code"><code><span class="danger-highlight">{finding.snippet}</span></code></pre>
    </div>
  {/if}

  <!-- Expanded: Full Detail View -->
  {#if isExpanded}
    <div class="expanded-details">
      <!-- Detail metadata grid -->
      <div class="detail-grid">
        <div class="detail-item">
          <span class="detail-label">Scanner</span>
          <span class="detail-value">{finding.tool}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Rule ID</span>
          <span class="detail-value mono">{finding.rule}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">File</span>
          <span class="detail-value mono">{finding.file || 'N/A'}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Line</span>
          <span class="detail-value">{finding.line || 'N/A'}</span>
        </div>
        {#if finding.category}
          <div class="detail-item wide">
            <span class="detail-label">OWASP / Category</span>
            <span class="detail-value">{finding.category}</span>
          </div>
        {/if}
      </div>

      <!-- AI Remediation Panel -->
      <div class="remediation-panel">
        <div class="panel-header remediation-header">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg>
          AI Remediation (Gemini)
        </div>
        <div class="remediation-body">
          {#if isLoadingAI}
            <div class="placeholder-ai">
              <div class="loading-dots">
                <span></span><span></span><span></span>
              </div>
              <p>Analyzing context and synthesizing patch...</p>
            </div>
          {:else if aiFix}
            {#if aiFix.explanation}
              <div class="fix-explanation">
                <strong>Why this is dangerous:</strong> {aiFix.explanation}
              </div>
            {/if}
            {#if aiFix.vulnerable_code}
              <div class="code-diff-section">
                <div class="diff-label danger">⛔ Vulnerable Code</div>
                <pre class="snippet-code"><code><span class="danger-highlight">{aiFix.vulnerable_code}</span></code></pre>
              </div>
            {/if}
            <div class="code-diff-section">
              <div class="diff-label safe">✅ Remediated Code</div>
              <pre class="remediation-code"><code><span class="safe-text">{aiFix.remediated_code_snippet}</span></code></pre>
            </div>
          {:else}
            <div class="placeholder-ai">
              <p>Use the <strong>"✨ Generate AI Strategy & Fixes"</strong> button above to generate a remediation for this finding.</p>
            </div>
          {/if}
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .finding-card {
    margin-bottom: 16px;
    overflow: hidden;
    transition: border-color 0.3s ease, box-shadow 0.3s ease;
  }
  .finding-card.expanded {
    border-color: rgba(129, 140, 248, 0.4);
    box-shadow: 0 0 20px rgba(129, 140, 248, 0.08);
  }

  /* ── Header ── */
  .header {
    padding: 16px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    gap: 16px;
  }
  .header-left {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
  }
  .header-right {
    display: flex;
    align-items: center;
    gap: 12px;
    min-width: 0;
  }

  .tool-tag {
    font-size: 0.78rem;
    font-family: var(--font-mono);
    color: var(--accent-purple);
    border: 1px solid rgba(176, 82, 255, 0.3);
    padding: 3px 8px;
    border-radius: 4px;
    background: rgba(176, 82, 255, 0.1);
    white-space: nowrap;
  }

  .file-path {
    font-family: var(--font-mono);
    font-size: 0.82rem;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    gap: 5px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 300px;
  }

  .line-badge {
    font-family: var(--font-mono);
    font-size: 0.78rem;
    background: rgba(56, 189, 248, 0.15);
    color: var(--accent-cyan);
    padding: 2px 8px;
    border-radius: 4px;
    border: 1px solid rgba(56, 189, 248, 0.3);
    white-space: nowrap;
  }

  .chevron {
    transition: transform 0.3s ease;
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .chevron.open {
    transform: rotate(180deg);
  }

  /* ── Rule + Category ── */
  .rule-row {
    padding: 0 20px 10px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .rule-name {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    color: var(--text-main);
    word-break: break-word;
  }
  .category-tag {
    font-size: 0.72rem;
    font-family: var(--font-mono);
    color: var(--accent-cyan);
    background: rgba(56, 189, 248, 0.1);
    border: 1px solid rgba(56, 189, 248, 0.25);
    padding: 2px 8px;
    border-radius: 4px;
    white-space: nowrap;
  }

  /* ── Detection Reason ── */
  .detection-reason {
    padding: 0 20px 14px;
    display: flex;
    gap: 8px;
    align-items: flex-start;
  }
  .reason-icon {
    color: var(--medium);
    flex-shrink: 0;
    margin-top: 2px;
  }
  .detection-reason p {
    margin: 0;
    font-size: 0.9rem;
    color: var(--text-muted);
    line-height: 1.5;
  }

  /* ── Snippet Preview ── */
  .snippet-preview {
    margin: 0 20px 16px;
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid rgba(239, 68, 68, 0.25);
    background: rgba(0, 0, 0, 0.4);
  }
  .snippet-label {
    padding: 8px 14px;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.5px;
    color: #fca5a5;
    background: rgba(239, 68, 68, 0.08);
    border-bottom: 1px solid rgba(239, 68, 68, 0.15);
    display: flex;
    align-items: center;
    gap: 6px;
    text-transform: uppercase;
  }
  .snippet-line {
    font-weight: 400;
    text-transform: none;
    color: var(--text-muted);
    margin-left: 6px;
  }
  .snippet-code {
    margin: 0;
    padding: 12px 16px;
    font-family: var(--font-mono);
    font-size: 0.85rem;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
  }
  .danger-highlight {
    display: block;
    padding: 4px 8px;
    border-left: 3px solid var(--critical);
    background: rgba(239, 68, 68, 0.12);
    color: #fca5a5;
  }

  /* ── Expanded Details ── */
  .expanded-details {
    border-top: 1px solid var(--glass-border);
    padding: 20px;
    animation: slideDown 0.2s ease-out;
  }
  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .detail-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
    padding: 16px;
    background: rgba(0, 0, 0, 0.25);
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.05);
  }
  .detail-item {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .detail-item.wide {
    grid-column: 1 / -1;
  }
  .detail-label {
    font-size: 0.7rem;
    font-family: var(--font-mono);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .detail-value {
    font-size: 0.88rem;
    color: var(--text-main);
    word-break: break-word;
  }
  .detail-value.mono {
    font-family: var(--font-mono);
    font-size: 0.82rem;
  }

  /* ── Remediation Panel ── */
  .remediation-panel {
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid rgba(56, 189, 248, 0.2);
  }
  .panel-header {
    padding: 10px 16px;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.5px;
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--bg-surface-elevated);
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }
  .remediation-header {
    color: var(--accent-cyan);
  }
  .remediation-body {
    padding: 16px;
    background: rgba(0, 0, 0, 0.3);
    min-height: 80px;
  }

  .placeholder-ai {
    color: var(--text-muted);
    font-size: 0.88rem;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
  }
  .placeholder-ai p {
    margin: 0;
    line-height: 1.5;
  }

  .remediation-code {
    margin: 0;
    padding: 12px 16px;
    font-family: var(--font-mono);
    font-size: 0.85rem;
    white-space: pre-wrap;
  }
  .safe-text {
    color: #6ee7b7;
    white-space: pre-wrap;
  }

  /* CWE Tags */
  .cwe-tag {
    font-size: 0.7rem;
    font-family: var(--font-mono);
    color: #93c5fd;
    background: rgba(59, 130, 246, 0.12);
    border: 1px solid rgba(59, 130, 246, 0.25);
    padding: 2px 7px;
    border-radius: 4px;
    white-space: nowrap;
  }

  /* Code Diff Sections */
  .code-diff-section {
    margin-top: 12px;
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid rgba(255, 255, 255, 0.08);
  }
  .diff-label {
    padding: 6px 14px;
    font-family: var(--font-mono);
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }
  .diff-label.danger {
    color: #fca5a5;
    background: rgba(239, 68, 68, 0.08);
    border-bottom: 1px solid rgba(239, 68, 68, 0.15);
  }
  .diff-label.safe {
    color: #6ee7b7;
    background: rgba(16, 185, 129, 0.08);
    border-bottom: 1px solid rgba(16, 185, 129, 0.15);
  }

  /* Fix Explanation */
  .fix-explanation {
    margin-bottom: 12px;
    padding: 10px 14px;
    font-size: 0.88rem;
    line-height: 1.5;
    color: var(--text-muted);
    background: rgba(0, 0, 0, 0.15);
    border-radius: 6px;
    border-left: 3px solid var(--accent-cyan);
  }
  .fix-explanation strong {
    color: var(--accent-cyan);
  }

  /* Loading dots animation */
  .loading-dots {
    display: flex;
    gap: 4px;
  }
  .loading-dots span {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent-cyan);
    animation: dot-pulse 1.4s ease-in-out infinite;
  }
  .loading-dots span:nth-child(2) { animation-delay: 0.2s; }
  .loading-dots span:nth-child(3) { animation-delay: 0.4s; }
  @keyframes dot-pulse {
    0%, 80%, 100% { opacity: 0.3; transform: scale(0.8); }
    40% { opacity: 1; transform: scale(1.2); }
  }
</style>
