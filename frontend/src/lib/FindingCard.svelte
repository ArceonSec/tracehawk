<script>
  export let finding;
  
  let isExpanded = false;

  function toggleExpand() {
    isExpanded = !isExpanded;
  }
</script>

<div class="finding-card glass-card">
  <div class="header" on:click={toggleExpand}>
    <div class="meta">
      <span class="badge badge-{finding.severity.toLowerCase()}">{finding.severity}</span>
      <span class="tool-tag">{finding.tool}</span>
      <h3 class="rule">{finding.rule}</h3>
    </div>
    <div class="file-info">
      <span class="file">{finding.file}</span>
      {#if finding.line}
        <span class="line">Line {finding.line}</span>
      {/if}
      <svg class="chevron {isExpanded ? 'open' : ''}" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
    </div>
  </div>

  <div class="message">
    {finding.message}
  </div>

  {#if isExpanded}
    <div class="code-diff-container">
      <div class="panel vulnerable">
        <div class="panel-header">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
          Detected Vulnerability
        </div>
        <div class="code-block">
          <div class="gutters">
            <span>{finding.line || '-'}</span>
          </div>
          <pre><code><span class="danger-highlight">{finding.message}</span></code></pre>
        </div>
      </div>

      <div class="panel remediated">
        <div class="panel-header">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg>
          AI Remediation (Gemini)
        </div>
        <div class="code-block safe-block">
          <div class="gutters">
            <span>{finding.line || '1'}</span>
          </div>
          <div class="placeholder-ai">
            <p>Gemini integration pending (Phase 4). Remediation logic will be injected here to auto-patch {finding.rule}.</p>
            <button class="btn btn-outline" disabled>Auto-Fix (Coming Soon)</button>
          </div>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .finding-card {
    margin-bottom: 20px;
    overflow: hidden;
  }

  .header {
    padding: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
  }

  .meta {
    display: flex;
    align-items: center;
    gap: 15px;
  }

  .tool-tag {
    font-size: 0.8rem;
    font-family: var(--font-mono);
    color: var(--accent-purple);
    border: 1px solid rgba(176, 82, 255, 0.3);
    padding: 3px 8px;
    border-radius: 4px;
    background: rgba(176, 82, 255, 0.1);
  }

  .rule {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 500;
  }

  .file-info {
    display: flex;
    align-items: center;
    gap: 15px;
    font-family: var(--font-mono);
    font-size: 0.85rem;
    color: var(--text-muted);
  }

  .line {
    background: rgba(255, 255, 255, 0.1);
    padding: 3px 8px;
    border-radius: 4px;
  }

  .chevron {
    transition: transform 0.3s ease;
  }
  .chevron.open {
    transform: rotate(180deg);
  }

  .message {
    padding: 0 20px 20px;
    color: var(--text-main);
    font-size: 0.95rem;
  }

  /* Split Pane Diff */
  .code-diff-container {
    display: grid;
    grid-template-columns: 1fr 1fr;
    border-top: 1px solid var(--glass-border);
    background: #000;
  }

  .panel {
    display: flex;
    flex-direction: column;
  }
  
  .vulnerable {
    border-right: 1px solid var(--glass-border);
  }

  .panel-header {
    padding: 12px 20px;
    font-family: var(--font-mono);
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 1px;
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--bg-surface-elevated);
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }

  .vulnerable .panel-header { color: #fca5a5; }
  .remediated .panel-header { color: var(--accent-cyan); }

  .code-block {
    display: flex;
    padding: 15px 0;
    flex: 1;
    min-height: 120px;
  }

  .gutters {
    width: 40px;
    text-align: right;
    padding-right: 10px;
    color: var(--text-muted);
    font-family: var(--font-mono);
    font-size: 0.85rem;
    user-select: none;
    border-right: 1px solid rgba(255, 255, 255, 0.1);
  }

  pre {
    margin: 0;
    padding: 0 15px;
    font-family: var(--font-mono);
    font-size: 0.85rem;
    white-space: pre-wrap;
    flex: 1;
  }

  .danger-highlight {
    background: rgba(239, 68, 68, 0.2);
    display: block;
    padding: 2px 5px;
    border-left: 2px solid var(--critical);
  }

  .safe-block {
    position: relative;
    background: repeating-linear-gradient(
      -45deg,
      rgba(0, 240, 255, 0.02),
      rgba(0, 240, 255, 0.02) 10px,
      rgba(0, 0, 0, 0) 10px,
      rgba(0, 0, 0, 0) 20px
    );
  }

  .placeholder-ai {
    padding: 0 20px;
    color: var(--text-muted);
    font-size: 0.9rem;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 15px;
  }
</style>
