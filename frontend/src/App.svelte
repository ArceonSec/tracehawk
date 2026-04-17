<script>
  import Dashboard from './lib/Dashboard.svelte';
</script>

<div class="app-shell">
  <!-- Top Navbar -->
  <header class="topbar">
    <div class="topbar-brand">
      <span class="brand-trace">TRACE</span><span class="brand-hawk">HAWK</span>
      <span class="brand-divider">///</span>
      <span class="brand-sub">DevSecOps Scanner</span>
    </div>
    <div class="topbar-status">
      <span class="status-dot"></span>
      <span class="status-text">v0.1.0</span>
    </div>
  </header>

  <main class="main-content">
    <Dashboard />
  </main>
</div>

<style>
  .app-shell {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 32px;
    background: rgba(0, 0, 0, 0.4);
    border-bottom: 1px solid var(--glass-border);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .topbar-brand {
    display: flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono);
    font-size: 1.1rem;
    font-weight: 700;
    letter-spacing: 2px;
  }

  .brand-trace { color: #cbd5e1; }
  .brand-hawk {
    background: linear-gradient(135deg, var(--accent-purple), var(--accent-cyan));
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .brand-divider {
    color: rgba(255,255,255,0.15);
    margin: 0 6px;
    font-weight: 400;
  }
  .brand-sub {
    font-size: 0.75rem;
    font-weight: 400;
    color: var(--text-muted);
    letter-spacing: 1px;
  }

  .topbar-status {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-muted);
  }
  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #22c55e;
    box-shadow: 0 0 6px rgba(34, 197, 94, 0.5);
  }

  .main-content {
    flex: 1;
    padding: 32px 40px;
    max-width: 1300px;
    width: 100%;
    margin: 0 auto;
    overflow-y: auto;
  }
</style>
