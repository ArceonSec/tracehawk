<script>
  export let currentView = 'dashboard';
  
  function setView(view) {
    currentView = view;
  }
</script>

<aside class="sidebar glass-panel">
  <div class="logo">
    <span class="hawk">TRACE</span><span class="gradient-text">HAWK</span>
  </div>
  
  <nav class="nav-links">
    <button 
      class="nav-btn {currentView === 'dashboard' ? 'active' : ''}" 
      on:click={() => setView('dashboard')}>
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect></svg>
      Dashboard
    </button>
    
    <button 
      class="nav-btn {currentView === 'scans' ? 'active' : ''}" 
      on:click={() => setView('scans')}>
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
      Scan History
    </button>

    <button 
      class="nav-btn {currentView === 'settings' ? 'active' : ''}" 
      on:click={() => setView('settings')}>
      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
      Settings
    </button>
  </nav>

  <div class="user-profile">
    <div class="avatar">
      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
    </div>
    <div class="info">
      <h4>Admin</h4>
      <span>Local Host</span>
    </div>
  </div>
</aside>

<style>
  .sidebar {
    width: 250px;
    height: 100vh;
    border-radius: 0;
    border-left: none;
    border-top: none;
    border-bottom: none;
    display: flex;
    flex-direction: column;
    position: fixed;
    top: 0;
    left: 0;
    z-index: 100;
  }

  .logo {
    padding: 30px;
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: 2px;
    border-bottom: 1px solid var(--glass-border);
  }
  
  .hawk {
    color: white;
  }

  .nav-links {
    padding: 30px 15px;
    display: flex;
    flex-direction: column;
    gap: 15px;
    flex: 1;
  }

  .nav-btn {
    display: flex;
    align-items: center;
    gap: 15px;
    padding: 15px;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 8px;
    color: var(--text-muted);
    font-family: var(--font-mono);
    font-size: 0.95rem;
    cursor: pointer;
    text-align: left;
    transition: all 0.2s ease;
  }

  .nav-btn:hover {
    background: rgba(255, 255, 255, 0.05);
    color: white;
  }

  .nav-btn.active {
    background: rgba(176, 82, 255, 0.1);
    color: var(--accent-cyan);
    border: 1px solid rgba(0, 240, 255, 0.2);
    box-shadow: inset 0 0 15px rgba(0, 240, 255, 0.1);
  }

  .user-profile {
    padding: 20px;
    border-top: 1px solid var(--glass-border);
    display: flex;
    align-items: center;
    gap: 15px;
    background: rgba(0, 0, 0, 0.2);
  }

  .avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: linear-gradient(135deg, var(--accent-purple), var(--accent-pink));
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
  }

  .info h4 {
    margin: 0;
    font-size: 0.9rem;
  }

  .info span {
    font-size: 0.75rem;
    color: var(--text-muted);
  }
</style>
