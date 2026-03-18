<script>
  import { onMount } from 'svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Topology from './pages/Topology.svelte';
  import Settings from './pages/Settings.svelte';
  import { settings, applyTheme } from './lib/settings.svelte.js';

  let page = $state(window.location.pathname);
  let expanded = $state(true);

  onMount(() => {
    applyTheme(settings.themeId);
    const onPop = () => { page = window.location.pathname; };
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  });

  // 테마 변경 시 즉시 적용
  $effect(() => {
    applyTheme(settings.themeId);
  });

  function navigate(path) {
    history.pushState({}, '', path);
    page = path;
  }

  const navItems = [
    { path: '/',         icon: '☰',  label: 'List'  },
    { path: '/topology', icon: '⬡',  label: 'Graph' },
  ];
</script>

<div class="app">
  <!-- 사이드바 -->
  <aside class:expanded>
    <div class="logo">
      {#if expanded}
        <span class="logo-text">Nefi</span>
      {:else}
        <span class="logo-icon">N</span>
      {/if}
    </div>

    <nav>
      {#each navItems as item}
        <a
          href={item.path}
          class:active={page === item.path}
          onclick={(e) => { e.preventDefault(); navigate(item.path); }}
          title={!expanded ? item.label : ''}
        >
          <span class="icon">{item.icon}</span>
          {#if expanded}<span class="label">{item.label}</span>{/if}
        </a>
      {/each}
    </nav>

    <!-- 설정 버튼 (토글 바로 위) -->
    <button
      class="settings-btn"
      class:active={page === '/settings'}
      onclick={() => navigate('/settings')}
      title={!expanded ? '설정' : ''}
    >
      <span class="icon">⚙</span>
      {#if expanded}<span class="label">설정</span>{/if}
    </button>

    <button class="toggle" onclick={() => expanded = !expanded} title={expanded ? '사이드바 축소' : '사이드바 확장'}>
      {expanded ? '◀' : '▶'}
    </button>
  </aside>

  <!-- 콘텐츠 -->
  <main>
    {#if page === '/topology'}
      <Topology />
    {:else if page === '/settings'}
      <Settings />
    {:else}
      <Dashboard />
    {/if}
  </main>
</div>

<style>
  :global(*, *::before, *::after) { box-sizing: border-box; margin: 0; padding: 0; }
  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--c-bg, #0f1117);
    color: var(--c-text, #e2e8f0);
    height: 100vh;
    overflow: hidden;
  }

  .app {
    display: flex;
    height: 100vh;
  }

  /* ── 사이드바 ── */
  aside {
    display: flex;
    flex-direction: column;
    width: 52px;
    background: var(--c-sidebar, #0a0e17);
    border-right: 1px solid var(--c-border, #1e293b);
    flex-shrink: 0;
    transition: width 0.22s ease;
    overflow: hidden;
  }

  aside.expanded {
    width: 180px;
  }

  .logo {
    height: 52px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-bottom: 1px solid var(--c-border, #1e293b);
    flex-shrink: 0;
  }

  .logo-text {
    font-size: 17px;
    font-weight: 700;
    color: var(--c-accent, #6366f1);
    letter-spacing: 1px;
    white-space: nowrap;
  }

  .logo-icon {
    font-size: 18px;
    font-weight: 700;
    color: var(--c-accent, #6366f1);
  }

  /* ── 네비게이션 ── */
  nav {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 12px 8px;
  }

  nav a {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 10px;
    border-radius: 8px;
    text-decoration: none;
    color: var(--c-muted, #64748b);
    font-size: 13px;
    font-weight: 500;
    white-space: nowrap;
    transition: background 0.15s, color 0.15s;
  }

  nav a:hover {
    background: var(--c-surface, #1e293b);
    color: var(--c-text, #e2e8f0);
  }

  nav a.active {
    background: var(--c-accent-bg, #1e1b4b);
    color: var(--c-accent-text, #a5b4fc);
  }

  nav a .icon, .settings-btn .icon {
    font-size: 15px;
    flex-shrink: 0;
    width: 20px;
    text-align: center;
  }

  nav a .label, .settings-btn .label {
    overflow: hidden;
  }

  /* ── 설정 버튼 ── */
  .settings-btn {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 10px;
    margin: 0 8px 4px;
    border-radius: 8px;
    border: none;
    background: transparent;
    color: var(--c-muted, #64748b);
    font-size: 13px;
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
    width: calc(100% - 16px);
    text-align: left;
  }

  .settings-btn:hover {
    background: var(--c-surface, #1e293b);
    color: var(--c-text, #e2e8f0);
  }

  .settings-btn.active {
    background: var(--c-accent-bg, #1e1b4b);
    color: var(--c-accent-text, #a5b4fc);
  }

  /* ── 토글 버튼 ── */
  .toggle {
    height: 40px;
    border: none;
    border-top: 1px solid var(--c-border, #1e293b);
    background: transparent;
    color: var(--c-muted, #475569);
    cursor: pointer;
    font-size: 11px;
    flex-shrink: 0;
    transition: color 0.15s, background 0.15s;
    width: 100%;
  }

  .toggle:hover {
    background: var(--c-surface, #1e293b);
    color: var(--c-text, #e2e8f0);
  }

  /* ── 메인 콘텐츠 ── */
  main {
    flex: 1;
    overflow: hidden;
    min-width: 0;
    background: var(--c-bg, #0f1117);
  }
</style>
