<script>
  import { settings, saveSettings, applyTheme } from '../lib/settings.svelte.js';
  import { THEMES } from '../lib/themes.js';

  const themeList = Object.values(THEMES);

  const nodeShapes = [
    { value: 'ellipse',          label: '원형' },
    { value: 'roundrectangle',   label: '둥근 사각형' },
    { value: 'hexagon',          label: '육각형' },
    { value: 'diamond',          label: '다이아몬드' },
  ];

  const nodeSizes = [
    { value: 32, label: '작게' },
    { value: 40, label: '보통' },
    { value: 52, label: '크게' },
  ];

  const edgeWidths = [
    { value: 1, label: '얇게' },
    { value: 2, label: '보통' },
    { value: 3, label: '굵게' },
  ];

  const edgeCurves = [
    { value: 'bezier',   label: '곡선' },
    { value: 'straight', label: '직선' },
    { value: 'taxi',     label: '직각' },
  ];

  const arrowShapes = [
    { value: 'triangle', label: '삼각형' },
    { value: 'vee',      label: 'V자형' },
    { value: 'circle',   label: '원형' },
    { value: 'none',     label: '없음' },
  ];

  function setTheme(id) {
    settings.themeId = id;
    applyTheme(id);
    saveSettings();
  }

  function setGraph(key, value) {
    settings.graph[key] = value;
    saveSettings();
  }
</script>

<div class="page">
  <div class="header">
    <h1>설정</h1>
    <p>테마와 그래프 시각화를 커스터마이징합니다.</p>
  </div>

  <div class="sections">

    <!-- ── 테마 ── -->
    <section>
      <h2>테마</h2>
      <div class="theme-grid">
        {#each themeList as theme}
          <button
            class="theme-card"
            class:active={settings.themeId === theme.id}
            onclick={() => setTheme(theme.id)}
            title={theme.label}
          >
            <div class="swatch">
              {#each theme.preview as color}
                <div style="background:{color}"></div>
              {/each}
            </div>
            <span class="theme-name">{theme.label}</span>
            {#if settings.themeId === theme.id}
              <span class="check">✓</span>
            {/if}
          </button>
        {/each}
      </div>
    </section>

    <!-- ── 그래프 — 노드 ── -->
    <section>
      <h2>그래프 — 노드</h2>

      <div class="option-row">
        <span class="option-label">모양</span>
        <div class="btn-group">
          {#each nodeShapes as s}
            <button
              class:active={settings.graph.nodeShape === s.value}
              onclick={() => setGraph('nodeShape', s.value)}
            >{s.label}</button>
          {/each}
        </div>
      </div>

      <div class="option-row">
        <span class="option-label">크기</span>
        <div class="btn-group">
          {#each nodeSizes as s}
            <button
              class:active={settings.graph.nodeSize === s.value}
              onclick={() => setGraph('nodeSize', s.value)}
            >{s.label}</button>
          {/each}
        </div>
      </div>
    </section>

    <!-- ── 그래프 — 엣지 ── -->
    <section>
      <h2>그래프 — 엣지</h2>

      <div class="option-row">
        <span class="option-label">두께</span>
        <div class="btn-group">
          {#each edgeWidths as s}
            <button
              class:active={settings.graph.edgeWidth === s.value}
              onclick={() => setGraph('edgeWidth', s.value)}
            >{s.label}</button>
          {/each}
        </div>
      </div>

      <div class="option-row">
        <span class="option-label">곡선</span>
        <div class="btn-group">
          {#each edgeCurves as s}
            <button
              class:active={settings.graph.edgeCurve === s.value}
              onclick={() => setGraph('edgeCurve', s.value)}
            >{s.label}</button>
          {/each}
        </div>
      </div>

      <div class="option-row">
        <span class="option-label">화살표</span>
        <div class="btn-group">
          {#each arrowShapes as s}
            <button
              class:active={settings.graph.arrowShape === s.value}
              onclick={() => setGraph('arrowShape', s.value)}
            >{s.label}</button>
          {/each}
        </div>
      </div>
    </section>

  </div>
</div>

<style>
  .page {
    height: 100%;
    overflow-y: auto;
    padding: 40px 48px;
    background: var(--c-bg, #0f1117);
    color: var(--c-text, #e2e8f0);
  }

  .header {
    margin-bottom: 36px;
  }

  h1 {
    font-size: 22px;
    font-weight: 700;
    color: var(--c-text, #e2e8f0);
    margin-bottom: 6px;
  }

  .header p {
    font-size: 13px;
    color: var(--c-muted, #64748b);
  }

  .sections {
    display: flex;
    flex-direction: column;
    gap: 36px;
    max-width: 640px;
  }

  section {
    background: var(--c-surface, #1e293b);
    border: 1px solid var(--c-border, #1e293b);
    border-radius: 12px;
    padding: 24px 28px;
  }

  h2 {
    font-size: 13px;
    font-weight: 600;
    color: var(--c-muted, #64748b);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 20px;
  }

  /* ── 테마 카드 ── */
  .theme-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
  }

  .theme-card {
    position: relative;
    background: var(--c-surface2, #334155);
    border: 2px solid var(--c-border, #1e293b);
    border-radius: 10px;
    padding: 12px;
    cursor: pointer;
    transition: border-color 0.15s, transform 0.1s;
    text-align: left;
  }

  .theme-card:hover {
    border-color: var(--c-accent, #6366f1);
    transform: translateY(-1px);
  }

  .theme-card.active {
    border-color: var(--c-accent, #6366f1);
    background: var(--c-accent-bg, #1e1b4b);
  }

  .swatch {
    display: flex;
    height: 36px;
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 10px;
  }

  .swatch div {
    flex: 1;
  }

  .theme-name {
    font-size: 12px;
    font-weight: 500;
    color: var(--c-text, #e2e8f0);
  }

  .check {
    position: absolute;
    top: 8px;
    right: 10px;
    font-size: 13px;
    color: var(--c-accent-text, #a5b4fc);
    font-weight: 700;
  }

  /* ── 옵션 행 ── */
  .option-row {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 10px 0;
    border-bottom: 1px solid var(--c-border, #1e293b);
  }

  .option-row:last-child {
    border-bottom: none;
    padding-bottom: 0;
  }

  .option-label {
    font-size: 13px;
    color: var(--c-text, #e2e8f0);
    width: 64px;
    flex-shrink: 0;
  }

  /* ── 버튼 그룹 ── */
  .btn-group {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }

  .btn-group button {
    padding: 5px 14px;
    border-radius: 6px;
    border: 1px solid var(--c-border, #334155);
    background: var(--c-surface2, #334155);
    color: var(--c-muted, #64748b);
    font-size: 12px;
    cursor: pointer;
    transition: background 0.12s, color 0.12s, border-color 0.12s;
  }

  .btn-group button:hover {
    color: var(--c-text, #e2e8f0);
    border-color: var(--c-accent, #6366f1);
  }

  .btn-group button.active {
    background: var(--c-accent-bg, #1e1b4b);
    border-color: var(--c-accent, #6366f1);
    color: var(--c-accent-text, #a5b4fc);
    font-weight: 500;
  }
</style>
