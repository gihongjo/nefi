<script>
  import { onMount, onDestroy } from 'svelte';
  import { fetchTopology } from '../api/client.js';
  import { settings } from '../lib/settings.svelte.js';
  import { THEMES } from '../lib/themes.js';

  // cytoscape + dagre를 lazy load — Dashboard 진입 시 번들 로드 안 함
  async function loadCytoscape() {
    const [cy, dagre] = await Promise.all([
      import('cytoscape'),
      import('cytoscape-dagre'),
    ]);
    cy.default.use(dagre.default);
    return cy.default;
  }

  const DAGRE_LAYOUT = {
    name: 'dagre',
    rankDir: 'LR',
    nodeSep: 70,
    rankSep: 140,
    padding: 40,
    animate: true,
    animationDuration: 400,
    animationEasing: 'ease-out',
  };

  let container = $state(null);
  let namespace = $state('');
  let limit = $state(5000);
  let tooltip = $state({ visible: false, html: '', x: 0, y: 0 });

  // 노드 정렬 자동화
  let autoLayout = $state(false);
  let autoLayoutMin = $state(5); // 분 단위
  let autoLayoutTimer = null;
  let nextLayoutIn = $state(0);  // 카운트다운 (초)
  let countdownTimer = null;

  let cy = null;
  let layoutDone = false;
  let pollTimer = null;
  let currentData = null;

  // ── 레이아웃 실행 ──────────────────────────────────────────────
  function runLayout() {
    if (!cy) return;
    cy.layout(DAGRE_LAYOUT).run();
    resetCountdown();
  }

  function resetCountdown() {
    nextLayoutIn = autoLayoutMin * 60;
  }

  // 자동 정렬 타이머 관리
  $effect(() => {
    clearInterval(autoLayoutTimer);
    clearInterval(countdownTimer);

    if (autoLayout) {
      resetCountdown();

      autoLayoutTimer = setInterval(() => {
        runLayout();
      }, autoLayoutMin * 60 * 1000);

      countdownTimer = setInterval(() => {
        nextLayoutIn = Math.max(0, nextLayoutIn - 1);
      }, 1000);
    }
  });

  function formatCountdown(sec) {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return m > 0 ? `${m}분 ${s}초` : `${s}초`;
  }

  // ── 테마 기반 cytoscape 스타일 빌드 ──────────────────────────
  function buildCyStyle() {
    const tv = (THEMES[settings.themeId] || THEMES.dark).vars;
    const g = settings.graph;
    return [
      {
        selector: 'node',
        style: {
          'background-color': tv['--c-node'],
          'border-color':     tv['--c-node-border'],
          'border-width':     2,
          'label':            'data(label)',
          'color':            tv['--c-node-text'],
          'font-size':        '11px',
          'text-valign':      'bottom',
          'text-margin-y':    6,
          'width':            g.nodeSize,
          'height':           g.nodeSize,
          'shape':            g.nodeShape,
        },
      },
      {
        selector: 'edge',
        style: {
          'width':                g.edgeWidth,
          'line-color':           'data(color)',
          'target-arrow-color':   'data(color)',
          'target-arrow-shape':   g.arrowShape,
          'curve-style':          g.edgeCurve,
          'opacity':              0.8,
        },
      },
      {
        selector: 'node:selected',
        style: { 'border-color': tv['--c-accent-text'], 'border-width': 3 },
      },
      {
        selector: 'edge:selected',
        style: { 'width': g.edgeWidth + 2, 'opacity': 1 },
      },
    ];
  }

  // 설정 변경 시 cy 스타일 실시간 반영
  $effect(() => {
    // 추적: themeId + 모든 graph 설정
    const _track = settings.themeId + settings.graph.nodeShape + settings.graph.nodeSize
      + settings.graph.edgeWidth + settings.graph.edgeCurve + settings.graph.arrowShape;
    if (cy) cy.style(buildCyStyle()).update();
  });

  // ── 색상 ───────────────────────────────────────────────────────
  function rateColor(rate) {
    if (rate >= 95) return '#4ade80';
    if (rate >= 80) return '#facc15';
    return '#f87171';
  }

  // ── elements 빌드 ──────────────────────────────────────────────
  function buildElements(data, nsFilter) {
    const filter = nsFilter.trim().toLowerCase();
    const nodeMap = {};

    (data.nodes || []).forEach(n => {
      if (filter && !n.namespace?.toLowerCase().includes(filter)) return;
      nodeMap[n.id] = n;
    });

    const edgeList = [];
    (data.edges || []).forEach(e => {
      if (filter) {
        const srcOk = !!nodeMap[e.source];
        const dstOk = !!nodeMap[e.target];
        if (!srcOk && !dstOk) return;
        if (!nodeMap[e.source]) nodeMap[e.source] = { id: e.source, namespace: '', workload: e.source };
        if (!nodeMap[e.target]) nodeMap[e.target] = { id: e.target, namespace: '', workload: e.target };
      }
      edgeList.push(e);
    });

    const elements = [];
    Object.values(nodeMap).forEach(n => {
      elements.push({ data: { id: n.id, label: n.workload || n.id, namespace: n.namespace || '' } });
    });
    edgeList.forEach(e => {
      elements.push({
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          total: e.total,
          success: e.success,
          error: e.error,
          success_rate: e.success_rate,
          avg_latency_ms: e.avg_latency_ms || 0,
          color: rateColor(e.success_rate),
        },
      });
    });
    return elements;
  }

  // ── cy 초기 생성 ───────────────────────────────────────────────
  async function initCy(elements) {
    const cytoscape = await loadCytoscape();
    cy = cytoscape({
      container,
      style: buildCyStyle(),
      layout: { ...DAGRE_LAYOUT, animate: false },
      elements,
    });

    cy.one('layoutstop', () => { layoutDone = true; });

    cy.on('mouseover', 'node', (e) => {
      const d = e.target.data();
      const pos = e.originalEvent;
      tooltip = {
        visible: true,
        html: `<div><span class="lbl">Workload</span> ${d.label}</div><div><span class="lbl">Namespace</span> ${d.namespace || '—'}</div>`,
        x: pos.clientX + 14,
        y: pos.clientY + 14,
      };
    });

    cy.on('mouseover', 'edge', (e) => {
      const d = e.target.data();
      const pos = e.originalEvent;
      const cls = d.success_rate >= 95 ? 'green' : d.success_rate >= 80 ? 'yellow' : 'red';
      const latency = d.avg_latency_ms > 0
        ? `<div><span class="lbl">레이턴시</span> <span class="${d.avg_latency_ms < 50 ? 'green' : d.avg_latency_ms < 200 ? 'yellow' : 'red'}">${d.avg_latency_ms.toFixed(1)} ms</span></div>`
        : '';
      tooltip = {
        visible: true,
        html: `
          <div><span class="lbl">경로</span> ${d.source} → ${d.target}</div>
          <div><span class="lbl">요청</span> ${(d.total || 0).toLocaleString()}</div>
          <div><span class="lbl">성공</span> <span class="green">${(d.success || 0).toLocaleString()}</span></div>
          <div><span class="lbl">에러</span> <span class="red">${(d.error || 0).toLocaleString()}</span></div>
          <div><span class="lbl">성공률</span> <span class="${cls}">${(d.success_rate || 0).toFixed(1)}%</span></div>
          ${latency}
        `,
        x: pos.clientX + 14,
        y: pos.clientY + 14,
      };
    });

    cy.on('mousemove', (e) => {
      if (tooltip.visible) {
        tooltip = { ...tooltip, x: e.originalEvent.clientX + 14, y: e.originalEvent.clientY + 14 };
      }
    });

    cy.on('mouseout', () => { tooltip = { ...tooltip, visible: false }; });
  }

  // ── 데이터 갱신 (노드 위치 유지) ──────────────────────────────
  function updateCy(elements) {
    if (!cy) return;
    const existingNodeIds = new Set(cy.nodes().map(n => n.id()));
    const newNodeIds = new Set(elements.filter(e => !e.data.source).map(e => e.data.id));

    cy.nodes().forEach(n => { if (!newNodeIds.has(n.id())) cy.remove(n); });
    cy.edges().remove();

    const addedIds = [];
    elements.forEach(el => {
      if (!el.data.source) {
        if (!existingNodeIds.has(el.data.id)) {
          cy.add(el);
          addedIds.push(el.data.id);
        } else {
          cy.getElementById(el.data.id).data(el.data);
        }
      }
    });

    elements.forEach(el => { if (el.data.source) cy.add(el); });

    // 새 노드가 추가됐으면 전체 재정렬 (새 노드 위치를 맥락에 맞게 배치)
    if (addedIds.length > 0) {
      cy.layout(DAGRE_LAYOUT).run();
    }
  }

  // ── fetch + 렌더 ───────────────────────────────────────────────
  async function load() {
    try {
      const data = await fetchTopology(limit);
      currentData = data;
      const elements = buildElements(data, namespace);
      if (!cy) {
        initCy(elements);
      } else {
        updateCy(elements);
      }
    } catch (err) {
      console.error('topology fetch error:', err);
    }
  }

  // namespace 필터 변경 시 cy 전체 재생성
  let prevNs = '';
  $effect(() => {
    if (namespace !== prevNs && cy && currentData) {
      prevNs = namespace;
      cy.destroy();
      cy = null;
      layoutDone = false;
      initCy(buildElements(currentData, namespace));
    }
  });

  onMount(() => {
    load();
    pollTimer = setInterval(load, 10000);
  });

  onDestroy(() => {
    clearInterval(pollTimer);
    clearInterval(autoLayoutTimer);
    clearInterval(countdownTimer);
    cy?.destroy();
  });
</script>

<div class="page">
  <div class="controls">
    <label>
      Namespace 필터
      <input bind:value={namespace} placeholder="전체" />
    </label>
    <label>
      이벤트 수
      <input type="number" bind:value={limit} min="100" max="50000" style="width:100px" />
    </label>

    <div class="divider"></div>

    <!-- 즉시 정렬 -->
    <button class="btn-layout" onclick={runLayout} title="노드 간격을 균등하게 재배치합니다">
      ⬡ 즉시 정렬
    </button>

    <!-- 자동 정렬 -->
    <div class="auto-layout">
      <label class="toggle-label">
        <input type="checkbox" bind:checked={autoLayout} />
        자동 정렬
      </label>
      {#if autoLayout}
        <label class="inline-label">
          매
          <input
            type="number"
            bind:value={autoLayoutMin}
            min="1"
            max="60"
            style="width:52px;text-align:center"
            onchange={() => { resetCountdown(); }}
          />
          분
        </label>
        <span class="countdown">({formatCountdown(nextLayoutIn)} 후)</span>
      {/if}
    </div>

    <div class="divider"></div>

    <button onclick={load}>새로고침</button>
    <button onclick={() => cy?.fit()}>화면 맞춤</button>
  </div>

  <div class="cy-wrap">
    <div bind:this={container} class="cy"></div>
  </div>

  <div class="legend">
    <span><span class="dot" style="background:#4ade80"></span>성공률 ≥ 95%</span>
    <span><span class="dot" style="background:#facc15"></span>성공률 80~95%</span>
    <span><span class="dot" style="background:#f87171"></span>성공률 &lt; 80%</span>
    <span style="color:#6366f1">● 노드 = workload · 엣지 = 트래픽 방향</span>
  </div>
</div>

{#if tooltip.visible}
  <div class="tooltip" style="left:{tooltip.x}px;top:{tooltip.y}px">
    {@html tooltip.html}
  </div>
{/if}

<style>
  .page {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .controls {
    display: flex;
    align-items: flex-end;
    gap: 12px;
    padding: 14px 32px;
    border-bottom: 1px solid #1e293b;
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  label {
    font-size: 12px;
    color: #94a3b8;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  input[type="text"],
  input[type="number"] {
    background: #1e293b;
    border: 1px solid #334155;
    color: #e2e8f0;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    outline: none;
    width: 150px;
  }
  input[type="text"]:focus,
  input[type="number"]:focus { border-color: #6366f1; }

  .divider {
    width: 1px;
    height: 28px;
    background: #1e293b;
    align-self: flex-end;
    margin: 0 4px;
  }

  button {
    padding: 6px 14px;
    border-radius: 6px;
    border: 1px solid #334155;
    background: #1e293b;
    color: #e2e8f0;
    font-size: 13px;
    cursor: pointer;
    align-self: flex-end;
  }
  button:hover { background: #334155; }

  .btn-layout {
    padding: 6px 14px;
    border-radius: 6px;
    border: 1px solid #4f46e5;
    background: #1e1b4b;
    color: #a5b4fc;
    font-size: 13px;
    cursor: pointer;
    align-self: flex-end;
    font-weight: 500;
  }
  .btn-layout:hover { background: #312e81; }

  .auto-layout {
    display: flex;
    align-items: center;
    gap: 8px;
    align-self: flex-end;
    padding-bottom: 2px;
  }

  .toggle-label {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: #94a3b8;
    cursor: pointer;
    white-space: nowrap;
  }
  .toggle-label input[type="checkbox"] {
    width: 14px;
    height: 14px;
    accent-color: #6366f1;
    cursor: pointer;
  }

  .inline-label {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 4px;
    font-size: 13px;
    color: #94a3b8;
  }

  .countdown {
    font-size: 12px;
    color: #6366f1;
    white-space: nowrap;
  }

  .cy-wrap { flex: 1; overflow: hidden; }
  .cy { width: 100%; height: 100%; }

  .legend {
    padding: 10px 32px;
    font-size: 11px;
    color: #475569;
    flex-shrink: 0;
    border-top: 1px solid #1e293b;
  }
  .legend span { margin-right: 16px; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }

  .tooltip {
    position: fixed;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 12px;
    color: #e2e8f0;
    pointer-events: none;
    z-index: 100;
    line-height: 1.8;
  }

  :global(.tooltip .lbl) { color: #64748b; margin-right: 6px; }
  :global(.tooltip .green) { color: #4ade80; }
  :global(.tooltip .red)   { color: #f87171; }
  :global(.tooltip .yellow){ color: #facc15; }
</style>
