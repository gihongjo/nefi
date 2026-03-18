<script>
  import { onMount, onDestroy } from 'svelte';
  import { createWS } from '../lib/websocket.js';
  import { fetchStats } from '../api/client.js';

  let endpoints = $state([]);
  let connected = $state(false);
  let namespace = $state('');
  let windowSec = $state(60);

  let wsHandle = null;
  let pollTimer = null;

  // WebSocket — window=60일 때 실시간 수신
  onMount(() => {
    wsHandle = createWS(
      (msg) => {
        if (msg.type === 'stats' && windowSec === 60) {
          endpoints = msg.endpoints ?? [];
        }
      },
      (status) => { connected = status; }
    );
  });

  onDestroy(() => {
    wsHandle?.close();
    clearInterval(pollTimer);
  });

  // window != 60이면 REST 폴링
  $effect(() => {
    clearInterval(pollTimer);
    if (windowSec === 60) return;
    const poll = () => {
      fetchStats(windowSec)
        .then(data => { endpoints = data.endpoints ?? []; })
        .catch(() => {});
    };
    poll();
    pollTimer = setInterval(poll, 2000);
  });

  // 필터링 + 집계
  let filtered = $derived(
    endpoints.filter(ep => {
      const ns = namespace.trim().toLowerCase();
      return !ns || ep.namespace?.toLowerCase().includes(ns);
    })
  );

  let summary = $derived({
    total:   filtered.reduce((s, e) => s + e.total,   0),
    success: filtered.reduce((s, e) => s + e.success, 0),
    error:   filtered.reduce((s, e) => s + e.error,   0),
    get rate() {
      return this.total > 0 ? this.success / this.total * 100 : null;
    },
  });

  function rateColor(r) {
    if (r >= 95) return '#4ade80';
    if (r >= 80) return '#facc15';
    return '#f87171';
  }

  function latencyColor(ms) {
    if (ms < 50)  return '#4ade80'; // 빠름
    if (ms < 200) return '#facc15'; // 보통
    return '#f87171';               // 느림
  }
</script>

<div class="page">
  <div class="controls">
    <div class="status-badge" class:connected>
      {connected ? '● Live' : '○ Disconnected'}
    </div>

    <label>
      Namespace
      <input bind:value={namespace} placeholder="전체" />
    </label>

    <label>
      윈도우
      <select bind:value={windowSec}>
        <option value={10}>10초</option>
        <option value={30}>30초</option>
        <option value={60}>1분</option>
        <option value={300}>5분</option>
      </select>
    </label>
  </div>

  {#if filtered.length > 0}
    <div class="summary">
      <div class="stat-card">
        <div class="label">전체 요청</div>
        <div class="value">{summary.total.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <div class="label">성공</div>
        <div class="value" style="color:#4ade80">{summary.success.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <div class="label">에러</div>
        <div class="value" style="color:#f87171">{summary.error.toLocaleString()}</div>
      </div>
      {#if summary.rate !== null}
        <div class="stat-card">
          <div class="label">전체 성공률</div>
          <div class="value" style="color:{rateColor(summary.rate)}">{summary.rate.toFixed(1)}%</div>
        </div>
      {/if}
    </div>
  {/if}

  <div class="table-wrap">
    {#if filtered.length === 0}
      <div class="empty">
        {connected ? '수신된 데이터가 없습니다.' : '서버에 연결 중...'}
      </div>
    {:else}
      <table>
        <thead>
          <tr>
            <th>Namespace</th>
            <th>Workload</th>
            <th>Pod</th>
            <th>Method</th>
            <th>Path</th>
            <th>성공률</th>
            <th>레이턴시</th>
            <th>요청 수</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered.slice().sort((a, b) => a.success_rate - b.success_rate) as ep (ep.namespace + ep.pod_name + ep.method + ep.path)}
            <tr>
              <td class="ns">{ep.namespace || '—'}</td>
              <td class="workload">{ep.workload_name || '—'}</td>
              <td class="pod">{ep.pod_name || '—'}</td>
              <td><span class="method {ep.method}">{ep.method}</span></td>
              <td class="path">{ep.path}</td>
              <td>
                <div class="rate-bar">
                  <div class="bar-bg">
                    <div class="bar-fill" style="width:{ep.success_rate}%;background:{rateColor(ep.success_rate)}"></div>
                  </div>
                  <span class="rate-text" style="color:{rateColor(ep.success_rate)}">{ep.success_rate.toFixed(1)}%</span>
                </div>
              </td>
              <td class="latency">
                {#if ep.avg_latency_ms > 0}
                  <span style="color:{latencyColor(ep.avg_latency_ms)}">{ep.avg_latency_ms.toFixed(1)} ms</span>
                {:else}
                  <span style="color:#475569">—</span>
                {/if}
              </td>
              <td class="count">
                {ep.total.toLocaleString()} req
                &nbsp;/&nbsp;
                <span style="color:#f87171">{ep.error} err</span>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    height: 100%;
    overflow: hidden;
  }

  .controls {
    display: flex;
    align-items: flex-end;
    gap: 16px;
    padding: 14px 32px;
    border-bottom: 1px solid #1e293b;
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .status-badge {
    font-size: 12px;
    padding: 4px 10px;
    border-radius: 99px;
    font-weight: 500;
    background: #450a0a;
    color: #f87171;
    margin-bottom: 2px;
  }
  .status-badge.connected { background: #14532d; color: #4ade80; }

  label {
    font-size: 12px;
    color: #94a3b8;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  input, select {
    background: #1e293b;
    border: 1px solid #334155;
    color: #e2e8f0;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    outline: none;
  }
  input:focus, select:focus { border-color: #6366f1; }

  .summary {
    display: flex;
    gap: 12px;
    padding: 16px 32px;
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .stat-card {
    background: #1e293b;
    border-radius: 8px;
    padding: 12px 20px;
    min-width: 130px;
  }
  .stat-card .label { font-size: 11px; color: #64748b; margin-bottom: 4px; }
  .stat-card .value { font-size: 22px; font-weight: 700; }

  .table-wrap {
    flex: 1;
    overflow-y: auto;
    padding: 0 32px 32px;
  }

  .empty {
    text-align: center;
    padding: 60px;
    color: #475569;
    font-size: 14px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  th {
    text-align: left;
    padding: 10px 12px;
    color: #64748b;
    font-weight: 500;
    border-bottom: 1px solid #1e293b;
    white-space: nowrap;
    position: sticky;
    top: 0;
    background: #0f1117;
  }

  td { padding: 10px 12px; border-bottom: 1px solid #1e293b; }
  tr:hover td { background: rgba(30,41,59,0.4); }

  .ns   { color: #94a3b8; }
  .workload { color: #e2e8f0; font-weight: 500; }
  .pod  { color: #64748b; font-size: 12px; }
  .path { font-family: monospace; color: #cbd5e1; }
  .latency { font-size: 12px; font-family: monospace; min-width: 70px; }
  .count { color: #64748b; font-size: 12px; }

  .method {
    font-family: monospace;
    font-weight: 600;
    font-size: 12px;
    padding: 2px 7px;
    border-radius: 4px;
  }
  .method.GET    { background: #1e3a5f; color: #60a5fa; }
  .method.POST   { background: #14532d; color: #4ade80; }
  .method.PUT    { background: #451a03; color: #fb923c; }
  .method.DELETE { background: #450a0a; color: #f87171; }
  .method.PATCH  { background: #2e1065; color: #c084fc; }

  .rate-bar { display: flex; align-items: center; gap: 10px; }
  .bar-bg { flex: 1; height: 6px; background: #1e293b; border-radius: 99px; overflow: hidden; max-width: 120px; }
  .bar-fill { height: 100%; border-radius: 99px; transition: width 0.4s ease; }
  .rate-text { font-weight: 600; font-size: 13px; min-width: 44px; text-align: right; }
</style>
