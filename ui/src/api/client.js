const base = () => `${window.location.protocol}//${window.location.host}`;

export async function fetchStats(windowSec) {
  const r = await fetch(`${base()}/api/v1/stats?window=${windowSec}`);
  if (!r.ok) throw new Error(`stats ${r.status}`);
  return r.json();
}

export async function fetchTopology(limit = 5000) {
  const r = await fetch(`${base()}/api/v1/topology?limit=${limit}`);
  if (!r.ok) throw new Error(`topology ${r.status}`);
  return r.json();
}

export async function fetchEvents(limit = 100) {
  const r = await fetch(`${base()}/api/v1/events?limit=${limit}`);
  if (!r.ok) throw new Error(`events ${r.status}`);
  return r.json();
}
