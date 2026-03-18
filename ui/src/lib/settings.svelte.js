import { THEMES } from './themes.js';

const DEFAULTS = {
  themeId: 'dark',
  graph: {
    nodeShape: 'ellipse',  // ellipse | roundrectangle | hexagon | diamond
    nodeSize: 40,          // 32 | 40 | 52
    edgeWidth: 2,          // 1 | 2 | 3
    edgeCurve: 'bezier',   // bezier | straight | taxi
    arrowShape: 'triangle',// triangle | vee | circle | none
  },
};

function loadStored() {
  try {
    const s = localStorage.getItem('nefi-settings');
    if (s) {
      const p = JSON.parse(s);
      return {
        ...DEFAULTS,
        ...p,
        graph: { ...DEFAULTS.graph, ...(p.graph || {}) },
      };
    }
  } catch { /* ignore */ }
  return { ...DEFAULTS };
}

export const settings = $state(loadStored());

export function saveSettings() {
  try {
    localStorage.setItem('nefi-settings', JSON.stringify({
      themeId: settings.themeId,
      graph: { ...settings.graph },
    }));
  } catch { /* ignore */ }
}

export function applyTheme(themeId) {
  const theme = THEMES[themeId] || THEMES.dark;
  const root = document.documentElement;
  Object.entries(theme.vars).forEach(([k, v]) => root.style.setProperty(k, v));
}
