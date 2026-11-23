/* NOSIH-CAZNSOS Localhost API Client */
window.NosihApi = {
  localKey() {
    const el = document.getElementById('local-key');
    return el ? el.value.trim() : '';
  },
  adminToken() {
    const el = document.getElementById('admin-token');
    return el ? el.value.trim() : '';
  },
  async getHealth() {
    const r = await fetch('/v1/health');
    if (!r.ok) return null;
    return r.json();
  },
  async getMetricCards(windowMins, view = 'api') {
    const r = await fetch(
      `/admin/metrics/cards?window_mins=${encodeURIComponent(windowMins)}&view=${encodeURIComponent(view)}`,
      { headers: { 'X-NOSIH-Admin': this.adminToken() } }
    );
    if (!r.ok) return null;
    return r.json();
  },
  async getSvg(chart, theme = 'dark') {
    const r = await fetch(
      `/admin/viz/svg?chart=${encodeURIComponent(chart)}&theme=${encodeURIComponent(theme)}`,
      { headers: { 'X-NOSIH-Admin': this.adminToken() } }
    );
    if (!r.ok) return null;
    return r.text();
  }
};
