/* 4-Card Stacked Bar Telemetry Renderer (Light & Dark Monochrome Operations Dashboard) */
window.NosihCharts = {
  esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  },
  renderCards(containerEl, payload) {
    if (!containerEl || !payload || !Array.isArray(payload.cards)) return;
    const totalEl = document.getElementById('kpi-total-reqs');
    const rateEl = document.getElementById('kpi-success-rate');
    if (totalEl) totalEl.textContent = String(payload.total_requests ?? 0);
    if (rateEl) rateEl.textContent = `${Number(payload.success_rate ?? 100).toFixed(1)}%`;

    containerEl.innerHTML = '';
    payload.cards.forEach(card => {
      const buckets = card.buckets || [];
      const maxVal = Math.max(1, ...buckets.map(b => (b.ok || 0) + (b.warn || 0) + (b.err || 0)));

      let barsHtml = '';
      buckets.forEach(b => {
        const ok = b.ok || 0;
        const warn = b.warn || 0;
        const err = b.err || 0;
        const okH = ok > 0 ? Math.max(4, Math.round((ok / maxVal) * 82)) : 0;
        const warnH = warn > 0 ? Math.max(3, Math.round((warn / maxVal) * 82)) : 0;
        const errH = err > 0 ? Math.max(3, Math.round((err / maxVal) * 82)) : 0;
        const title = `ok:${ok} warn:${warn} err:${err}`;
        barsHtml += `<div class="bar-col" title="${title}">` +
          (okH ? `<div class="bar-seg-ok" style="height:${okH}px"></div>` : '') +
          (warnH ? `<div class="bar-seg-warn" style="height:${warnH}px"></div>` : '') +
          (errH ? `<div class="bar-seg-err" style="height:${errH}px"></div>` : '') +
          `</div>`;
      });

      const div = document.createElement('div');
      div.className = 'metric-card';
      div.innerHTML = `
        <div class="metric-card-top">
          <div>
            <div class="metric-title">${this.esc(card.title)}</div>
            <div class="metric-big">${Number(card.total ?? 0)}</div>
          </div>
          <div class="metric-counters">
            <div>
              <div class="metric-stat-label"><span class="dot-warn"></span> WARNINGS</div>
              <div class="metric-stat-val">${Number(card.warnings ?? 0)}</div>
            </div>
            <div>
              <div class="metric-stat-label"><span class="dot-err"></span> ERRORS</div>
              <div class="metric-stat-val">${Number(card.errors ?? 0)}</div>
            </div>
          </div>
        </div>
        <div class="bar-chart">${barsHtml}</div>
        <div class="bar-timestamps">
          <span>${this.esc(payload.start_label || '')}</span>
          <span>${this.esc(payload.end_label || '')}</span>
        </div>`;
      containerEl.appendChild(div);
    });
  }
};
