(function () {
  'use strict';
  const data = JSON.parse(document.getElementById('review-data').textContent);
  const core = CatalogueReview;
  const $ = id => document.getElementById(id);
  const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[character]));
  const storageKey = 'nomad-catalogue-review:v1';
  const pageSize = 40;
  let review = core.state(data), page = 0, activeId = null, activeView = 'review', filtered = [], toastTimer;
  let storageAvailable = true, storageBlocked = false, unsavedExport = false;
  const auditIds = [...new Set(data.findings.flatMap(finding => finding.affectedStableIds.map(id => id.toLowerCase())))];
  const allRows = () => core.rows(data, review);
  const findingFor = item => data.findings.filter(finding => finding.affectedStableIds.some(id => [item.id, (item.row['Original stable ID'] || '').toLowerCase()].includes(id.toLowerCase())));
  function safeUrl(value) {
    try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.href : null; } catch (_) { return null; }
  }
  function link(url, label) {
    const safe = safeUrl(url);
    return safe ? `<a href="${escape(safe)}" target="_blank" rel="noopener noreferrer">${escape(label)}</a>` : '';
  }
  const badge = (text, kind = '') => `<span class="badge ${kind}">${escape(text)}</span>`;
  function feedback(message) { $('feedback').textContent = message; $('feedback').classList.remove('hidden'); }
  function toast(message) {
    $('toast').textContent = message; $('toast').classList.remove('hidden'); clearTimeout(toastTimer);
    toastTimer = setTimeout(() => $('toast').classList.add('hidden'), 3500);
  }
  function persist() {
    unsavedExport = true;
    try {
      if (storageBlocked) throw new Error('Existing unreadable storage must not be overwritten.');
      localStorage.setItem(storageKey, JSON.stringify(core.pack(review)));
      storageAvailable = true;
      $('saving').textContent = 'Saved in this browser. Export JSON for a portable backup.';
      if (activeId) $('detail-save-state').textContent = 'Saved in this browser';
    } catch (_) {
      storageAvailable = false;
      $('saving').textContent = 'Browser storage unavailable. Export JSON before closing.';
      if (activeId) $('detail-save-state').textContent = 'In memory only. Export before closing.';
      feedback('Your edits are currently kept only in this page’s memory. Browser storage is blocked or full. Export review JSON before closing or reloading.');
    }
  }
  function filters() {
    return {search: $('search').value, group: $('group-filter').value, visibility: $('visibility-filter').value, kind: $('kind-filter').value, status: $('status-filter').value, attention: $('attention-filter').value, auditIds};
  }
  const statusLabel = record => ({pending: 'Not reviewed', research: 'Needs research', reviewed: 'Reviewed', changed: 'Source changed', conflict: 'Import conflict'}[core.status(record)]);
  function renderStats() {
    const all = allRows();
    const done = all.filter(item => core.status(review.records[item.id]) === 'reviewed').length;
    const hidden = all.filter(item => item.row.Visibility === 'Hidden').length;
    const attention = all.filter(item => ['changed', 'conflict'].includes(core.status(review.records[item.id]))).length;
    const percent = all.length ? Math.round(done / all.length * 100) : 0;
    $('stats').innerHTML = `<div class="stat"><strong>${all.length}</strong><span>Review records</span></div><div class="stat"><strong>${done} / ${all.length}</strong><span>Reviewed (${percent}%)</span><div class="progress"><span style="width:${percent}%"></span></div></div><div class="stat"><strong>${hidden}</strong><span>Hidden records retained</span></div><div class="stat"><strong>${attention}</strong><span>Changed sources or conflicts</span></div>`;
    const counts = new Map(data.groups.map(group => [group.name, 0]));
    all.forEach(item => counts.set(item.row['Review group'], (counts.get(item.row['Review group']) || 0) + 1));
    $('group-nav').innerHTML = data.groups.map(group => `<button data-group="${escape(group.name)}" ${$('group-filter').value === group.name && activeView === 'review' ? 'aria-current="page"' : ''}><span>${escape(group.name)}</span><span class="count">${counts.get(group.name)}</span></button>`).join('');
  }
  function renderTable() {
    filtered = core.filterRows(allRows(), review, filters());
    const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
    page = Math.min(page, pages - 1);
    const shown = filtered.slice(page * pageSize, (page + 1) * pageSize);
    $('visible-count').textContent = `${filtered.length} of ${allRows().length} records match · ${shown.length ? page * pageSize + 1 : 0}–${Math.min((page + 1) * pageSize, filtered.length)} shown`;
    $('page-count').textContent = `Page ${page + 1} of ${pages}`;
    $('previous-page').disabled = page === 0; $('next-page').disabled = page === pages - 1;
    $('table-body').innerHTML = shown.map(item => {
      const row = item.row, record = review.records[item.id], findings = findingFor(item);
      const kind = row['Current kind'] || row['Original kind'] || 'No current record';
      return `<tr><td class="project-cell"><button class="project-title" data-open="${escape(item.id)}">${escape(row.Name || item.id)}</button><div class="id">${escape(row['Stable ID'])}</div><div class="links">${link(row['Repository URL'], 'Repository')}${link(row['pyproject.toml URL'], 'pyproject.toml')}${link(row['Documentation URL'], 'Docs')}${link(row['PyPI URL'], 'PyPI')}</div></td><td>${badge(row.Visibility, row.Visibility === 'Visible' ? 'ok' : 'hidden-badge')}<div>${escape(kind)}</div><div class="flag-text">${escape(row['Visibility reason'])}</div><div class="small">${escape(row['Current plugin types'] || '')}</div></td><td>${badge(row['Review group'])}${findings.length ? badge('Agent finding', 'warn') : ''}<div class="flag-text">${escape(row['Audit flags'])}</div></td><td>${badge(statusLabel(record), ['changed', 'conflict', 'research'].includes(core.status(record)) ? 'warn' : core.status(record) === 'reviewed' ? 'ok' : '')}<div class="small">${escape(record.fields['Reviewer verdict'])}</div><div class="review-preview">${escape(record.fields['Reviewer comment'])}</div><button data-open="${escape(item.id)}">Review</button></td></tr>`;
    }).join('') || '<tr><td colspan="4" class="empty">No matching records. Try resetting the filters.</td></tr>';
    renderStats();
  }
  function setView(view) {
    activeView = view;
    ['review', 'audit', 'guide'].forEach(name => $(name + '-view').classList.toggle('hidden', view !== name));
    document.querySelectorAll('[data-view]').forEach(button => button.setAttribute('aria-current', button.dataset.view === view ? 'page' : 'false'));
    renderStats();
  }
  function definitions(values) {
    return '<dl class="definition">' + values.map(([label, value]) => `<dt>${escape(label)}</dt><dd>${escape(value ?? 'Not recorded')}</dd>`).join('') + '</dl>';
  }
  function comparison(plugin, title) {
    if (!plugin) return `<div class="panel"><h3>${escape(title)}</h3><p class="muted">No record in this snapshot.</p></div>`;
    const status = plugin.status || {};
    const entries = plugin.entrypoints || [];
    return `<div class="panel"><h3>${escape(title)}</h3>${definitions([['Kind', plugin.projectKind], ['Visible', String(plugin.registryVisible)], ['Owner', plugin.owner], ['Archived', String(status.archived ?? 'Not recorded')], ['Fork', String(status.fork ?? 'Not recorded')], ['Plugin types', (plugin.pluginTypes || []).join(', ') || 'None'], ['Entry points', entries.length], ['Metadata source', plugin.metadataSource]])}<p>${escape(plugin.description || 'No description recorded.')}</p><details><summary>Entry points and dependencies</summary><pre class="source">${escape(JSON.stringify({entrypoints: entries, dependencies: plugin.dependencies || []}, null, 2))}</pre></details><details><summary>Complete snapshot record</summary><pre class="source">${escape(JSON.stringify(plugin, null, 2))}</pre></details></div>`;
  }
  const valueText = value => typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  function findingHtml(finding, withProjects) {
    const excluded = new Set(['caseId', 'status', 'affectedStableIds', 'evidenceUrls', 'localEvidence']);
    return `<article class="finding"><h3>${escape(finding.caseId)}</h3>${badge(finding.status || 'Audit note', 'warn')}${Object.entries(finding).filter(([key]) => !excluded.has(key)).map(([key, value]) => `<div class="finding-key">${escape(key.replace(/([A-Z])/g, ' $1'))}</div><p>${escape(valueText(value))}</p>`).join('')}<div class="finding-links">${(finding.evidenceUrls || []).map(url => link(url, url)).join('')}</div>${withProjects ? `<h3>Affected projects</h3><div class="finding-links">${finding.affectedStableIds.map(id => { const item = allRows().find(row => row.id === id.toLowerCase() || (row.row['Original stable ID'] || '').toLowerCase() === id.toLowerCase()); return item ? `<button data-open="${escape(item.id)}">${escape(id)}</button>` : `<span>${escape(id)} (not in this comparison)</span>`; }).join('')}</div>` : ''}</article>`;
  }
  function openDetail(id) {
    const item = allRows().find(row => row.id === id);
    if (!item) return;
    activeId = id;
    const row = item.row, record = review.records[id], findings = findingFor(item);
    $('detail-id').textContent = row['Stable ID']; $('detail-title').textContent = row.Name || id;
    $('detail-badges').innerHTML = badge(row['Review group']) + badge(row.Visibility, row.Visibility === 'Visible' ? 'ok' : '') + badge(statusLabel(record));
    $('detail-body').innerHTML = `<div class="links">${[['Repository URL', 'Repository'], ['Original repository URL', 'Original repository'], ['pyproject.toml URL', 'pyproject.toml'], ['Documentation URL', 'Documentation'], ['PyPI URL', 'PyPI'], ['Original catalogue URL', 'Original catalogue']].map(([key, label]) => link(row[key], label)).join('')}</div>${row['Original stable ID'] ? `<div class="panel">${definitions([['Original ID', row['Original stable ID']], ['Current ID', row['Stable ID']], ['Move evidence', row['Move basis']]])}</div>` : ''}${record.needsReview ? '<div class="banner warn">The source evidence changed or imported reviews conflict. Your notes were retained. Recheck this record and choose a verdict to confirm your review.</div>' : ''}<div class="form-grid"><label>Reviewer verdict<select id="edit-verdict">${data.verdicts.map(value => `<option value="${escape(value)}" ${value === record.fields['Reviewer verdict'] ? 'selected' : ''}>${escape(value || 'Not reviewed')}</option>`).join('')}</select></label><label>Evidence URL<input id="edit-evidence" type="text" maxlength="30000" value="${escape(record.fields['Evidence URL'])}" placeholder="https://…"></label><label class="wide">Reviewer comment<textarea id="edit-comment" maxlength="30000" placeholder="What looks wrong, or why this is a useful example">${escape(record.fields['Reviewer comment'])}</textarea></label><label class="wide">Expected handling<textarea id="edit-handling" maxlength="30000" placeholder="Suggested general rule or narrow exception">${escape(record.fields['Expected handling'])}</textarea></label></div><div id="conflicts">${record.conflicts.map((fields, index) => `<div class="conflict"><h3>Conflicting imported review ${index + 1}</h3>${core.fields.map(key => `<p><strong>${escape(key)}</strong><br>${escape(fields[key] || '(empty)')}</p>`).join('')}<button data-use-conflict="${index}">Use this version</button> <button data-dismiss-conflict="${index}">Keep current fields instead</button></div>`).join('')}</div><div class="panel">${definitions([['Visibility reason', row['Visibility reason'] || (row.Visibility === 'Visible' ? 'Allowed kind; not archived or a fork' : 'No current record')], ['Audit flags', row['Audit flags'] || 'None'], ['Warnings', row.Warnings || 'None']])}</div>${findings.length ? `<div class="panel"><h3>Agent findings</h3>${findings.map(finding => findingHtml(finding, false)).join('')}</div>` : ''}<div class="compare">${comparison(item.current, 'Current snapshot')}${comparison(item.reference, 'Original snapshot')}</div>`;
    const bindings = {'edit-verdict': 'Reviewer verdict', 'edit-evidence': 'Evidence URL', 'edit-comment': 'Reviewer comment', 'edit-handling': 'Expected handling'};
    Object.entries(bindings).forEach(([elementId, field]) => {
      $(elementId).addEventListener(elementId === 'edit-verdict' ? 'change' : 'input', event => {
        record.fields[field] = event.target.value;
        if (field === 'Reviewer verdict' && !record.conflicts.length) record.needsReview = false;
        persist(); renderStats();
      });
    });
    $('detail-save-state').textContent = storageAvailable ? 'Changes autosave in this browser' : 'In memory only. Export before closing.';
    if (!$('detail-dialog').open) $('detail-dialog').showModal();
    $('detail-body').scrollTop = 0;
  }
  function closeDetail() { $('detail-dialog').close(); activeId = null; renderTable(); }
  function verdict(value) {
    if (!activeId) return;
    const record = review.records[activeId];
    record.fields['Reviewer verdict'] = value;
    if (!record.conflicts.length) record.needsReview = false;
    $('edit-verdict').value = value; persist(); renderStats(); toast('Review saved');
  }
  function renderGuide() {
    $('guide-view').innerHTML = `<h2>Review guide</h2>
      <div class="guide-grid">
        <div class="panel"><h3>Review and save decisions</h3>
          <ol><li>Choose a group, then open a project with Review.</li>
            <li>Compare the snapshots and open the live repository or metadata links.</li>
            <li>Set a verdict and add a comment, expected handling, and evidence.</li>
            <li>Export review JSON to keep your latest decisions.</li></ol>
          <p>Use one working folder with <code>index.html</code> and the latest
            <code>catalogue-review.json</code>. Regenerate the same page and
            import the latest JSON, or supply it as <code>--previous</code>.
            Old HTML pages, dated folders, and a history of exported files are not required.</p>
          <p>Autosave belongs to this browser and origin, not the HTML file.
            Export before refreshing the page or clearing browser data.
            Your browser may download JSON elsewhere or add a filename suffix;
            replace your working copy after the new export succeeds.</p>
        </div>
        <div class="panel"><h3>What the data means</h3>
          <p>The embedded baseline is not guaranteed to be fully validated.
            Generation of this page does not perform a new crawl.
            Agent findings are separate evidence, not your verdicts.</p>
          <p>A reference snapshot is optional comparison data, not a previous review.
            Without one, visible entries are not labeled as new and no reference-only
            or changed-metadata rows can be identified.
            Your latest review JSON contains the saved notes, including notes on
            records no longer in either snapshot. Import uses verified moves when
            supplied and flags changed sources or conflicting reviews for you to check.</p>
          <p>CSV export is optional for other tools. It includes every row and
            the four reviewer fields, but not source fingerprints or conflict history.</p>
        </div>
      </div>
      <div class="panel"><h3>Review groups</h3>
        <table class="guide-table"><thead><tr><th>Group</th><th>Meaning</th></tr></thead>
          <tbody>${data.groups.map(group => `<tr><td>${escape(group.name)}</td><td>${escape(group.description)}</td></tr>`).join('')}</tbody></table>
        <p>Groups use the first matching category. A moved record can also have
          a link-collision flag; inspect the flags and source details, not only the group.</p>
      </div>
      <div class="panel"><h3>Classification and hiding rules</h3>
        <ol class="rules">
          <li>Template/example heuristics run first (for example an <code>examples</code>
            path, a template name, or a cookiecutter repository), even if entry points exist.</li>
          <li>A parsed <code>nomad.plugin</code> entry point makes the record a plugin.</li>
          <li>Distribution-name and description heuristics run next.</li>
          <li>A <code>nomad-lab</code> runtime or optional dependency makes it a NOMAD-dependent package.</li>
          <li>Anything else is an ecosystem-package fallback. Code-search text alone is not proof of an integration.</li>
        </ol>
        <p>Plugins, dependent packages, and curated official software/templates
          are visible unless GitHub marks the repository archived or a fork.
          Distributions, ordinary templates/examples, and fallback ecosystem
          packages remain hidden in the JSON. Candidate exclusions instead prevent export.</p>
      </div>`;
  }
  function download(text, name, type) {
    const url = URL.createObjectURL(new Blob([text], {type}));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  try {
    if (data.savedReview) review = core.restore(data, review, data.savedReview).review;
    const stored = localStorage.getItem(storageKey);
    if (stored) {
      const restored = core.restore(data, review, JSON.parse(stored)); review = restored.review;
      const {changed, conflicts} = restored.summary;
      if (changed || conflicts) feedback(`Restored saved notes. ${changed} source record(s) changed; ${conflicts} review conflict(s) need checking.`);
    }
    $('saving').textContent = 'Browser autosave ready. Export JSON for a portable backup.';
  } catch (_) {
    storageAvailable = false;
    storageBlocked = true;
    feedback('Saved browser data could not be loaded. It has not been overwritten. Export this session before closing; import a known JSON backup if needed.');
    $('saving').textContent = 'Could not restore browser storage';
  }
  $('snapshot-sub').textContent = `${data.records.filter(item => item.current).length} current records · Catalogue schema ${data.schemaVersion} · Workspace built ${new Date(data.builtAt).toLocaleString()}${data.hasReference ? '' : ' · No reference supplied'}`;
  data.groups.forEach(group => { const option = document.createElement('option'); option.value = option.textContent = group.name; $('group-filter').append(option); });
  [...new Set(data.records.map(item => item.row['Current kind']).filter(Boolean))].sort().forEach(kind => { const option = document.createElement('option'); option.value = option.textContent = kind; $('kind-filter').append(option); });
  ['search', 'group-filter', 'visibility-filter', 'status-filter', 'kind-filter', 'attention-filter'].forEach(id => $(id).addEventListener(id === 'search' ? 'input' : 'change', () => { page = 0; renderTable(); }));
  $('reset-filters').addEventListener('click', () => { ['search', 'group-filter', 'visibility-filter', 'status-filter', 'kind-filter', 'attention-filter'].forEach(id => $(id).value = ''); page = 0; renderTable(); });
  $('previous-page').addEventListener('click', () => { page--; renderTable(); }); $('next-page').addEventListener('click', () => { page++; renderTable(); });
  document.addEventListener('click', event => {
    const button = event.target.closest('button'); if (!button) return;
    if (button.dataset.view) setView(button.dataset.view);
    if (button.dataset.group) { $('group-filter').value = button.dataset.group; page = 0; setView('review'); renderTable(); }
    if (button.dataset.open) openDetail(button.dataset.open);
    if (button.dataset.useConflict !== undefined || button.dataset.dismissConflict !== undefined) {
      const record = review.records[activeId];
      const index = Number(button.dataset.useConflict ?? button.dataset.dismissConflict);
      if (button.dataset.useConflict !== undefined) record.fields = {...record.conflicts[index]};
      record.conflicts.splice(index, 1);
      record.needsReview = true;
      persist(); openDetail(activeId);
    }
  });
  $('close-detail').addEventListener('click', closeDetail);
  $('detail-dialog').addEventListener('cancel', () => { activeId = null; renderTable(); });
  $('looks-right').addEventListener('click', () => verdict('Looks right'));
  $('research').addEventListener('click', () => verdict('Needs research'));
  $('save-next').addEventListener('click', () => {
    const index = filtered.findIndex(item => item.id === activeId);
    const next = filtered[index + 1];
    renderTable();
    if (next) { openDetail(next.id); } else { closeDetail(); toast('End of the current filtered list'); }
  });
  $('export').addEventListener('click', () => {
    download(JSON.stringify(core.pack(review), null, 2), 'catalogue-review.json', 'application/json');
    unsavedExport = false; toast('Review JSON exported');
  });
  $('export-csv').addEventListener('click', () => download(core.csv(data, review), 'catalogue-review.csv', 'text/csv;charset=utf-8'));
  $('import').addEventListener('click', () => $('import-file').click());
  $('import-file').addEventListener('change', async event => {
    const file = event.target.files[0]; if (!file) return;
    try {
      if (file.size > 20000000) throw new Error('Review file is too large (maximum 20 MB).');
      const restored = core.restore(data, review, JSON.parse(await file.text()));
      review = restored.review; persist(); renderTable();
      const summary = restored.summary;
      feedback(`Imported ${summary.restored} review records; ${summary.changed} changed sources, ${summary.conflicts} conflicts, ${summary.retained} prior-review-only records retained. Nothing was written to the catalogue.`);
    } catch (error) { feedback(`Import rejected; existing reviews were not changed. ${error.message}`); }
    event.target.value = '';
  });
  window.addEventListener('beforeunload', event => { if (!storageAvailable && unsavedExport) { event.preventDefault(); event.returnValue = ''; } });
  $('audit-view').innerHTML = `<h2>Agent findings</h2><p class="sub">Preliminary checks kept separately from your review decisions. Open an affected project to compare your assessment.</p><div class="panel">${data.findings.length ? data.findings.map(finding => findingHtml(finding, true)).join('') : '<p>No agent findings were supplied when this page was generated.</p>'}</div>`;
  renderGuide(); renderTable();
})();
