/* Pure review logic: shared by the offline page and Node tests. */
(function (root) {
  'use strict';
  const fields = ['Reviewer verdict', 'Reviewer comment', 'Expected handling', 'Evidence URL'];
  const verdicts = ['', 'Looks right', 'Should be hidden', 'Should be excluded', 'Should be visible', 'Metadata wrong', 'Needs research'];
  const clone = value => JSON.parse(JSON.stringify(value));
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const substantive = record => fields.some(key => Boolean(record.fields[key]));
  const blank = row => ({fingerprint: row.fingerprint, row: clone(row.row), fields: Object.fromEntries(fields.map(key => [key, row.initial[key] || ''])), needsReview: false, conflicts: []});
  function state(data) {
    return {records: Object.fromEntries(data.records.map(row => [row.id, blank(row)]))};
  }
  function validateFields(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Missing reviewer fields.');
    const result = {};
    fields.forEach(key => {
      const text = value[key] === undefined ? '' : value[key];
      if (typeof text !== 'string' || text.length > 30000) throw new Error('Reviewer fields must be text of at most 30,000 characters.');
      if (key === fields[0] && !verdicts.includes(text)) throw new Error('Unknown reviewer verdict.');
      result[key] = text;
    });
    return result;
  }
  function validatePayload(payload) {
    if (!payload || payload.format !== 'nomad-catalogue-review' || payload.version !== 1 || !payload.records || typeof payload.records !== 'object' || Array.isArray(payload.records)) {
      throw new Error('Choose a catalogue review JSON export (version 1).');
    }
    const entries = Object.entries(payload.records);
    if (entries.length > 10000) throw new Error('Too many review records.');
    const seen = new Set();
    return entries.map(([rawId, record]) => {
      const id = rawId.toLowerCase();
      if (!/^github\.com\/[^/#\s]+\/[^/#\s]+(?:#\S+)?$/.test(id) || seen.has(id)) throw new Error('Invalid or duplicate stable ID in review file.');
      seen.add(id);
      if (!record || !record.row || typeof record.row !== 'object' || Array.isArray(record.row) || typeof record.fingerprint !== 'string') throw new Error('Missing review row or fingerprint.');
      if (typeof record.row['Stable ID'] !== 'string' || record.row['Stable ID'].toLowerCase() !== id) throw new Error('Review row and stable ID disagree.');
      if (Object.values(record.row).some(value => typeof value !== 'string' || value.length > 100000)) throw new Error('Invalid row metadata.');
      if (record.conflicts !== undefined && (!Array.isArray(record.conflicts) || record.conflicts.length > 100)) throw new Error('Invalid saved conflict history.');
      return [id, {row: clone(record.row), fingerprint: record.fingerprint, fields: validateFields(record.fields), needsReview: Boolean(record.needsReview), conflicts: (record.conflicts || []).map(validateFields)}];
    });
  }
  function restore(data, existing, payload) {
    const incomingRecords = validatePayload(payload); // Validate completely before mutation.
    const next = clone(existing);
    const sources = new Map(data.records.map(row => [row.id, row]));
    const aliases = new Map(data.records.filter(row => row.row['Original stable ID']).map(row => [row.row['Original stable ID'].toLowerCase(), row.id]));
    const summary = {restored: 0, changed: 0, conflicts: 0, retained: 0};
    incomingRecords.forEach(([oldId, incoming]) => {
      const id = aliases.get(oldId) || oldId;
      const source = sources.get(id);
      if (!source) {
        if (substantive(incoming) || incoming.conflicts.length) summary.retained++;
        else return;
      }
      const local = next.records[id];
      if (local && !substantive(incoming) && !incoming.conflicts.length) return;
      if (local && substantive(local) && substantive(incoming) && !same(local.fields, incoming.fields)) {
        fields.forEach(key => { if (!local.fields[key]) local.fields[key] = incoming.fields[key]; });
        const candidates = [incoming.fields, ...incoming.conflicts];
        candidates.forEach(candidate => {
          if (!same(candidate, local.fields) && !local.conflicts.some(value => same(value, candidate))) local.conflicts.push(clone(candidate));
        });
        local.needsReview = true;
        summary.conflicts++;
      } else {
        const record = source ? blank(source) : clone(incoming);
        record.fields = clone(incoming.fields);
        record.conflicts = clone(local ? local.conflicts : []);
        incoming.conflicts.forEach(candidate => {
          if (!record.conflicts.some(value => same(value, candidate))) record.conflicts.push(clone(candidate));
        });
        record.needsReview = incoming.needsReview || Boolean(local && local.needsReview);
        next.records[id] = record;
      }
      const record = next.records[id];
      if (source && incoming.fingerprint !== source.fingerprint && substantive(record)) {
        record.needsReview = true;
        summary.changed++;
      }
      summary.restored++;
    });
    return {review: next, summary};
  }
  function pack(review) {
    return {format: 'nomad-catalogue-review', version: 1, exportedAt: new Date().toISOString(), recommendationsOnly: true, records: clone(review.records)};
  }
  function rows(data, review) {
    const all = [...data.records];
    const ids = new Set(all.map(row => row.id));
    Object.entries(review.records).forEach(([id, record]) => {
      if (ids.has(id)) return;
      all.push({id, fingerprint: record.fingerprint, current: null, reference: null, initial: {}, row: {...record.row, 'Review group': 'Prior-review only', 'Presence': 'Prior review only', 'Visibility': 'Absent', 'Current kind': '', 'Visibility reason': 'Not in either embedded snapshot'}});
    });
    return all;
  }
  function status(record) {
    if (record.conflicts.length) return 'conflict';
    if (record.needsReview) return 'changed';
    if (!record.fields['Reviewer verdict']) return 'pending';
    if (record.fields['Reviewer verdict'] === 'Needs research') return 'research';
    return 'reviewed';
  }
  function filterRows(all, review, filters = {}) {
    const query = (filters.search || '').trim().toLowerCase();
    return all.filter(item => {
      const row = item.row, record = review.records[item.id];
      if (filters.group && row['Review group'] !== filters.group) return false;
      if (filters.visibility && row.Visibility !== filters.visibility) return false;
      if (filters.kind && row['Current kind'] !== filters.kind) return false;
      if (filters.status && status(record) !== filters.status) return false;
      if (filters.attention === 'agent' && !(filters.auditIds || []).includes(item.id) && !(filters.auditIds || []).includes((row['Original stable ID'] || '').toLowerCase())) return false;
      if (filters.attention === 'flags' && !row['Audit flags']) return false;
      return !query || [...Object.values(row), ...Object.values(record.fields)].join(' ').toLowerCase().includes(query);
    });
  }
  function csv(data, review) {
    const safe = value => {
      const text = String(value || '');
      const protectedText = /^[\s]*[=+\-@]/.test(text) ? "'" + text : text;
      return '"' + protectedText.replace(/"/g, '""') + '"';
    };
    return '\ufeff' + [data.columns, ...rows(data, review).map(item => data.columns.map(column => fields.includes(column) ? review.records[item.id].fields[column] : item.row[column] || ''))].map(row => row.map(safe).join(',')).join('\r\n') + '\r\n';
  }
  const api = {fields, verdicts, blank, state, validateFields, restore, pack, rows, status, filterRows, csv};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.CatalogueReview = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
