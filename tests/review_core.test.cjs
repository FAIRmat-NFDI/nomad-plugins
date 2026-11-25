const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../src/nomad_plugins/review_assets/core.js');
const item = (id = 'github.com/example/parser', fingerprint = 'original') => ({
  id, fingerprint, row: {'Stable ID': id, 'Name': 'Parser', 'Review group': 'New visible', 'Visibility': 'Visible', 'Current kind': 'plugin', 'Original stable ID': ''}, initial: Object.fromEntries(core.fields.map(key => [key, ''])),
});
const data = (...records) => ({records, columns: ['Stable ID', ...core.fields]});

test('notes survive JSON round trip and reordered records', () => {
  const source = data(item(), item('github.com/example/other'));
  const review = core.state(source);
  review.records[source.records[0].id].fields['Reviewer comment'] = 'Needs a narrow exception';
  const reversed = data(...source.records.toReversed());
  const result = core.restore(reversed, core.state(reversed), core.pack(review));
  assert.equal(result.review.records[source.records[0].id].fields['Reviewer comment'], 'Needs a narrow exception');
});

test('changed source requires re-review without deleting comments', () => {
  const source = data(item());
  const review = core.state(source);
  review.records[source.records[0].id].fields['Reviewer verdict'] = 'Looks right';
  const refreshed = data(item(undefined, 'changed'));
  const result = core.restore(refreshed, core.state(refreshed), core.pack(review));
  assert.equal(result.summary.changed, 1);
  assert.equal(core.status(result.review.records[source.records[0].id]), 'changed');
  assert.equal(result.review.records[source.records[0].id].fields['Reviewer verdict'], 'Looks right');
});

test('conflicts retain both versions and empty imports cannot erase notes', () => {
  const source = data(item());
  const local = core.state(source), other = core.state(source);
  local.records[source.records[0].id].fields['Reviewer comment'] = 'Local';
  other.records[source.records[0].id].fields['Reviewer comment'] = 'Imported';
  const result = core.restore(source, local, core.pack(other));
  const record = result.review.records[source.records[0].id];
  assert.equal(record.fields['Reviewer comment'], 'Local');
  assert.equal(record.conflicts[0]['Reviewer comment'], 'Imported');
  assert.equal(core.status(record), 'conflict');
  const empty = core.restore(source, result.review, core.pack(core.state(source)));
  assert.equal(empty.review.records[source.records[0].id].fields['Reviewer comment'], 'Local');
  const matching = core.state(source);
  matching.records[source.records[0].id].fields['Reviewer comment'] = 'Local';
  const sameFields = core.restore(source, result.review, core.pack(matching));
  assert.equal(sameFields.review.records[source.records[0].id].conflicts[0]['Reviewer comment'], 'Imported');
});

test('missing records and verified ID moves retain notes', () => {
  const source = data(item('github.com/example/old'));
  const review = core.state(source);
  review.records[source.records[0].id].fields['Reviewer comment'] = 'Keep';
  const missing = core.restore(data(), core.state(data()), core.pack(review));
  assert.equal(core.rows(data(), missing.review)[0].row['Review group'], 'Prior-review only');
  const moved = item('github.com/example/new');
  moved.row['Original stable ID'] = source.records[0].id;
  const result = core.restore(data(moved), core.state(data(moved)), core.pack(review));
  assert.equal(result.review.records[moved.id].fields['Reviewer comment'], 'Keep');
  assert.equal(core.rows(data(moved), result.review).length, 1);
});

test('invalid imports fail before changing the existing state', () => {
  const source = data(item());
  const review = core.state(source), payload = core.pack(review);
  payload.records[source.records[0].id].fields['Reviewer verdict'] = 'Made up';
  assert.throws(() => core.restore(source, review, payload), /Unknown reviewer verdict/);
  assert.equal(review.records[source.records[0].id].fields['Reviewer verdict'], '');
});

test('filters include notes, hidden rows and agent findings', () => {
  const record = item(); record.row.Visibility = 'Hidden';
  const source = data(record), review = core.state(source);
  review.records[record.id].fields['Reviewer comment'] = 'Special rule';
  assert.equal(core.filterRows(source.records, review, {search: 'special', visibility: 'Hidden'}).length, 1);
  assert.equal(core.filterRows(source.records, review, {attention: 'agent', auditIds: [record.id]}).length, 1);
  assert.equal(core.filterRows(source.records, review, {visibility: 'Visible'}).length, 0);
});

test('CSV exports all notes with formula-injection protection', () => {
  const source = data(item()), review = core.state(source);
  review.records[source.records[0].id].fields['Reviewer comment'] = '=bad,"text"\nnext';
  assert.match(core.csv(source, review), /"'=bad,""text""\nnext"/);
});
