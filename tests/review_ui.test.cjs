/* DOM-shell smoke tests; these do not replace visual browser verification. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const core = require('../src/nomad_plugins/review_assets/core.js');
const source = fs.readFileSync(path.join(__dirname, '../src/nomad_plugins/review_assets/ui.js'), 'utf8');
const template = fs.readFileSync(path.join(__dirname, '../src/nomad_plugins/review_assets/template.html'), 'utf8');

function fixture(saved = new Map(), options = {}) {
  const id = 'github.com/example/parser';
  const row = {'Stable ID': id, 'Original stable ID': '', 'Name': '<unsafe name>', 'Review group': 'Hidden plugin', 'Visibility': 'Hidden', 'Current kind': 'plugin', 'Visibility reason': 'archived repository', 'Repository URL': 'javascript:bad()'};
  const data = {records: [{id, fingerprint: 'old', row, current: {projectKind: 'plugin', registryVisible: false, status: {archived: true}}, reference: null, initial: Object.fromEntries(core.fields.map(field => [field, '']))}], fields: core.fields, verdicts: core.verdicts, columns: Object.keys(row).concat(core.fields), groups: [{name: 'Hidden plugin', description: 'An archived plugin'}], findings: [], builtAt: '2026-11-24T09:00:00Z', schemaVersion: '2.2.0', hasReference: false};
  const elements = new Map(), listeners = {};
  class Element {
    constructor(id) { this.id = id; this.value = ''; this.listeners = {}; this.classes = new Set(); this.classList = {add: name => this.classes.add(name), remove: name => this.classes.delete(name), toggle: (name, enabled) => enabled ? this.classes.add(name) : this.classes.delete(name)}; }
    set innerHTML(html) {
      this.html = html;
      for (const match of html.matchAll(/\bid="([^"]+)"/g)) elements.set(match[1], new Element(match[1]));
    }
    get innerHTML() { return this.html || ''; }
    addEventListener(name, callback) { this.listeners[name] = callback; }
    setAttribute() {}
    append() {}
    click() {}
    showModal() { this.open = true; }
    close() { this.open = false; }
    emit(name, event = {}) { return this.listeners[name]({...event, target: event.target || this}); }
  }
  for (const match of template.matchAll(/\bid="([^"]+)"/g)) elements.set(match[1], new Element(match[1]));
  elements.get('review-data').textContent = JSON.stringify(data);
  const document = {getElementById: id => elements.get(id), querySelectorAll: () => [], createElement: () => new Element('new'), addEventListener: (name, callback) => { listeners[name] = callback; }};
  const localStorage = {getItem: key => { if (options.corrupt) return 'bad JSON'; return saved.get(key) || null; }, setItem: (key, value) => { if (options.blocked) throw new Error('blocked'); saved.set(key, value); }};
  const context = {CatalogueReview: core, document, localStorage, URL, Blob, console, setTimeout: () => 0, clearTimeout() {}, window: {addEventListener() {}}};
  vm.runInNewContext(source, context);
  const click = dataset => listeners.click({target: {closest: () => ({dataset})}});
  return {elements, saved, id, click};
}

test('UI renders, escapes names, blocks unsafe links and filters the table', () => {
  const app = fixture();
  assert.match(app.elements.get('table-body').innerHTML, /&lt;unsafe name&gt;/);
  assert.doesNotMatch(app.elements.get('table-body').innerHTML, /href="javascript:/);
  assert.match(app.elements.get('visible-count').textContent, /1 of 1/);
  app.elements.get('search').value = 'missing';
  app.elements.get('search').emit('input');
  assert.match(app.elements.get('table-body').innerHTML, /No matching records/);
  app.elements.get('reset-filters').emit('click');
  assert.match(app.elements.get('visible-count').textContent, /1 of 1/);
  app.click({view: 'guide'});
  assert.equal(app.elements.get('review-view').classes.has('hidden'), true);
  assert.equal(app.elements.get('guide-view').classes.has('hidden'), false);
});

test('detail edits autosave and survive a fresh UI initialization', () => {
  const app = fixture();
  app.click({open: app.id});
  assert.equal(app.elements.get('detail-dialog').open, true);
  app.elements.get('edit-comment').value = 'A useful policy example';
  app.elements.get('edit-comment').emit('input');
  app.elements.get('looks-right').emit('click');
  app.elements.get('close-detail').emit('click');
  const restored = fixture(app.saved);
  assert.match(restored.elements.get('table-body').innerHTML, /A useful policy example/);
  assert.match(restored.elements.get('table-body').innerHTML, /Looks right/);
});

test('blocked storage is visible and unreadable existing data is not overwritten', () => {
  const saved = new Map();
  const app = fixture(saved, {corrupt: true});
  app.click({open: app.id});
  app.elements.get('edit-comment').value = 'In memory';
  app.elements.get('edit-comment').emit('input');
  assert.match(app.elements.get('saving').textContent, /unavailable/);
  assert.equal(saved.size, 0);
});

test('invalid import leaves local notes unchanged', async () => {
  const app = fixture();
  app.click({open: app.id});
  app.elements.get('edit-comment').value = 'Keep this';
  app.elements.get('edit-comment').emit('input');
  const before = app.saved.get('nomad-catalogue-review:v1');
  app.elements.get('import-file').files = [{size: 2, text: async () => '{}'}];
  await app.elements.get('import-file').emit('change');
  assert.equal(app.saved.get('nomad-catalogue-review:v1'), before);
  assert.match(app.elements.get('feedback').textContent, /Import rejected/);
});
