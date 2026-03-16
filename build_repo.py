import json
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

BASE = Path('/mnt/data/precize-iran-mitre-matrix')
DATA = BASE / 'data'
GEN = DATA / 'generated_layers'
ASSETS = BASE / 'assets'
SCRIPTS = BASE / 'scripts'
for p in [DATA, GEN, ASSETS, SCRIPTS]:
    p.mkdir(parents=True, exist_ok=True)

GROUPS = [
    {"id":"G1030","name":"Agrius","confidence":"explicit","rationale":"MITRE describes Agrius as an Iranian threat group."},
    {"id":"G0130","name":"Ajax Security Team","confidence":"suspected","rationale":"MITRE says Ajax Security Team is believed to be operating out of Iran."},
    {"id":"G0064","name":"APT33","confidence":"suspected","rationale":"MITRE describes APT33 as a suspected Iranian threat group."},
    {"id":"G0087","name":"APT39","confidence":"explicit","rationale":"MITRE links APT39 activity to the Iranian MOIS through Rana Intelligence Computing."},
    {"id":"G1044","name":"APT42","confidence":"explicit","rationale":"MITRE describes APT42 as an Iranian-sponsored threat group."},
    {"id":"G0003","name":"Cleaver","confidence":"explicit","rationale":"MITRE describes Cleaver as an Iranian threat group."},
    {"id":"G0052","name":"CopyKittens","confidence":"suspected","rationale":"MITRE describes CopyKittens as a suspected Iranian cyber espionage group."},
    {"id":"G1012","name":"CURIUM","confidence":"explicit","rationale":"MITRE describes CURIUM as an Iranian threat group."},
    {"id":"G1027","name":"CyberAv3ngers","confidence":"suspected","rationale":"MITRE describes CyberAv3ngers as suspected IRGC-affiliated."},
    {"id":"G0137","name":"Ferocious Kitten","confidence":"suspected","rationale":"MITRE describes Ferocious Kitten as a threat group with Iranian links."},
    {"id":"G0117","name":"Fox Kitten","confidence":"suspected","rationale":"MITRE describes Fox Kitten as a suspected Iranian threat group."},
    {"id":"G0043","name":"Group5","confidence":"explicit","rationale":"MITRE describes Group5 as an Iranian government cyber espionage group."},
    {"id":"G0077","name":"Leafminer","confidence":"suspected","rationale":"MITRE describes Leafminer as a suspected Iranian threat group."},
    {"id":"G0059","name":"Magic Hound","confidence":"suspected","rationale":"MITRE describes Magic Hound as a suspected Iranian threat group."},
    {"id":"G1009","name":"Moses Staff","confidence":"suspected","rationale":"MITRE describes Moses Staff as a suspected Iranian threat group."},
    {"id":"G0069","name":"MuddyWater","confidence":"explicit","rationale":"MITRE describes MuddyWater as an Iranian threat group."},
    {"id":"G0049","name":"OilRig","confidence":"suspected","rationale":"MITRE describes OilRig as a suspected Iranian threat group."},
    {"id":"G0122","name":"Silent Librarian","confidence":"explicit","rationale":"MITRE describes Silent Librarian as an Iranian cyber espionage group."},
]
SELECTED = {g['id']: g for g in GROUPS}

techniques_xlsx = DATA / 'enterprise-attack-v18.1-techniques.xlsx'
groups_xlsx = DATA / 'enterprise-attack-v18.1-groups.xlsx'
tactics_xlsx = DATA / 'enterprise-attack-v18.1-tactics.xlsx'

tech_df = pd.read_excel(techniques_xlsx, sheet_name='techniques')
group_df = pd.read_excel(groups_xlsx, sheet_name='groups')
uses_df = pd.read_excel(groups_xlsx, sheet_name='techniques used')
tactics_df = pd.read_excel(tactics_xlsx, sheet_name='tactics')

tech_df = tech_df.fillna('')
group_df = group_df.fillna('')
uses_df = uses_df.fillna('')

tech_by_id = {}
for _, row in tech_df.iterrows():
    tactics = [t.strip() for t in str(row['tactics']).split(',') if str(t).strip()]
    platforms = [p.strip() for p in str(row['platforms']).split(',') if str(p).strip()]
    tech_by_id[row['ID']] = {
        'id': row['ID'],
        'name': row['name'],
        'description': row['description'],
        'url': row['url'],
        'tactics': tactics,
        'platforms': platforms,
        'is_subtechnique': bool(row['is sub-technique']) if isinstance(row['is sub-technique'], bool) else str(row['is sub-technique']).lower() == 'true',
        'subtechnique_of': row['sub-technique of'],
    }

group_meta = {}
for _, row in group_df.iterrows():
    if row['ID'] in SELECTED:
        group_meta[row['ID']] = {
            'id': row['ID'],
            'name': row['name'],
            'description': row['description'],
            'url': row['url'],
            'associated_groups': row['associated groups'],
        }

all_groups = []
tech_counts = Counter()
tech_to_groups = defaultdict(list)
tactic_to_techs = defaultdict(set)
validation = []

for gid, choice in SELECTED.items():
    gmeta = group_meta.get(gid, {'id': gid, 'name': choice['name'], 'description': '', 'url': f'https://attack.mitre.org/groups/{gid}/', 'associated_groups': ''})
    rows = uses_df[uses_df['source ID'] == gid].copy()
    rows = rows.sort_values(['target ID', 'target name'])
    generated_techs = []
    seen = set()
    for _, row in rows.iterrows():
        tid = row['target ID']
        if tid in seen:
            continue
        seen.add(tid)
        meta = tech_by_id.get(tid, {'id': tid, 'name': row['target name'], 'description': '', 'url': f'https://attack.mitre.org/techniques/{tid.replace(".", "/")}/', 'tactics': [], 'platforms': []})
        generated_techs.append({
            'techniqueID': tid,
            'name': meta['name'],
            'url': meta['url'],
            'tactics': meta['tactics'],
            'platforms': meta['platforms'],
            'comment': row['mapping description'],
            'showSubtechniques': True,
        })
        tech_counts[tid] += 1
        tech_to_groups[tid].append({'id': gid, 'name': gmeta['name']})
        for tactic in meta['tactics']:
            tactic_to_techs[tactic].add(tid)

    layer = {
        'name': f"{gmeta['name']} ({gid})",
        'description': f"Enterprise techniques used by {gmeta['name']} derived from MITRE ATT&CK Excel v18.1 'techniques used' mappings.",
        'domain': 'enterprise-attack',
        'versions': {'layer': '4.5', 'attack': '18.1', 'navigator': '5.2.0'},
        'techniques': [
            {
                'techniqueID': t['techniqueID'],
                'comment': t['comment'],
                'score': 1,
                'color': '#66b1ff',
                'showSubtechniques': True,
            }
            for t in generated_techs
        ],
        'legendItems': [{'label': f"used by {gmeta['name']}", 'color': '#66b1ff'}],
        'metadata': [
            {'name': 'source', 'value': 'MITRE ATT&CK Excel v18.1 groups.xlsx / techniques used'},
            {'name': 'groupPage', 'value': gmeta['url']},
        ],
    }
    (GEN / f'{gid}-enterprise-layer.json').write_text(json.dumps(layer, indent=2))

    record = {
        **choice,
        **gmeta,
        'layer_url': f'data/generated_layers/{gid}-enterprise-layer.json',
        'official_layer_url': f'https://attack.mitre.org/groups/{gid}/{gid}-enterprise-layer.json',
        'technique_count': len(generated_techs),
        'techniques': generated_techs,
    }
    all_groups.append(record)
    validation.append({
        'id': gid,
        'name': gmeta['name'],
        'group_url': gmeta['url'],
        'generated_layer_path': f'data/generated_layers/{gid}-enterprise-layer.json',
        'official_layer_url': f'https://attack.mitre.org/groups/{gid}/{gid}-enterprise-layer.json',
        'technique_count': len(generated_techs),
        'validated': len(generated_techs) > 0,
        'source': 'MITRE ATT&CK Excel v18.1 / techniques used sheet',
    })

combined_layer = {
    'name': 'Precize - Iran-Linked ATT&CK Enterprise Matrix',
    'description': 'Aggregated Enterprise ATT&CK techniques across selected Iran-linked groups. Score = number of selected groups mapped to the technique.',
    'domain': 'enterprise-attack',
    'versions': {'layer': '4.5', 'attack': '18.1', 'navigator': '5.2.0'},
    'techniques': [
        {
            'techniqueID': tid,
            'score': count,
            'comment': 'Used by ' + ', '.join(g['name'] for g in tech_to_groups[tid]),
            'showSubtechniques': True,
        }
        for tid, count in tech_counts.most_common()
    ],
    'gradient': {'colors': ['#fff7ec', '#fc8d59', '#b30000'], 'minValue': 1, 'maxValue': max(tech_counts.values()) if tech_counts else 1},
    'legendItems': [
        {'label': 'Used by fewer selected groups', 'color': '#fc8d59'},
        {'label': 'Used by more selected groups', 'color': '#b30000'},
    ],
}
(DATA / 'iran_attack_aggregated_layer.json').write_text(json.dumps(combined_layer, indent=2))

enterprise_tactics = [
    'reconnaissance','resource development','initial access','execution','persistence','privilege escalation',
    'defense evasion','credential access','discovery','lateral movement','collection','command and control','exfiltration','impact'
]

technique_rows = []
for tid, count in tech_counts.most_common():
    meta = tech_by_id.get(tid, {'id': tid, 'name': tid, 'url': f'https://attack.mitre.org/techniques/{tid.replace(".", "/")}/', 'tactics': [], 'platforms': []})
    technique_rows.append({
        'techniqueID': tid,
        'name': meta['name'],
        'url': meta['url'],
        'group_count': count,
        'tactics': meta['tactics'],
        'platforms': meta['platforms'],
        'groups': tech_to_groups[tid],
    })

matrix_cards = []
for tactic in enterprise_tactics:
    tids = [tid for tid in tech_counts if tactic in [t.lower() for t in tech_by_id.get(tid, {}).get('tactics', [])]]
    tids = sorted(tids, key=lambda x: (-tech_counts[x], x))
    matrix_cards.append({
        'tactic': tactic,
        'technique_count': len(tids),
        'top_techniques': [
            {
                'techniqueID': tid,
                'name': tech_by_id.get(tid, {}).get('name', tid),
                'url': tech_by_id.get(tid, {}).get('url', f'https://attack.mitre.org/techniques/{tid.replace(".", "/")}/'),
                'group_count': tech_counts[tid],
                'groups': tech_to_groups[tid],
            }
            for tid in tids[:12]
        ]
    })

manifest = {
    'generated_from': {
        'groups_xlsx': 'data/enterprise-attack-v18.1-groups.xlsx',
        'techniques_xlsx': 'data/enterprise-attack-v18.1-techniques.xlsx',
        'tactics_xlsx': 'data/enterprise-attack-v18.1-tactics.xlsx',
        'source_index': 'https://attack.mitre.org/resources/attack-data-and-tools/',
        'groups_page': 'https://attack.mitre.org/groups/',
        'enterprise_matrix_page': 'https://attack.mitre.org/matrices/enterprise/',
    },
    'selected_group_count': len(all_groups),
    'unique_technique_count': len(tech_counts),
    'groups': all_groups,
    'validation': validation,
    'techniques': technique_rows,
    'tactic_summary': matrix_cards,
}
(DATA / 'manifest.json').write_text(json.dumps(manifest, indent=2))
(DATA / 'validation.json').write_text(json.dumps(validation, indent=2))
(SCRIPTS / 'build_repo.py').write_text(Path(__file__).read_text())

(BASE / 'index.html').write_text('''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Precize | Iran-Linked MITRE ATT&CK Matrix</title>
  <link rel="stylesheet" href="assets/styles.css" />
</head>
<body>
  <header class="hero">
    <div class="wrap">
      <div class="eyebrow">Precize External Research</div>
      <h1>Iran-Linked MITRE ATT&amp;CK Enterprise Matrix</h1>
      <p class="lede">A complete GitHub Pages repository for sharing selected Iran-linked ATT&amp;CK groups, their mapped techniques, and an aggregated Enterprise Navigator layer. The site uses MITRE ATT&amp;CK Excel v18.1 as the reproducible source dataset and keeps per-group generated layer files in the repository.</p>
      <div class="actions">
        <a class="button primary" href="data/iran_attack_aggregated_layer.json">Download combined Navigator layer</a>
        <a class="button" target="_blank" rel="noreferrer" href="https://mitre-attack.github.io/attack-navigator/">Open ATT&amp;CK Navigator</a>
        <a class="button" href="README.md">Deployment guide</a>
      </div>
    </div>
  </header>

  <main class="wrap">
    <section class="grid stats" id="stats"></section>

    <section class="panel">
      <div class="panel-head">
        <h2>Validation</h2>
        <p>Each selected group has a generated local Navigator layer and a linked official MITRE group page. Technique counts come from MITRE ATT&amp;CK Excel v18.1 <code>groups.xlsx</code> → <code>techniques used</code>.</p>
      </div>
      <div id="validationTable"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Enterprise tactic view</h2>
        <p>This matrix-style rendering shows the top observed techniques under each Enterprise tactic. The number shown is the count of selected groups mapped to that technique.</p>
      </div>
      <div id="matrix"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Technique catalog</h2>
        <p>Search across technique ID, technique name, tactic, or group name.</p>
      </div>
      <div class="filters">
        <input id="techSearch" type="search" placeholder="Search technique, tactic, or group" />
        <select id="tacticFilter"><option value="">All tactics</option></select>
      </div>
      <div id="techniquesTable"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Selected groups</h2>
        <p>Each card links to the MITRE group page, the generated local layer file, and the official MITRE layer URL pattern.</p>
      </div>
      <div id="groupCards" class="card-grid"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Repository contents</h2>
      </div>
      <ul class="repo-list">
        <li><code>data/generated_layers/*.json</code> - one generated layer per included group</li>
        <li><code>data/iran_attack_aggregated_layer.json</code> - combined ATT&amp;CK Navigator layer</li>
        <li><code>data/manifest.json</code> - complete machine-readable dataset for the site</li>
        <li><code>data/enterprise-attack-v18.1-*.xlsx</code> - MITRE ATT&amp;CK source files used to build the repo</li>
        <li><code>scripts/build_repo.py</code> - reproducible regeneration script</li>
      </ul>
    </section>
  </main>

  <footer class="footer wrap">
    <p>Built for Precize using official MITRE ATT&amp;CK source files and group pages.</p>
  </footer>
  <script src="assets/app.js"></script>
</body>
</html>''')

(BASE / 'assets' / 'styles.css').write_text('''
:root {
  --bg: #08101b;
  --panel: #121a2b;
  --panel-2: #162036;
  --text: #e8eefc;
  --muted: #9eb0d1;
  --accent: #70b7ff;
  --accent-2: #ff8b60;
  --border: #24304a;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: linear-gradient(180deg,#09101d,#0d1525 20%,#0b1220); color: var(--text); }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { width: min(1240px, calc(100% - 32px)); margin: 0 auto; }
.hero { padding: 56px 0 28px; border-bottom: 1px solid var(--border); background: radial-gradient(circle at top left, rgba(112,183,255,.14), transparent 35%), radial-gradient(circle at right, rgba(255,139,96,.12), transparent 25%); }
.eyebrow { color: var(--accent); font-size: 13px; text-transform: uppercase; letter-spacing: .12em; margin-bottom: 8px; }
h1 { font-size: clamp(2rem, 4vw, 3.2rem); margin: 0 0 14px; line-height: 1.05; }
.lede { max-width: 900px; color: var(--muted); font-size: 1.06rem; line-height: 1.7; }
.actions { display:flex; flex-wrap:wrap; gap:12px; margin-top: 20px; }
.button { display:inline-flex; align-items:center; padding: 12px 16px; border:1px solid var(--border); border-radius: 12px; background: rgba(255,255,255,.02); color: var(--text); }
.button.primary { background: linear-gradient(90deg, rgba(112,183,255,.2), rgba(255,139,96,.12)); }
main { padding: 28px 0 60px; }
.grid.stats { display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat, .panel, .card { background: linear-gradient(180deg, rgba(255,255,255,.02), rgba(255,255,255,.01)); border: 1px solid var(--border); border-radius: 18px; }
.stat { padding: 18px; }
.stat .label { color: var(--muted); font-size: 13px; margin-bottom: 6px; }
.stat .value { font-size: 1.9rem; font-weight: 700; }
.panel { padding: 18px; margin-bottom: 20px; }
.panel-head { margin-bottom: 14px; }
.panel-head h2 { margin: 0 0 8px; font-size: 1.35rem; }
.panel-head p { margin: 0; color: var(--muted); line-height: 1.6; }
.table-wrap { overflow:auto; border: 1px solid var(--border); border-radius: 14px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { border-bottom: 1px solid var(--border); padding: 12px 10px; text-align: left; vertical-align: top; }
th { position: sticky; top: 0; background: #0f1729; z-index: 1; }
code { background:#0d1526; border:1px solid var(--border); padding:2px 6px; border-radius:8px; }
.badge { display:inline-flex; padding: 4px 8px; border-radius: 999px; font-size: 12px; margin-right: 6px; border:1px solid var(--border); color: var(--text); background: #10192d; }
.badge.explicit { border-color: rgba(68,195,139,.4); color: #b3f0d2; }
.badge.suspected { border-color: rgba(255,139,96,.35); color: #ffd4c4; }
.badge.ok { border-color: rgba(68,195,139,.4); color: #b3f0d2; }
.card-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(270px, 1fr)); gap: 16px; }
.card { padding: 16px; }
.card h3 { margin: 0 0 8px; font-size: 1.1rem; }
.meta, .small { color: var(--muted); font-size: 13px; }
.matrix-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }
.matrix-card { border:1px solid var(--border); border-radius: 14px; padding: 14px; background: var(--panel-2); }
.matrix-card h3 { margin: 0 0 10px; text-transform: capitalize; font-size: 1rem; }
.matrix-card ul { margin: 0; padding-left: 18px; }
.matrix-card li { margin: 0 0 8px; color: var(--muted); }
.score { font-weight: 700; color: var(--text); }
.filters { display:flex; gap:12px; margin-bottom: 12px; flex-wrap: wrap; }
input, select { background:#0d1526; color: var(--text); border:1px solid var(--border); border-radius: 12px; padding: 10px 12px; }
.repo-list { color: var(--muted); line-height: 1.9; }
.footer { padding: 0 0 36px; color: var(--muted); }
@media (max-width: 700px) { .wrap { width: min(100% - 20px, 1240px); } }
''')

(BASE / 'assets' / 'app.js').write_text('''
async function load() {
  const manifest = await fetch('data/manifest.json').then(r => r.json());
  renderStats(manifest);
  renderValidation(manifest.validation);
  renderMatrix(manifest.tactic_summary);
  renderTechniques(manifest.techniques);
  renderGroups(manifest.groups);
}
function el(tag, cls, html) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (html !== undefined) node.innerHTML = html;
  return node;
}
function renderStats(manifest) {
  const stats = document.getElementById('stats');
  const peak = Math.max(...manifest.techniques.map(t => t.group_count));
  [[ 'Selected groups', manifest.selected_group_count ], [ 'Unique techniques', manifest.unique_technique_count ], [ 'Generated layers', manifest.groups.length ], [ 'Peak overlap', peak ]].forEach(([label, value]) => {
    const card = el('div', 'stat');
    card.append(el('div', 'label', label));
    card.append(el('div', 'value', String(value)));
    stats.append(card);
  });
}
function renderValidation(rows) {
  const host = document.getElementById('validationTable');
  const wrap = el('div', 'table-wrap');
  const table = el('table');
  table.innerHTML = `<thead><tr><th>Group</th><th>MITRE page</th><th>Local layer</th><th>Official layer</th><th>Techniques</th><th>Status</th></tr></thead>`;
  const tbody = el('tbody');
  rows.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><strong>${r.name}</strong><br><span class="small">${r.id}</span></td><td><a target="_blank" rel="noreferrer" href="${r.group_url}">group page</a></td><td><a href="${r.generated_layer_path}">generated JSON</a></td><td><a target="_blank" rel="noreferrer" href="${r.official_layer_url}">official pattern</a></td><td>${r.technique_count}</td><td><span class="badge ok">${r.validated ? 'validated' : 'check failed'}</span></td>`;
    tbody.append(tr);
  });
  table.append(tbody); wrap.append(table); host.append(wrap);
}
function renderMatrix(rows) {
  const host = document.getElementById('matrix');
  const grid = el('div', 'matrix-grid');
  rows.forEach(row => {
    const card = el('div', 'matrix-card');
    const items = row.top_techniques.map(t => `<li><a target="_blank" rel="noreferrer" href="${t.url}"><span class="score">${t.group_count}</span> — ${t.techniqueID} ${t.name}</a></li>`).join('');
    card.innerHTML = `<h3>${row.tactic} <span class="small">(${row.technique_count} techniques)</span></h3><ul>${items || '<li>No mapped techniques in current selection.</li>'}</ul>`;
    grid.append(card);
  });
  host.append(grid);
}
function renderTechniques(rows) {
  const tacticSelect = document.getElementById('tacticFilter');
  const search = document.getElementById('techSearch');
  const host = document.getElementById('techniquesTable');
  [...new Set(rows.flatMap(r => r.tactics))].sort().forEach(t => {
    const opt = document.createElement('option'); opt.value = t; opt.textContent = t; tacticSelect.append(opt);
  });
  function draw() {
    const q = search.value.trim().toLowerCase();
    const tactic = tacticSelect.value;
    const filtered = rows.filter(r => {
      const hay = [r.techniqueID, r.name, ...r.tactics, ...r.groups.map(g => g.name)].join(' ').toLowerCase();
      return (!q || hay.includes(q)) && (!tactic || r.tactics.includes(tactic));
    });
    host.innerHTML = '';
    const wrap = el('div', 'table-wrap');
    const table = el('table');
    table.innerHTML = '<thead><tr><th>Technique</th><th>Tactics</th><th>Groups</th><th>Platforms</th></tr></thead>';
    const tbody = el('tbody');
    filtered.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><a target="_blank" rel="noreferrer" href="${r.url}"><strong>${r.techniqueID}</strong> ${r.name}</a><br><span class="small">Used by ${r.group_count} selected groups</span></td><td>${r.tactics.map(t => `<span class="badge">${t}</span>`).join('')}</td><td>${r.groups.map(g => g.name).join(', ')}</td><td>${(r.platforms || []).join(', ')}</td>`;
      tbody.append(tr);
    });
    table.append(tbody); wrap.append(table); host.append(wrap);
  }
  search.addEventListener('input', draw); tacticSelect.addEventListener('change', draw); draw();
}
function renderGroups(groups) {
  const host = document.getElementById('groupCards');
  groups.forEach(g => {
    const card = el('article', 'card');
    card.innerHTML = `<h3><a target="_blank" rel="noreferrer" href="${g.url}">${g.name}</a></h3><div class="meta">${g.id}</div><p><span class="badge ${g.confidence}">${g.confidence}</span> ${g.rationale}</p><p class="small">${g.description}</p><p class="small">${g.technique_count} techniques • <a href="${g.layer_url}">generated layer</a> • <a target="_blank" rel="noreferrer" href="${g.official_layer_url}">official URL pattern</a></p>`;
    host.append(card);
  });
}
load();
''')

(BASE / 'README.md').write_text('''# Precize - Iran-Linked MITRE ATT&CK Enterprise Matrix

## What it contains

- `index.html` - external-facing static site
- `assets/` - site CSS and JavaScript
- `data/generated_layers/*.json` - one per-group Navigator layer generated from MITRE ATT&CK Excel mappings
- `data/iran_attack_aggregated_layer.json` - combined Navigator layer across all selected groups
- `data/manifest.json` - full machine-readable dataset used by the site
- `data/validation.json` - validation summary
- `data/enterprise-attack-v18.1-groups.xlsx` - MITRE ATT&CK source file
- `data/enterprise-attack-v18.1-techniques.xlsx` - MITRE ATT&CK source file
- `data/enterprise-attack-v18.1-tactics.xlsx` - MITRE ATT&CK source file
- `scripts/build_repo.py` - regeneration script

## Build logic

This repository uses MITRE ATT&CK Excel v18.1 files from the official ATT&CK Data & Tools page.

1. Group descriptions are taken from `groups.xlsx`.
2. Group-to-technique mappings are taken from `groups.xlsx` → `techniques used`.
3. Technique names, URLs, tactics, and platforms are taken from `techniques.xlsx`.
4. Per-group local layer files are generated in `data/generated_layers/`.
5. The combined layer in `data/iran_attack_aggregated_layer.json` scores each technique by the number of selected groups that use it.

## Selected group IDs

- G1030	**Agrius**
- G0130	**Ajax Security Team**
- G0064	**APT33**
- G0087	**APT39** 
- G1044	**APT42** 
- G0003	**Cleaver** 
- G0052	**CopyKittens** 
- G1012	**CURIUM**
- G1027	**CyberAv3ngers** 
- G0137	**Ferocious Kitten** 
- G0117	**Fox Kitten** 
- G0043	**Group5** 
- G0077	**Leafminer** 
- G0059	**Magic Hound**
- G1009	**Moses Staff**
- G0069	**MuddyWater** 
- G0049	**OilRig**
- G0122	**Silent Librarian**

## Open the combined matrix in ATT&CK Navigator

1. Go to the MITRE ATT&CK Navigator https://mitre-attack.github.io/attack-navigator/
2. Choose **Open Existing Layer**.
3. Upload `data/iran_attack_aggregated_layer.json` or point to https://github.com/precize/precize-iran-mitre-matrix/blob/main/data/iran_attack_aggregated_layer.json

## Notes

- The repository keeps the original MITRE Excel source files so external reviewers can reproduce the build.
- The per-group JSON files are generated locally from those MITRE mappings. They are intended for GitHub sharing and ATT&CK Navigator loading.
''')

print('[OK] repo rebuilt from Excel sources')
