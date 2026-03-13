# Precize - Iran-Linked MITRE ATT&CK Enterprise Matrix

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

G1030, G0130, G0064, G0087, G1044, G0003, G0052, G1012, G1027, G0137, G0117, G0043, G0077, G0059, G1009, G0069, G0049, G0122


## Open the combined matrix in ATT&CK Navigator

1. Go to the MITRE ATT&CK Navigator https://mitre-attack.github.io/attack-navigator/
2. Choose **Open Existing Layer**.
3. Upload `data/iran_attack_aggregated_layer.json`.

## Notes

- The repository keeps the original MITRE Excel source files so external reviewers can reproduce the build.
- The per-group JSON files are generated locally from those MITRE mappings. They are intended for GitHub sharing and ATT&CK Navigator loading.
