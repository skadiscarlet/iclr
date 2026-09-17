# R02B local-asset handoff

- Collection / experiment SHA: `59301b66c98cdb960bc35550939d0c0fcecbefd7`
- Catalog: 300 records, complete profile via `tools/r02b_catalog_probe.py --allow-data-root-symlink`
- New actor root: `local_data/r02b/` (gitignored); 8 version-bound instances, 4 complete pairs
- Frozen runs: `artifacts/r02b/runs/2026-09-17T141202+0000` (primary) and `...T142041+0000` (repeat)
- Model weights remain in the local Hugging Face hub snapshot `2e1fd397ee46e1388853d2af2c993145b0f1098a`
- Execute-only launchers: excluded_nonblocking
- Stable overview: `reports/LOCAL_ASSETS.md`
- R02A snapshot not overwritten: `reports/rounds/R02/LOCAL_ASSET_HANDOFF.md`
