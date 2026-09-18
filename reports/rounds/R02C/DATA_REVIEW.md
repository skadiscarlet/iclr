# R02C data review (four registered pairs, eight instances)

`gold_assisted_context=true`. `task_scope=given_location_frozen_evidence`. All eight remain `split=dev_pilot`. Materials were compared to the pinned git blobs; R02B actor files were not overwritten.

## Pair cards

### r01-pair-01 — pgjdbc / `SimpleParameterList.quoteAndCast` (conventional)

- Component: PostgreSQL JDBC driver, v3 parameter list, SQL literal quoting/cast helper.
- Revisions: `93b0fcb2711d9c1e3a2a03134369738a02a58b40` (inst-6bf462ca01bb071f) and `06abfb78a627277a580d4df825f210e96a4e14ee` (inst-b750a376e1e3c54c).
- File: `pgjdbc/src/main/java/org/postgresql/core/v3/SimpleParameterList.java` lines 212–233 both sides.
- Material: complete method `quoteAndCast`. Exact blob slice match. `snippet_truncated=false`. Continuous original span. Initial snippet has method body (escape/cast), not imports-only.
- Why reviewable: the helper is the unit that turns a Java string plus optional type name into a quoted SQL literal.
- Missing: surrounding call sites and PostgreSQL `standard_conforming_strings` policy text.

### r01-pair-12 — Apache CXF / `WadlGenerator.doFilter` (conventional)

- Component: CXF JAX-RS WADL generator filter.
- Revisions: `7ae4b00d0b2750fc3fca43fabcc1d0f5a11f0541` (inst-614b3612f0e5db8a, 233–299) and `378afe1acb7503315bc63555c8743db0f55d8312` (inst-3300fc1a03e22857, 233–307).
- File: `rt/rs/description/src/main/java/org/apache/cxf/jaxrs/model/wadl/WadlGenerator.java`.
- Material: complete `doFilter` method both sides. Exact blob slice match. Continuous. Has request-method and WADL query behaviour, not a class header only.
- Why reviewable: the method decides whether a GET WADL/doc request is answered or ignored.
- Missing: `WADL_QUERY`, stylesheet/doc maps, and JAX-RS security constraints declared outside this method.

### r01-pair-13 — jenkinsci/favorite-plugin / `FavoritePlugin.doToggleFavorite` (logic draft)

- Component: Jenkins Favorite plugin Stapler endpoint on `FavoritePlugin`.
- Revisions: `a5537f3e0da6594a474df2325ca89acbcb704425` (inst-cb80f8fe5eb55013, 1–69 of 78) and `b6359532fe085d9ea6b7894e997e797806480777` (inst-ebf077b5bfcdcc88, 1–62 of 71).
- File: `src/main/java/hudson/plugins/favorite/FavoritePlugin.java`.
- Material: exact consecutive prefix of the original file. **Not a complete enclosing unit**: `getItem` is cut at `if (jenkins == null) {`. `snippet_truncated=false` is therefore misleading (the extractor stopped early; this is not `truncated_middle` splicing). Package/imports plus `doToggleFavorite` are present and have behaviour.
- Why reviewable: left snapshot accepts `@QueryParameter String userName` and loads `jenkins.getUser(userName)` before `Favorites.toggleFavorite`; right snapshot drops `userName` and uses `User.current()`.
- Missing: remainder of `getItem`, permission checks (`Item.READ` / CSRF), and a plugin-specific written spec. See logic card.

### r01-pair-15 — openhab/openhab-webui / CometVisu `ManagerSettings` mount loop (logic draft)

- Component: openHAB CometVisu UI manager settings, mount-point registration loop.
- Revisions: `091d0edc06862bb40a70d74a2d607d1366ce134d` (inst-ba9671eef76541a9, 109–124 of 202) and `630e8525835c698cf58856aa43782d92b18087f2` (inst-90a9632ec46227d5, 109–126 of 204).
- File: `bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/ManagerSettings.java`.
- Material: exact consecutive for-loop fragment. **Not a complete method**; `allowLookup`, `lookupMount`, and `mounts` are referenced but not defined in the snippet. `snippet_truncated=false` again overstates completeness. Right side adds a `value != null` guard.
- Why reviewable: the loop is the code that accepts or rejects a configured filesystem mount.
- Missing: enclosing method, default `allowLookup`, and the CometVisu manager configuration document for the frozen versions.

## Eight-instance continuity table

| instance | pair | exact original slice | continuous span | complete enclosing unit | notes |
|---|---|---|---|---|---|
| inst-6bf462ca01bb071f | 01 | yes | yes | yes (method) | quoteAndCast |
| inst-b750a376e1e3c54c | 01 | yes | yes | yes (method) | @Nullable type |
| inst-614b3612f0e5db8a | 12 | yes | yes | yes (method) | doFilter 67 lines |
| inst-3300fc1a03e22857 | 12 | yes | yes | yes (method) | doFilter 75 lines |
| inst-cb80f8fe5eb55013 | 13 | yes | yes (file prefix) | **no** | getItem truncated; flag false |
| inst-ebf077b5bfcdcc88 | 13 | yes | yes (file prefix) | **no** | getItem truncated; flag false |
| inst-ba9671eef76541a9 | 15 | yes | yes | **no** (for-loop) | method context missing |
| inst-90a9632ec46227d5 | 15 | yes | yes | **no** (for-loop) | null-check added |

No `truncated_middle` markers. Different body hashes across a pair are **not** treated as a semantic-ready test.

## Logic requirement status (not `obligation_generic=True`)

| pair | requirement_status | human_verified | context_complete |
|---|---|---|---|
| r01-pair-13 | concrete_unreviewed | false | no |
| r01-pair-15 | concrete_unreviewed | false | no |

Full cards: `local_data/r02c/evaluator/review_cards/`. Git-safe excerpts are in `HUMAN_CHECK.md` (signatures and null-check only).

## Homology (limited)

- `repository_group_count` = 24 unique `project_family` strings in `metadata/r01_candidates.jsonl`.
- Unique GitHub-style org prefixes = 15 (`apache` 6, `jenkinsci` 5, others 1).
- `independent_group_count` = **null** (string-distinct families are not independently verified projects; forks/backports not resolved).
- This does not block the pair-01 interface pilot.

`remote_content_review=partial`. `raw_content_not_remotely_reviewed` for third-party bodies.
