# R02C human check (at most two questions)

`human_verified` remains **false** on both cards. This file does not record agent self-verification. No detection accuracy/F1/GPC/reward is computed.

Local full cards: `local_data/r02c/evaluator/review_cards/r01-pair-13.json` and `r01-pair-15.json`.

## Question 1 — r01-pair-13 (jenkinsci/favorite-plugin)

Is the following a **component requirement** of Favorite plugin’s Stapler `doToggleFavorite` action, or only a later maintainer/security reading?

> A request that toggles favorites may change only the authenticated current Jenkins user’s favorite set. The action must not accept a request parameter that names a different user and then mutate that other user’s favorites.

Git-safe signatures (no exploit steps):

- Left (`a5537f3e…`): `doToggleFavorite(..., @QueryParameter String job, @QueryParameter String userName, @QueryParameter Boolean redirect)` then `User user = jenkins.getUser(userName);`
- Right (`b6359532…`): `doToggleFavorite(..., @QueryParameter String job, @QueryParameter Boolean redirect)` then `User user = User.current();`

Context gap: `getItem` is truncated in both frozen snippets (`snippet_truncated=false` is wrong). Stapler `do*` HTTP exposure is a Jenkins platform convention; a Favorite-plugin-specific spec page for the frozen revisions was not found (`requirement_source` on the card is the platform convention plus the later commit, marked after-the-fact).

Please answer: **requirement holds / does not hold / cannot tell**, and whether the truncated `getItem` plus missing permission/CSRF text is enough to judge.

## Question 2 — r01-pair-15 (openhab/openhab-webui CometVisu mounts)

Is the following a **component requirement** of CometVisu manager mount registration, or only an inference from the loop body?

> A configured mount must not be registered when the target contains `..`, when the target is `demo`, when the source path contains `..` unless the code’s own allowLookup matcher permits it, or when the mapping value is null.

Git-safe difference: the right snapshot wraps `Config.mountPoints.get(target)` with `if (value != null)` before `split(":")`. Both snippets are a for-loop fragment, not a full method; `allowLookup` / `lookupMount` are not in the snippet.

Please answer: **requirement holds / does not hold / cannot tell**, and whether the missing enclosing method and frozen-version CometVisu config document block the judgment.
