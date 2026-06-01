<!--
Reviewer's verification checklist. Fill out each box before merging.
Reasoning: today's pattern across the family was shipping fixes that
surfaced new issues the moment a user touched the change. Slow-down
at merge time prevents the next round.
-->

## Summary

<!-- 1-3 sentences describing the change and its motivation. -->

## What changed (probe behavior)

<!-- New probe? Probe verdict logic changed? Output format changed? -->

## Verification

- [ ] Unit tests pass (`python -m unittest discover -s . -p "test_*.py"`).
- [ ] Integration tests pass (`python -m unittest integration_test`).
- [ ] If a new probe was added: ran it live against `wdgwars.pl` at least once and recorded the actual verdict (paste below).
- [ ] If verdict logic changed: live-probe run with the new logic AND with the prior logic still produces the same verdict on a healthy API.
- [ ] CHANGELOG.md has an entry.
- [ ] `__version__` is bumped if probe behavior changed.
- [ ] No `Co-Authored-By: Claude` trailer in any commit.
- [ ] No `zhn*` hostnames, real names, or lab-internal references in code/commits.
- [ ] No probe added that is state-mutating (auth/login, bounty accept, etc.) — read-only probes only.

## Live-probe verdict (if applicable)

<!-- Paste the actual output of running this branch against wdgwars.pl. -->

## Notes for reviewer

<!-- Anything that needs context. -->
