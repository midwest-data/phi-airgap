# Publish checklist

This repo was built and tested locally. Publishing is **yours** — nothing here
was pushed. Run these steps when you are ready.

## 1. Re-run the leak scan (must be zero hits)

Org/vendor proper nouns must not appear anywhere. This is the gate that decides
whether it is safe to publish:

```bash
cd ~/Desktop/phi-airgap
grep -rIiE 'percepta|summa|hatco|caboodle|clarity|midas|costflex|platinum|performance_management|oe_?u[0-9_]|oeu_|scorecard|shdata|gswaminathan|azuredatabricks|adb-[0-9]|ed3038|d69c97|dapi[0-9a-f]|barberton|wadsworth|akron|press.?ganey|hcahps|cms_2[0-9]|cardiovascular|neuroscience|ohsum|ohshmg|9930[0-9]|9940[0-9]|lpanda|lcurry|dawson|anderson' \
  --exclude-dir=.venv --exclude-dir=.git --exclude-dir=__pycache__ --exclude=PUBLISH.md .
```

**Zero hits.** `grep` exits 1 when it finds nothing — that is the pass. Any
printed line is a leak; fix it before continuing. (`PUBLISH.md` is excluded
because it *contains* the scan pattern — that is the search list, not a leak.)

> Do **not** add the generic HIPAA identifier tokens (`mrn`, `csn`, `dob`,
> `ssn`, `durable_key`, `_nk`, `*name*`) to that scan. Those legitimately ship
> in `policy.example.yml`'s denylist and in `scrub.py`'s regex — the tool is
> *supposed* to contain the identifier vocabulary. The scan hunts org/vendor
> proper nouns, not the identifier vocabulary.

## 2. Confirm the tests are green

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[ner,databricks]'
.venv/bin/phi-airgap selftest        # expect: N/N cases pass — AIRGAP OK
```

## 3. Verify the name is available before you commit to it

Check that `phi-airgap` is free on the registries you plan to release to (this repo
does not publish to either — v1 is source-only):

- PyPI: <https://pypi.org/project/phi-airgap/>
- Homebrew: `brew search phi-airgap`

If taken, pick a dist name now and update `pyproject.toml` `name`,
`[project.scripts]`, `[tool.hatch.build.targets.wheel]`, and the `pip install`
lines in `README.md`. (The import package and CLI can stay `phi-airgap` even if the
dist name differs, but keeping them aligned is cleaner.)

## 4. Init, commit, create the repo

```bash
cd ~/Desktop/phi-airgap
git init
git add -A
git commit -m "phi-airgap: PHI-airgap query broker (gate + scrubber + hook)"

# Private first — flip to public after your own review.
gh repo create phi-airgap --private --source=. --push
```

Review the pushed tree once more on GitHub (especially that `.venv/` and
`.phi-airgap/` were ignored, per `.gitignore`), then make it public when satisfied:

```bash
gh repo edit --visibility public
```

## Out of scope for v1

- Snowflake / BigQuery / Postgres adapters (the seam is documented in
  `src/phi_airgap/adapters/__init__.py`; add on demand).
- Publishing to PyPI / a Homebrew formula.
- Porting the hook to non-Claude-Code harnesses.
