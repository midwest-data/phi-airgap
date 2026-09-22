# Security model

## phi-airgap reduces disclosure risk; it does not create HIPAA compliance

This tool exists for one situation: an LLM coding agent needs to do real work
against a warehouse that holds regulated or otherwise sensitive data, and you
want to keep that data out of the model. It lowers the probability and the blast
radius of an accidental disclosure. **It does not make anything compliant.**

If no Business Associate Agreement covers your model provider, there is no lawful
path for PHI to reach that model, and no combination of gate, scrubber and hook
changes that. Deploy this as a harm-reduction control during an interim period,
not as a substitute for the legal and architectural work of getting a BAA'd
inference path. The k≥11 suppression plus identifier stripping *approximates*
HIPAA Safe Harbor; it is **not** an expert determination and not a
certification.

## Threat model

**What phi-airgap defends against:** an agent (or a careless prompt) that would pull
row-grain data into the transcript — by querying directly, peeking at rows,
reading a raw extract off disk, or lifting a warehouse credential to do any of
the above.

**Trust boundary:** the agent is **untrusted for data egress**. It may write
SQL, read schema, and read *aggregate, scrubbed* results. It may not execute
queries, read credentials, or read raw extracts. A human runs `phi-airgap run`.

**The three layers, and how each can fail:**

- **The gate** is deterministic and fails closed: an unclassified relation is
  RED, an unparseable statement is denied. Its blind spot is `policy.yml` — a
  GREEN carve-out you scoped too broadly is a hole *you* opened. Review the
  policy like an ACL. The gate also trusts sqlglot's parse; a dialect mismatch
  that mis-parses a statement is a risk, which is why `sql_dialect` must match
  your warehouse.
- **The scrubber** has a deterministic floor (regex for SSN/phone/email/MRN/
  tokens) that cannot miss the shapes it knows, and a statistical ceiling
  (Presidio NER) that **has false negatives by construction**. Presidio scored
  `ssn 123-45-6789` at zero in testing. A clean NER pass is not proof of
  anything. When NER *fires*, the gate already leaked — fix the policy.
- **The hook** enforces the human-runs-the-query rule at the harness level. It
  is designed to **fail open**: if the hook crashes, it exits 0 and allows the
  tool, because a broken governance hook must never wedge the agent. That means
  a hook you have disabled, misconfigured, or crashed is providing no
  protection — `phi-airgap doctor` checks that it is installed and registered.
- **`PHI_AIRGAP_BYPASS=1`** disables the hook entirely. It exists for the human to
  use deliberately; if it is set in the agent's environment, there is no hook.

**Out of scope:** phi-airgap does not defend against a malicious operator, a
compromised warehouse, side channels in aggregate statistics beyond the k-anon
threshold, or a model provider that violates its own retention terms. It does
not encrypt anything or manage access to the warehouse itself.

## Responsible disclosure

If you find a way to get row-grain data past the gate or the scrubber — a query
shape the gate allows that it should not, a scrubber false negative on a
deterministic shape, or a hook bypass — please report it privately rather than
opening a public issue. Open a [GitHub security
advisory](https://docs.github.com/en/code-security/security-advisories) on this
repository (**Security → Report a vulnerability**), or contact the maintainer
listed in the repository metadata.

When reporting, describe the *class* of the problem and a minimal reproducing
query or command. Please do not include real PHI in a report.
