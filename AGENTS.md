# sloth — agent instructions (pointer)

The canonical, cross-tool agent instructions have moved to **`agents/AGENTS.md`**
and are **git-crypt encrypted** to prevent third-party contamination of the
files that govern agent behavior.

- Trusted local agents (with the git-crypt key unlocked) read `agents/AGENTS.md`
  as normal plaintext.
- Third parties (GitHub viewers, forks, PR authors) see only ciphertext and
  cannot read or tamper with the real instructions.

If `agents/AGENTS.md` is ciphertext on your machine, run `git-crypt unlock` with
the project key before relying on any instruction file. The build/infra runbook
is `agents/FACTORY.md`; the pattern + autonomy contract is
`agents/dark-factory.md`; the product charter and sacred invariants remain in
the root `MISSION.md`.
