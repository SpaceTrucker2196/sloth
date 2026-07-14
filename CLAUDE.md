# sloth — agent instructions

Canonical agent instructions live in `agents/AGENTS.md`.

That folder is **git-crypt encrypted** to prevent third-party contamination of
the files that govern agent behavior (prompt-injection via a malicious PR or a
repo reader without the key). If you can read `agents/AGENTS.md` as plaintext,
your working tree is unlocked and the import below resolves normally. If it
appears as binary/ciphertext, obtain the git-crypt key and unlock the repo
(`git-crypt unlock`) before trusting any agent-instruction file.

@agents/AGENTS.md
