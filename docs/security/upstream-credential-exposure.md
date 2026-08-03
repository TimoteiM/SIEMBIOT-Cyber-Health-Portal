# Upstream Tyche Credential Exposure

**Classification:** Critical prerequisite / launch blocker

**Scope:** Read-only Microsoft Tyche reference checkout

**Recorded:** 2026-08-03

Tracked Tyche backend files contain database credentials or credential-bearing defaults. This document intentionally excludes every secret and exact endpoint.

Required action by the credential owner, outside the SIEMBIOT repository:

1. Identify the affected service and owners without testing the credential.
2. Revoke and rotate the credential immediately; do not wait for history cleanup.
3. Review database and identity-provider audit logs for misuse.
4. Remove hard-coded values from the current tree and use a secret manager.
5. Rewrite affected Git history only under repository-owner coordination; notify downstream clone/fork owners.
6. Add secret scanning and push protection.
7. Record incident disposition without placing secret values in tickets or chat.

SIEMBIOT contributors are not authorized to modify the Tyche repository, validate the credential, access the database, or perform history rewriting. Launch approval requires written confirmation of rotation or a documented risk acceptance by the accountable owner; risk acceptance cannot make an active credential safe.
