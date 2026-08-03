# ADR-0001: Separate Greenfield Product Repository

**Status:** Accepted — 2026-08-03

## Context

Tyche is MIT-licensed but contains unrelated ticket/CRM functionality, insecure configuration, incomplete dependencies, no production security foundation, and a critical credential exposure.

## Decision

Create an independent SIEMBIOT repository with its own MIT license, history, CI, documentation, contracts, and dependencies. Treat Tyche commit `2609c7e…` as read-only provenance. Reimplement only generic patterns documented in the adaptation matrix; copy no source/config/history.

## Consequences

This avoids secret and provenance contamination and permits a coherent security architecture. It costs more initial foundation work. Any future source-level reuse requires a new provenance/security review and attribution decision.
