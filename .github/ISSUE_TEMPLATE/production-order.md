---
name: Production order
about: A work order for the dark factory — an agent picks this up, converges against the test suite, and ships.
title: ''
labels: production-order
assignees: ''
---

## Goal

<!-- One paragraph: what should exist when this is done. -->

## Acceptance criteria

<!-- Checkable statements. The agent treats these as the definition of done. -->

- [ ]
- [ ]

## Test requirements

<!-- What tests must exist/pass beyond `make test` staying green.
     New behavior needs new assertions; bug fixes need a test that
     would have caught the bug. -->

## Autonomy level

<!-- Per docs/dark-factory.md §4:
     "decides"          — agent ships without escalation
     "decides-and-flags" — agent ships, flags the judgment calls
     "stops-and-asks"    — agent plans, then waits for the human -->

decides-and-flags

## Out of scope

<!-- Anything the agent must NOT touch while doing this. -->
