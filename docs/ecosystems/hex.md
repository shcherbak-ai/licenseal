---
title: "Elixir and Erlang"
description: "Elixir and Erlang: the files licenseal reads, what counts as a dev dependency, and what is off-registry."
---

# Elixir and Erlang

What licenseal reads in a Mix, rebar, or erlang.mk project. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** Hex (`hex.pm`)
- **Manifests:** `mix.exs`, `rebar.config`, erlang.mk `Makefile`
- **Lockfiles:** `mix.lock`, `rebar.lock`

## Dev dependencies

These count as dev dependencies:

- a `mix.exs` dependency whose `only:` does not include `:prod`;
- the dependencies of the rebar `test` and `dev` profiles;
- erlang.mk `TEST_DEPS`, `BUILD_DEPS`, `DOC_DEPS`, and `SHELL_DEPS`.

## Off-registry dependencies

These are reported as [off-registry dependencies](../concepts/off-registry.md):

- a `mix.lock` entry that is not a `:hex` tuple;
- `git:` / `github:` / `path:` in `mix.exs`;
- a source tuple other than `{pkg, …}` in `rebar.config` and `rebar.lock`;
- an erlang.mk dependency fetched by a method other than `hex`.

Umbrella apps are the project's own code.

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [Estimates](../concepts/version-resolution.md#estimates), for the license of a release other than the one published last
- [Failed lookups and rate limits](../concepts/version-resolution.md#failed-lookups-and-rate-limits), for hex.pm's rate limit in a project with more than 100 packages
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
