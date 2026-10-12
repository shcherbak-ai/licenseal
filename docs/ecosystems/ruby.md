---
title: "Ruby"
description: "Ruby: the files licenseal reads, what counts as a dev dependency, and what is off-registry."
---

# Ruby

What licenseal reads in a Bundler project. The rules that hold for every ecosystem are under [How a scan works](../concepts/index.md).

- **Registry:** RubyGems and [deps.dev](../security/license-sources.md)
- **Manifests:** `Gemfile`, `*.gemspec`
- **Lockfiles:** `Gemfile.lock`

## Dev dependencies

- A `Gemfile` gem is a dev dependency only when every group it belongs to is `:development` or `:test`; a gem in any other group, in a mixed list, or in no group is production, and so is one whose group name is not written as a literal.
- A gemspec `add_development_dependency` is a dev dependency.

## Off-registry dependencies

These are reported as [off-registry dependencies](../concepts/off-registry.md):

- `GIT`, `PATH`, and `PLUGIN SOURCE` specs in `Gemfile.lock`;
- a `Gemfile` gem declared with a `git` / `github` / `gist` / `bitbucket` / `path` option or block.

## See also

- [Dependency resolution](../concepts/dependency-resolution.md) and [Versions and estimates](../concepts/version-resolution.md), which apply to every ecosystem
- [Alternate registries](../concepts/off-registry.md#alternate-registries), for a gem in a `Gemfile` `source` block
- [License lists](../concepts/license-expressions.md#license-lists), for a gem that declares several licenses
- [Network egress](../security/network.md), for the hosts contacted and what each is asked
