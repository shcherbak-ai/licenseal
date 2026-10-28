# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in licenseal, please report it **privately** using [GitHub's private vulnerability reporting](https://github.com/shcherbak-ai/licenseal/security/advisories/new). Please avoid opening public issues for security vulnerabilities. Confirmed vulnerabilities will be addressed in a patch release.

## Security model

licenseal is a license-assessment tool, not a security primitive. It reads manifests, calls public registries (read-only), and writes only the local outputs a user asks for (a report, a `licenseal.review.toml` scaffold, or the project-local Claude review skill): no code execution, no privileged operations.

The model is described in the documentation:

- [Security model](https://licenseal.shcherbak.ai/security/): what is read, what is never done, and which files can decide a verdict
- [Network egress](https://licenseal.shcherbak.ai/security/network/): each host, what it is asked, and the rules that hold for all of them
- [License sources](https://licenseal.shcherbak.ai/security/license-sources/): where each host's answer holds the license
- [What leaves the process](https://licenseal.shcherbak.ai/security/data-sent/): what a request carries, and when a private package's name is sent to a public registry

## Network egress

Outbound network access is restricted to fourteen hosts: licenseal's HTTP client refuses a request to any other host before it opens a connection. The hosts are `pypi.org:443`, `files.pythonhosted.org:443`, `registry.npmjs.org:443`, `crates.io:443`, `api.deps.dev:443`, `proxy.golang.org:443`, `repo.maven.apache.org:443`, `dl.google.com:443`, `repo.jenkins-ci.org:443`, `api.nuget.org:443`, `repo.packagist.org:443`, `rubygems.org:443`, `hex.pm:443`, `cran.r-project.org:443`.

When a proxy is set, licenseal reaches the same fourteen hosts through it ([Proxies](https://licenseal.shcherbak.ai/security/network/#proxies)).

An application that runs licenseal under an egress policy of its own must allow these fourteen, and the proxy when one is set. The documentation's [Network egress](https://licenseal.shcherbak.ai/security/network/) page says what each is asked.
