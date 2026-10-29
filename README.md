# Sha'ar by Masora

AI agents propose patches to infrastructure software; a deterministic gate, with no model in it, decides whether to accept them.

> **Status at tag `pre-event-base`:** this repository contains only documentation of work done before the hackathon building period (Oct 27 – Nov 4, 2026). It contains no code yet.
>
> **Current status (event work in progress):** the repository now also contains event-built code: a capability probe of the hosted model API with its evidence, and a minimal recording CLI, `shaar.py`, that records one locally validated model reply for a synthetic task. **The deterministic gate, replay and artifact verification are not implemented yet.** No verdict has been produced. See [docs/CLI_STATUS.md](docs/CLI_STATUS.md).

## Provenance

|  | Prior work (before Oct 27, 2026) | Built during the event (Oct 27 – Nov 4, 2026) |
|---|---|---|
| What | PostgreSQL default key-exchange finding; OpenSSL 3.0 reproduction; PostgreSQL regression and reproducible-build measurements; the shaar-lite proof of concept and its five sabotaged patches | So far: a capability probe of the hosted model API ([docs/CAPABILITY_REPORT.md](docs/CAPABILITY_REPORT.md)) and a minimal recording CLI ([docs/CLI_STATUS.md](docs/CLI_STATUS.md)). The gate is not built yet |
| Where | Described in [docs/PRIOR_WORK.md](docs/PRIOR_WORK.md). The proof of concept is a separate repository: [dguchie/shaar-lite](https://github.com/dguchie/shaar-lite) | This repository, in commits after the tag `pre-event-base` |
| Code in this repository | None. No code, files or Git history from shaar-lite are imported | Everything committed after `pre-event-base` |

The tag `pre-event-base` is on the first commit of this repository. It marks the logical boundary between prior work and event work; it is not an earlier timestamp. The commit and tag dates recorded by Git are the real dates on which they were made. Event changes: [pre-event-base...main](https://github.com/dguchie/shaar/compare/pre-event-base...main).

[EVENT_SCOPE.md](EVENT_SCOPE.md) classifies every file in the repository as prior-work documentation or event work.

## Third-party software

The work described here uses the projects below. None of their source code or binaries is included in this repository.

| Project | License | Versions used in prior work |
|---|---|---|
| [PostgreSQL](https://www.postgresql.org/) | PostgreSQL License | master (20devel), built from source |
| [OpenSSL](https://www.openssl.org/) | Apache License 2.0 | 3.6.3, 3.5.9, 3.0.22 (built from source), 3.0.13 |

## License

Apache License 2.0. See [LICENSE](LICENSE).
