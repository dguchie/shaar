# Sha'ar by Masora

AI agents propose patches to infrastructure software; a deterministic gate, with no model in it, decides whether to accept them.

> **Status at tag `pre-event-base`:** this repository contains only documentation of work done before the hackathon building period (Oct 27 – Nov 4, 2026). It contains no code yet.
>
> **Current status (event work in progress):** the repository now also contains event-built code:
> - a capability probe of the hosted model API, with its evidence;
> - a minimal recording CLI, `shaar.py`, that records one locally validated model reply for a synthetic task;
> - a deterministic gate, `gate/check.py`, for one bounded case: PostgreSQL's default TLS key-exchange groups, checked against OpenSSL 3.6.3 and OpenSSL 3.0.22 on one Mac. Besides its hand-written fixtures it accepts one explicit external candidate patch (`--case candidate`), whose exact bytes and SHA-256 are bound to the run's evidence.
>
> Measured gate verdicts: the unmodified PostgreSQL source is REJECT, a hand-written hybrid-first default without library-version awareness is REJECT (the server does not start with OpenSSL 3.0), and a hand-written version-aware default is ACCEPT. That ACCEPT verified hybrid post-quantum key exchange (X25519MLKEM768) for the tested configurations; authentication remains classical. The external input was exercised as `candidate-90`: a scripted, exact copy of the version-aware fixture, with 21/21 PASS and a matching technical comparison; **it was not a model proposal or repair**. **No model-proposed patch has been gated yet, and replay and artifact verification are not implemented.** See [docs/GATE_STATUS.md](docs/GATE_STATUS.md) and [docs/CLI_STATUS.md](docs/CLI_STATUS.md).

## Provenance

|  | Prior work (before Oct 27, 2026) | Built during the event (Oct 27 – Nov 4, 2026) |
|---|---|---|
| What | PostgreSQL default key-exchange finding; OpenSSL 3.0 reproduction; PostgreSQL regression and reproducible-build measurements; the shaar-lite proof of concept and its five sabotaged patches | So far: a capability probe of the hosted model API ([docs/CAPABILITY_REPORT.md](docs/CAPABILITY_REPORT.md)), a minimal recording CLI ([docs/CLI_STATUS.md](docs/CLI_STATUS.md)) and the deterministic gate for one bounded PostgreSQL case, with its measured runs ([docs/GATE_STATUS.md](docs/GATE_STATUS.md)) |
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

The event-built gate builds PostgreSQL master at commit `68af68ac691f2b57d29524a191debed9b0bdd558` against OpenSSL 3.6.3 and 3.0.22, in a work directory outside this repository ([docs/GATE_STATUS.md](docs/GATE_STATUS.md)).

## License

Apache License 2.0. See [LICENSE](LICENSE).
