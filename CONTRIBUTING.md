# Contributing to Skyforge Server

Thanks for taking the time to contribute.

This repository is the Encore/Go backend component of Skyforge OSS. For the meta repo (submodules, bootstrap, and cross-component docs), see `forwardnetworks/skyforge`.

## Code of Conduct
By participating, you agree to the Code of Conduct in `CODE_OF_CONDUCT.md`.

## Quick start
- Run tests: `encore test ./...`
- Run locally: `ENCORE_DISABLE_UPDATE_CHECK=1 encore run`

## Secrets
Do not commit secrets (`*.env`, kubeconfigs, `*-secrets.yaml`, credentials).

## PRs
- Keep PRs small and scoped.
- Update docs when behavior changes.
