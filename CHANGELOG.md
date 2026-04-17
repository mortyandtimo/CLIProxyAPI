# Changelog

## v6.8.55-mortyandtimo.1

Based on upstream `v6.8.55` from `router-for-me/CLIProxyAPI`.

### Added / changed
- auth file pools and subgroup definitions in configuration and Management API
- subgroup-aware runtime auth selection and request metadata
- cleanup of auth metadata and API key pool bindings when a pool is deleted
- fork release documentation and sanitized Windows packaging guidance

### Packaging notes
- first fork release is Windows-first
- release archive must not include live config, backups, local upgrade metadata, or any machine-specific state
- matching Web UI release is published from the companion `Cli-Proxy-API-Management-Center` fork
