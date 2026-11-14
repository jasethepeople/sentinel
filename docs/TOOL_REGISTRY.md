# Fixed fixture registry

Every registered tool is a deterministic, in-process example. No tool accepts arguments beyond the scope-checked target string. The target is not contacted or used to select data.

| Tool | Category | Fixture |
| --- | --- | --- |
| `simulate_asset_inventory` | recon | Synthetic example asset |
| `simulate_service_inventory` | recon | Synthetic service metadata |
| `simulate_http_headers` | scanning | Static example headers |
| `simulate_tls_posture` | scanning | Static example TLS posture |
| `simulate_dependency_advisories` | scanning | Empty sample advisory result |
| `simulate_misconfiguration` | scanning | Empty sample observations |
| `simulate_verification` | scanning | `not_performed` status |
| `simulate_cwe_context` | reporting | Generic local sample context |
| `simulate_cve_context` | reporting | Generic local sample context |
| `simulate_attack_path` | reporting | Empty sample path list |

The YAML definitions under `src/sentinel/registry/tools/` are parsed into strict Pydantic models. The registry additionally hard-codes the exact supported tool names, fixture IDs, backend type, empty parameters, categories, and non-destructive safety metadata. Editing a YAML file cannot enable a new backend or action. Unknown fixtures fail closed in `MockSandboxProvider`.

To add another harmless example fixture, change the backend allowlist/data, registry schema and YAML, user-facing documentation, and tests together. Never add a command, URL, process, arbitrary input field, or live adapter under this prototype's mock-only scope.
