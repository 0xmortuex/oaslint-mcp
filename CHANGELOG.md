# Changelog

## 0.1.0

First release.

- Reads OpenAPI 3.0.x, 3.1.x and Swagger 2.0 (JSON or YAML) and says which one it read.
- `$ref` resolution: local `#/...` pointers with cycle detection, relative file refs
  inside the `--dir` sandbox (traversal and symlink escapes blocked), remote refs
  reported as unresolved and never fetched.
- Seven tools: `spec_overview`, `lint_spec` (rules OAS1001-OAS1025), `diff_specs`,
  `changelog_markdown`, `find_endpoints`, `describe_operation`, `validate_example`.
- `diff_specs` classifies every change as BREAKING, POTENTIALLY_BREAKING, NON_BREAKING
  or INFO using request/response variance, after flattening `allOf` and normalising
  `nullable` / `type: [x, "null"]`, `const`, exclusive bounds and Swagger 2.0 bodies.
- Guards: 50 MB file cap, line cap, nesting-depth cap, YAML alias-bomb cap, safe YAML
  tags only, duplicate-key warnings, secret-looking values redacted from output.
