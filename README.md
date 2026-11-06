# oaslint-mcp

**Ask your AI agent "is this API change safe to release?" and get a real answer.**

<!-- mcp-name: io.github.0xmortuex/oaslint-mcp -->

oaslint-mcp is an [MCP](https://modelcontextprotocol.io) server that lints OpenAPI and
Swagger specs and, above all, **detects breaking changes between two versions of a spec**.
It runs offline, reads files only, and never fetches a URL.

## Why another OpenAPI diff tool?

Other MCP servers already diff OpenAPI specs (for example
[Specwise](https://github.com/Bytestay/specwise-mcp), which needs OpenAPI 3.x for diffs, or the
hosted Apify actors). What this one does differently:

- **One engine for Swagger 2.0, OpenAPI 3.0 and 3.1, including across versions.** A 2.0 spec and
  its 3.1 rewrite show *no changes* (`nullable: true` equals `type: [x, "null"]`, `const` equals
  a one-value enum, `consumes`/`produces` equal `content`, csv arrays equal `explode: false`).
- **Request/response variance.** The same edit is breaking in a request and harmless in a
  response (and the reverse): removing an enum value, adding a property, loosening a limit. Each
  finding says which question it answered.
- **Flattened before compared.** `allOf` is merged, `$ref` and inline are the same thing,
  reordered keys and renamed components do not show up.
- **Honest about uncertainty.** `oneOf`/`anyOf`/`discriminator` changes and enum values added to
  a *response* are reported as POTENTIALLY_BREAKING with the reason, not guessed.
- **Lints and validates too**, with a JSON pointer *and the source line* on every finding.
- **Local and sandboxed**: nothing leaves your machine; file access is limited to `--dir`.

## Tools

| Tool | What it does |
|---|---|
| `spec_overview` | Version read, title, servers, tags, paths/operations, auth schemes, schemas, deprecations, unresolved `$ref`s |
| `lint_spec` | Rules OAS1001-OAS1025 with severity, JSON pointer, line and a fix |
| `diff_specs` | **Old vs new**: BREAKING / POTENTIALLY_BREAKING / NON_BREAKING / INFO, with reason and exact location |
| `changelog_markdown` | The same diff as release notes in markdown, as text |
| `find_endpoints` | Filter operations by path glob, method, tag or text |
| `describe_operation` | Parameters, request and response schemas resolved into a compact outline (cycles marked) |
| `validate_example` | Check a JSON document against an operation's request or response schema, with JSON pointers to each violation |

`spec`, `old` and `new` are paths to `.yaml`/`.yml`/`.json` files inside the allowed directory
(relative paths work), or the spec text pasted inline.

### What counts as breaking

In a **request** the server validates input, so tightening breaks clients: a new required
parameter or property, a narrower type, removed enum values, a new `pattern`, a higher `minimum`,
`additionalProperties: false`, a removed content type, stricter auth or extra scopes.
In a **response** clients rely on output, so loosening or dropping a guarantee breaks them: a
removed property, required to optional, a changed type, `nullable` added, a removed success code
or content type. Enum values *added* to a response are POTENTIALLY_BREAKING (strict clients).
`operationId` changes are non-breaking but called out.

## Install

Needs [uv](https://docs.astral.sh/uv/). Replace the folder with the one that holds your specs.

**Claude Code**

```
claude mcp add oaslint -- uvx oaslint-mcp --dir "/path/to/your/specs"
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "oaslint": {
      "command": "uvx",
      "args": ["oaslint-mcp", "--dir", "C:\\path\\to\\your\\specs"]
    }
  }
}
```

`--dir` (or the `OASLINT_DIR` environment variable) defaults to the current directory.

## Try asking

- "Give me an overview of `openapi.yaml`."
- "Lint `openapi.yaml` and fix the errors first."
- "Compare `api-v1.yaml` with `api-v2.yaml`. Is it safe to release? List every breaking change."
- "Write the changelog for v2 as markdown."
- "Which endpoints are tagged `orders` and still use POST?"
- "Describe `PATCH /orders/{id}`, including what a 409 returns."
- "Is `{"name": "x", "qty": "3"}` a valid request body for `POST /orders`?"

## Security

- **Read-only and offline.** The server never writes files and never opens a network connection.
  Remote `$ref`s (`http://`, `https://`) are reported as unresolved with a note, never fetched.
- **Sandboxed.** Every file, including relative `$ref` targets, must resolve (symlinks followed)
  to a path inside `--dir`. `../` traversal, absolute paths and symlink escapes are refused.
- **Hostile input guards.** 50 MB file cap, line cap, nesting-depth cap, YAML alias-bomb
  (billion laughs) cap, `yaml.safe_load` semantics only (no Python tags), duplicate keys warned
  about, catastrophic-backtracking `pattern`s skipped with a note.
- **No secrets in output.** Values that look like secrets (API keys, JWTs, long tokens, values
  under keys such as `password`, URL credentials) are shown as `<redacted>`; names are kept.

Limits to know about: JSON Schema `pattern` is evaluated with Python's regex engine (ECMA-262
differences are possible), `not` / `if` / `patternProperties` / `prefixItems` are compared as
opaque text and reported as POTENTIALLY_BREAKING when they change, and line numbers are
best-effort (the nearest existing node when a pointer goes through `allOf` or a `$ref`).

## Development

```
uv sync --extra test
uv run pytest
uv run ruff check src tests
uv run mypy --strict src
```

Learn how it works by building a small version yourself:
[oaslint-mcp-the-hard-way](https://github.com/0xmortuex/oaslint-mcp-the-hard-way).

MIT licensed.
