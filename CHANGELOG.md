# AccessGuard Changelog

## Modernization (2026-04-03 — in progress)

### Phase 1: Code Cleanup and Foundation

#### Dead code removal
- Removed `access-guard.py` — deprecated Excel/xlwings interface, incomplete Lambda handler
- Removed `package.json` and `package-lock.json` — unused JavaScript dependencies (graphql-tools, promise-toolbox)
- Removed `README (1).md` — duplicate README
- Removed `accessGuard-account-configuration-2.csv` — duplicate sample config

#### New files
- `requirements.txt` — Python dependency manifest
- `CHANGELOG.md` — this file

### Phase 2: AI-Powered Role Analysis

#### Abstract model provider (`modelProvider.py`)
- `ModelProvider` — abstract base class for LLM integrations; subclass to add any vendor
- `AnthropicProvider` — concrete implementation for Claude models (Opus, Sonnet, Haiku)
- Model aliases: `opus`, `sonnet`, `haiku` resolve to current model IDs
- API key via `ANTHROPIC_API_KEY` environment variable
- JSON code fence stripping for reliable structured output

#### Role analyzer (`roleAnalyzer.py`)
- **Stage 1 (deterministic):** Jaccard similarity clustering on managed policy sets
  - Single-linkage clustering at configurable threshold (default 70%)
  - Subset detection: finds roles whose policies are strict subsets of another role
- **Stage 2 (AI-powered):** Per-cluster consolidation recommendations via LLM
  - Structured JSON prompt with risk rating schema (LOW/MEDIUM/HIGH)
  - Risk based on whether added permissions are read-only, write, or sensitive-service write
  - Model is user-selectable; default Sonnet for cost/speed balance
  - Graceful fallback: `--no-ai` runs deterministic analysis only

### Phase 1: Code Cleanup and Foundation

#### Inline policy comparison
- Added third similarity dimension to `SimilarEntities`: inline policy content
- Policies are canonicalized (sorted keys, policy names stripped) before comparison
- Two entities with identical inline policy documents but different policy names are now detected as similar

#### Field normalization
- Renamed `ugr` field to `entityType` throughout `accessGuardClasses.py` and `accessGuard.py` — the old name (User/Group/Role abbreviation) was opaque
- Cleaned up imports: removed commented-out imports, sorted alphabetically, separated stdlib from third-party
