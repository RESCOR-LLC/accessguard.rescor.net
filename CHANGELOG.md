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

### Phase 3: Output Improvements

#### Report generator (`reportGenerator.py`)
- Self-contained HTML report with summary cards, entity tables, exact duplicates, subset relationships, and AI recommendations with risk ratings
- JSON output for machine-readable pipeline integration
- CSV output preserved for backward compatibility via existing OutputBroker

### Phase 4: CLI Modernization

#### New command-line flags
- `--model` / `-m`: AI model selection (opus, sonnet, haiku, or full model ID; default: sonnet)
- `--threshold` / `-t`: Jaccard similarity threshold (0.0-1.0; default: 0.70)
- `--no-ai`: Deterministic analysis only, no API calls required
- `--format` / `-f`: Local report format (html, json, csv, all; default: html)

#### Integration
- `processAccounts()` now runs RoleAnalyzer after existing similarity detection
- HTML/JSON reports written to local output directories alongside existing CSV files
- AI model initialization gracefully falls back if ANTHROPIC_API_KEY is not set

### Phase 1: Code Cleanup and Foundation

#### Inline policy comparison
- Added third similarity dimension to `SimilarEntities`: inline policy content
- Policies are canonicalized (sorted keys, policy names stripped) before comparison
- Two entities with identical inline policy documents but different policy names are now detected as similar

#### Field normalization
- Renamed `ugr` field to `entityType` throughout `accessGuardClasses.py` and `accessGuard.py` — the old name (User/Group/Role abbreviation) was opaque
- Cleaned up imports: removed commented-out imports, sorted alphabetically, separated stdlib from third-party
