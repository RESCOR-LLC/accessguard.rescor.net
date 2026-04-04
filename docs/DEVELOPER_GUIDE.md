# AccessGuard Developer Guide

## Extending AccessGuard

AccessGuard is designed for extensibility at two integration points:

1. **Cloud Providers** — add support for new identity platforms (cloud or on-premise)
2. **Model Providers** — add support for new LLM vendors

Both follow the same pattern: subclass an abstract base class, implement the required methods, and register the implementation. No modification to core AccessGuard code is required.

---

## Adding a Cloud Provider

### 1. Subclass `CloudProvider`

Create a new file in `src/providers/` (e.g., `src/providers/mycloud.py`):

```python
from providers.base import CloudProvider, EntityRecord

class MyCloudProvider(CloudProvider):

    def __init__(self, region: str = "default", **kwargs):
        # Initialize credentials, clients, etc.
        self._current_account = "..."

    @property
    def name(self) -> str:
        return "mycloud"

    def discover_accounts(self) -> list:
        # Return [{"id": "account-id", "name": "display name"}, ...]
        # This is called when the user passes --org
        ...

    def get_identity_client(self, account_id: str, role: str = None):
        # Return an authenticated client object (any type — it's passed
        # back to scan_entities). Return None if the account is unreachable.
        ...

    def scan_entities(self, client, account_id: str,
                      report_date: str) -> list:
        # Scan the account and return a list of EntityRecord objects.
        # Must handle partial failures gracefully.
        ...

    def system_prompt_context(self) -> str:
        # Return platform-specific rules for the AI analysis prompt.
        # This is appended to the generic preamble.
        ...
```

### 2. Produce `EntityRecord` Objects

Every provider must map its platform-specific entities into `EntityRecord`:

```python
from providers.base import EntityRecord

record = EntityRecord(
    name="alice",                          # display name
    account="account-123",                 # account/subscription/project ID
    entity_type="User",                    # User, Group, Role, ServiceAccount, etc.
    platform="mycloud",                    # your provider name
    identifier="mycloud:account-123:user/alice",  # unique platform identifier
    managed_policies=["ReadOnly", "Admin"],        # role/policy names
    inline_policies={"custom": {"...": "..."}},    # embedded policy documents
    members=["bob", "charlie"],            # group membership (if applicable)
    trust_info={"assumable_by": "..."},    # who can assume/impersonate
    tags={"env": "prod"},                  # ownership metadata
    last_used="2026-01-15T10:30:00",       # ISO datetime or None
    create_date="2025-06-01T00:00:00",     # ISO datetime or None
    metadata={"custom_field": "value"},    # platform-specific extras
    report_date=report_date,               # passed in from caller
)
```

**Key fields for the analysis pipeline:**

| Field | Used By | Purpose |
|-------|---------|---------|
| `managed_policies` | SimilarEntities, RoleAnalyzer | Jaccard similarity, clustering, subset detection |
| `inline_policies` | SimilarEntities | Canonicalized content comparison |
| `members` | SimilarEntities | Group membership similarity |
| `trust_info` | AI prompt | Who can assume this identity |
| `tags` | AI prompt | Ownership, stack/automation association |
| `last_used` | AI prompt | Deletion vs. consolidation recommendation |
| `identifier` | Report, deduplication | Unique ID for display and linking |
| `platform` | Report | Multi-provider column |

### 3. Register the Provider

Add auto-registration to `src/providers/__init__.py`:

```python
try:
    from providers.mycloud import MyCloudProvider
    register("mycloud", MyCloudProvider)
except ImportError:
    pass  # mycloud SDK not installed
```

The provider is now available via `--provider mycloud`.

### 4. Write Tests

Create `tests/test_mycloud_provider.py`. At minimum, test:

- Account discovery returns correct format
- Entity scanning produces valid `EntityRecord` objects
- Graceful failure handling (API errors don't crash)
- `EntityRecord` compatibility with `SimilarEntities` and `RoleAnalyzer`
- Prompt context contains platform-specific rules

Mock the cloud SDK — don't require real credentials for unit tests.

### 5. Prompt Context Guidelines

The `system_prompt_context()` return value is appended to the generic AI preamble. It should:

- Explain the platform's IAM model (principal-centric vs resource-centric)
- Define what `managed_policies` represents on this platform
- Explain `trust_info` semantics (who can assume, impersonate, delegate)
- List critical findings specific to this platform
- List entity types that must NOT be consolidated (system-managed, etc.)
- Define risk indicators (e.g., "user-managed keys" on GCP, "password credentials" on Azure)

---

## Adding a Model Provider

### 1. Subclass `ModelProvider`

Create a new file or add to `src/modelProvider.py`:

```python
from modelProvider import ModelProvider

class MyLlmProvider(ModelProvider):

    def __init__(self, model_id: str = "default-model", max_tokens: int = 4096):
        super().__init__(model_id=model_id, max_tokens=max_tokens)
        # Initialize your client
        self.client = ...

    @property
    def provider_name(self) -> str:
        return "MyLLM"

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        # Send prompts to your model
        # Return parsed JSON dict
        # Strip markdown code fences if the model wraps JSON in them
        response = self.client.generate(...)
        return json.loads(response.text)
```

### 2. Key Requirements

- `analyze()` must return a **parsed Python dict**, not a string
- Handle markdown code fences (`\`\`\`json ... \`\`\``) — strip them before parsing
- Raise `ValueError` if the response is not valid JSON
- Log the model ID and request for debugging
- Respect `max_tokens` to avoid truncated responses

### 3. Dynamic Model Registration (Planned)

Currently, the model provider is selected by a hardcoded mapping in `cli.py`. A future version will support plugin-style registration similar to cloud providers, allowing new model providers to be added without modifying core code.

The intended pattern:

```python
# In a future modelProvider registry:
MODEL_REGISTRY = {}

def register_model(prefix: str, cls: type):
    MODEL_REGISTRY[prefix] = cls

register_model("anthropic", AnthropicProvider)
register_model("openai", OpenAiProvider)      # future
register_model("bedrock", BedrockProvider)    # future

# CLI usage: --model openai:gpt-4o or --model anthropic:sonnet
```

For now, to add a new model provider:
1. Create the subclass in `src/modelProvider.py`
2. Update `cli.py` to instantiate it based on `--model` prefix

### 4. Model Selection Guidance

| Use Case | Recommended Model | Why |
|----------|-------------------|-----|
| Standard analysis | Sonnet | Best cost/speed/quality balance |
| Complex environments (500+ roles) | Opus | Deeper reasoning for nuanced consolidation |
| Cost-sensitive batch runs | Haiku | Fast, cheap, adequate for obvious duplicates |
| Customer-specific requirements | Whatever they require | Subclass ModelProvider |

---

## Project Architecture

```
src/
├── cli.py                  CLI entry point — provider-agnostic orchestration
├── providers/
│   ├── __init__.py         Provider registry (auto-registration)
│   ├── base.py             CloudProvider ABC + EntityRecord dataclass
│   ├── aws.py              AWS: IAM + SSO + Organizations
│   ├── azure.py            Azure: Entra ID + RBAC + subscriptions
│   └── gcp.py              GCP: Cloud Asset API + IAM + service accounts
├── accessGuardClasses.py   SimilarEntities (cloud-agnostic similarity engine)
├── roleAnalyzer.py         Jaccard clustering + AI analysis (cloud-agnostic)
├── reportGenerator.py      HTML/JSON output (cloud-agnostic)
├── modelProvider.py        LLM abstraction (ModelProvider ABC + Anthropic impl)
└── commonClasses.py        AWS utilities (Actor, DataSource — legacy pipeline)
```

### Data Flow

```
CloudProvider.scan_entities()
    → list[EntityRecord]
        → SimilarEntities.add() / .extract()      (exact matches)
        → RoleAnalyzer.add_entities() / .analyze() (clustering + AI)
            → ModelProvider.analyze()              (per cluster)
        → reportGenerator.generate_html/json()     (output)
```

The analysis pipeline knows nothing about cloud platforms. It operates
entirely on `EntityRecord.managed_policies`, `.inline_policies`,
`.members`, `.trust_info`, `.tags`, and `.last_used`. Adding a new
platform requires only a new `CloudProvider` subclass that produces
`EntityRecord` objects.

---

## Testing

```bash
# Run all unit tests (no cloud credentials needed)
python3 -m pytest tests/ --ignore=tests/test_live.py -v

# Run provider-specific tests
python3 -m pytest tests/test_azure_provider.py -v
python3 -m pytest tests/test_gcp_provider.py -v

# Run live test against real AWS
python3 src/cli.py --provider aws --output /tmp/test

# Run live test against real Azure
python3 src/cli.py --provider azure --org --output /tmp/test

# Run live test against real GCP
python3 src/cli.py --provider gcp --org --output /tmp/test
```
