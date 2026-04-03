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

#### Field normalization
- Renamed `ugr` field to `entityType` throughout `accessGuardClasses.py` and `accessGuard.py` — the old name (User/Group/Role abbreviation) was opaque
- Cleaned up imports: removed commented-out imports, sorted alphabetically, separated stdlib from third-party
