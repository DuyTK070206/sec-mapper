# OSV API Integration - Implementation Details

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    DependencyScanner                         │
│  Main entry point for vulnerability scanning workflow       │
└────┬────────────────────────────────────────────────────────┘
     │
     ├─ use_osv_direct=True (default)
     │  │
     │  └─────────────────┐
     │                    │
     └─────────────────── ─────────────────────────┐
                          │                         │
                     ┌────▼─────────────────────┐   │
                     │   OSVClient              │   │
                     │ (Direct API queries)     │   │
                     └────┬─────────────────────┘   │
                          │                         │
                          └─ Caching Layer ────────┤
                             (In-mem + File)       │
                                                   │
                     ┌─────────────────────────┐   │
                     │ VulnerabilityManager    │◄──┤
                     │ (Conversion & matching) │   │
                     └────┬────────────────────┘   │
                          │                         │
                     ┌────▼──────────────────────┐  │
                     │ OSVVulnerabilityConverter │  │
                     │ (Format transformation)   │  │
                     └────┬──────────────────────┘  │
                          │                         │
                     ┌────▼──────────────────────┐  │
                     │ Scanner Pipeline         │◄─┘
                     │ (Filtering & enrichment) │
                     └────┬──────────────────────┘
                          │
                     ┌────▼──────────────────────┐
                     │ AITriageEngine           │
                     │ (Deduplication, scoring) │
                     └──────────────────────────┘
```

## Data Flow

### 1. Dependency Parsing Phase
```
manifest.json/txt
    │
    ├─ ParsedDependency(name, version, ecosystem)
    │  e.g., ParsedDependency("lodash", "4.17.19", "npm")
    │
    └─ List[ParsedDependency]
```

### 2. OSV Query Phase
```
ParsedDependency
    │
    ├─ Extract actual version (if spec: ^4.17.0 → 4.17.0)
    │
    ├─ Map ecosystem (npm → "npm", pip → "PyPI", maven → "Maven")
    │
    ├─ Query OSV API
    │  POST https://api.osv.dev/v1/query
    │  {
    │    "package": {"name": "lodash", "ecosystem": "npm"},
    │    "version": "4.17.19"
    │  }
    │
    └─ Response: {"vulns": [{"id": "...", "aliases": [...], ...}]}
```

### 3. Format Conversion Phase
```
OSV Vulnerability (API format)
    │
    ├─ Extract CVE ID from aliases array
    │
    ├─ Extract affected versions from "affected" array
    │
    ├─ Extract fixed version from events
    │
    ├─ Map severity (numeric → low/medium/high/critical)
    │
    ├─ Extract CWE IDs from references
    │
    └─ Internal Format:
       {
         "vulnerability_id": "CVE-2020-28500",
         "affected_versions": ["<4.17.21"],
         "fixed_version": "4.17.21",
         "severity": "high",
         "source": "OSV"
       }
```

### 4. Matching Phase
```
Internal Vulnerability Format + ParsedDependency
    │
    ├─ Check if version matches affected ranges
    │  - Use _hits() method with version matching logic
    │  - Handles npm version specs (^, ~, >=, etc.)
    │
    ├─ Skip if already fixed in current version
    │
    ├─ Skip very old CVEs (CVE-1999*, CVE-2000*)
    │
    └─ Finding (matched vulnerability)
```

### 5. Enrichment Phase
```
Finding (raw match)
    │
    ├─ Calculate confidence score
    │  - Version specificity: +0.25
    │  - Source reputation: +0.20 (OSV)
    │  - Patch availability: +0.10
    │  - Transitive dependency: +0.05
    │
    ├─ Infer vulnerability type
    │  - Parse title/description for keywords
    │  - Map to: Injection, Code Execution, XSS, etc.
    │
    ├─ Generate PoC (if generator available)
    │
    ├─ Apply remediation recommendations
    │
    ├─ AITriageEngine enrichment
    │  - Deduplication
    │  - Risk scoring
    │
    └─ Final Finding (with all metadata)
```

## Key Design Decisions

### 1. Caching Strategy

**Why dual-layer caching?**
- **In-memory:** Fast within same session
- **File-based:** Persistent across sessions

**Cache key:** `"{package_name}:{version}"`
- Unique per package+version combination
- Enables cache hits for same dependency across projects

**24-hour TTL:**
- Balance between freshness and performance
- OSV data is relatively stable
- Can be adjusted in code if needed

### 2. Version Extraction

**Problem:** Users specify versions in many formats
- Exact: `1.2.3`
- Caret: `^1.2.3`
- Tilde: `~1.2.3`
- Ranges: `>=1.0.0,<2.0.0`
- Wildcards: `*`

**Solution:** `_extract_actual_version()` method
- Strips prefixes (^, ~, >=, >, <, =)
- Extracts first part from ranges
- Returns None for wildcards
- Enables querying with concrete version

### 3. Ecosystem Mapping

**Problem:** Different ecosystems use different names
- npm uses "npm"
- Python uses "PyPI" (not "pip")
- Maven uses "Maven" (not "maven")

**Solution:** `ECOSYSTEM_MAP` dictionary in OSVClient
```python
ECOSYSTEM_MAP = {
    'npm': 'npm',
    'pip': 'PyPI',
    'pypi': 'PyPI',
    'maven': 'Maven',
}
```

### 4. Error Handling Strategy

**No crash on error:** All exceptions caught and logged
- Returns empty list instead of raising
- Allows scan to continue even if one API call fails
- Log includes error type for debugging

**Retry logic:** 2 attempts per query
- Tolerates transient network issues
- 15s timeout per attempt

### 5. Direct vs. Pipeline Mode

**Direct mode (default):**
- Pros: Simple, fast, no IntelligencePipeline overhead
- Use: Production scans, new projects

**Pipeline mode:**
- Pros: Backward compatible, can combine multiple sources
- Use: Legacy systems, complex advisory mixing

## Key Classes

### OSVClient
**Responsibility:** Query OSV API and manage caching

**Key Methods:**
- `query()` - Main entry point
- `_query_osv_api()` - HTTP layer
- `_load_from_cache()` - File cache read
- `_save_to_cache()` - File cache write
- `clear_cache()` - Manual cache clearing
- `get_cache_stats()` - Introspection

**Static Methods:**
- `_extract_cve_id()` - Parse CVE from aliases

### OSVVulnerabilityConverter
**Responsibility:** Transform OSV API format to internal format

**Key Methods:**
- `convert()` - Main conversion method
- `_extract_affected_versions()` - Parse "affected" field
- `_extract_fixed_version()` - Extract patch version
- `_map_severity()` - Severity translation
- `_extract_cwe()` - CWE ID extraction

### VulnerabilityManager
**Responsibility:** Coordinate OSV queries with version matching

**Key Methods:**
- `find_vulnerabilities()` - Primary interface
- `_extract_actual_version()` - Version resolution
- `_hits()` - Version range matching (reused)
- `get_cache_stats()` - Cache visibility
- `clear_cache()` - Cache management

### DependencyScanner
**Responsibility:** Full scan workflow orchestration

**Key Methods:**
- `scan_file()` - Entry point
- `_scan_with_osv_direct()` - OSV direct path
- `_scan_with_pipeline()` - Legacy path
- `_confidence_for_osv()` - Confidence scoring
- `_infer_vuln_type_from_advisory()` - Type detection

## Logging Levels

### DEBUG
- Cache hits/misses
- Version extraction
- API attempt numbers
- Skipped matches

### INFO
- Vulnerabilities found
- API queries initiated
- Cache stats

### WARNING
- Timeouts
- Connection errors
- HTTP errors (non-404)

### ERROR
- Exceptions (rarely logged, usually caught)

## Performance Characteristics

### Time Complexity
- **Per dependency:** O(1) - single API call
- **Full project:** O(n) - n dependencies
- **With caching:** O(h + (n-h)) - h hits, (n-h) misses

### Space Complexity
- **In-memory cache:** O(n*v) - n packages, v versions
- **File cache:** O(n*v) - limited by 24h TTL

### Network Complexity
- **First scan:** n API calls (1 per unique dependency)
- **Cached scan:** 0 API calls
- **Mixed scan:** k API calls (k new dependencies)

## Testing Strategy

### Unit Tests (Would add)
- `test_extract_actual_version()` - Version parsing
- `test_ecosystem_mapping()` - Ecosystem names
- `test_version_matching()` - Range logic
- `test_cache_operations()` - Cache layer

### Integration Tests (Current)
- `test_osv_client_direct()` - API queries
- `test_vulnerability_manager()` - Conversion
- `test_dependency_parser_with_scanner()` - Parsing
- `test_scanner_osv_direct()` - Full workflow

### Real-World Tests
- ✅ qs 6.9.0 → CVE-2022-24999
- ✅ lodash 4.17.19 → Multiple CVEs
- ✅ express 4.18.2 → CVEs (not always clean)

## Future Enhancements

### 1. Concurrent Queries
```python
# Could use ThreadPoolExecutor or asyncio
async def scan_dependencies_concurrent(deps):
    tasks = [osv_client.query(dep.name, dep.ecosystem, dep.version) 
             for dep in deps]
    return await asyncio.gather(*tasks)
```

### 2. Multiple Advisory Sources
```python
# Could integrate with:
- NVD API (direct)
- GitHub Advisory API
- Snyk API
- Dependabot

# Round-robin or fallback strategy
```

### 3. Severity Calculation
```python
# Better severity mapping from CVSS scores
def map_cvss_to_severity(score):
    if score >= 9.0: return "critical"
    elif score >= 7.0: return "high"
    # ...
```

### 4. Filtering Options
```python
# User-controlled filtering
- Min severity level
- Min CVSS score
- Exclude patterns (e.g., exclude dev deps)
- Include/exclude specific CVEs
```

### 5. Metrics Collection
```python
# Track performance metrics
- API call latencies
- Cache hit rates
- CVE detection trends
- Scanner execution time
```

## Maintenance Guidelines

### Adding New Ecosystem
1. Add to `ECOSYSTEM_MAP` in OSVClient
2. Test with sample package in that ecosystem
3. Verify version extraction works
4. Add to test suite

### Changing Cache TTL
- Modify `CACHE_DURATION` in OSVClient
- Current: `24 * 3600` (24 hours)
- Consider impact on freshness vs. performance

### Updating Severity Mapping
- Modify `_map_severity()` in OSVVulnerabilityConverter
- Test with real OSV responses
- Ensure backward compatibility

### Debugging Issues
- Enable DEBUG logging: `logging.basicConfig(level=logging.DEBUG)`
- Check cache directory: `scan_cache/`
- Verify OSV API availability: `https://api.osv.dev`
- Test with `test_osv_integration.py`

## API Contract

### OSV Query Request
```json
{
  "package": {
    "name": "lodash",
    "ecosystem": "npm"
  },
  "version": "4.17.19"
}
```

### OSV Query Response
```json
{
  "vulns": [
    {
      "id": "GHSA-xxxxx-xxxxx-xxxxx",
      "aliases": ["CVE-2020-28500"],
      "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
      "details": "...",
      "affected": [
        {
          "package": {"name": "lodash", "ecosystem": "npm"},
          "versions": ["..."],
          "ranges": [
            {
              "type": "SEMVER",
              "events": [
                {"introduced": "0"},
                {"fixed": "4.17.21"}
              ]
            }
          ]
        }
      ],
      "references": [...],
      "severity": [...],
      "published": "2020-11-16T...",
      "modified": "2023-10-17T..."
    }
  ]
}
```

## Error Scenarios

### Scenario 1: Network Timeout
```
OSV Query → Timeout (>15s)
↓
Retry once
↓
If still timeout: Return [], log WARNING
↓
Scan continues with next dependency
```

### Scenario 2: Invalid Version
```
DependencyScanner receives: "4.17.abc"
↓
VulnerabilityManager._extract_actual_version()
↓
Returns "4.17.abc" (couldn't parse, return as-is)
↓
OSVClient.query() sends to API
↓
OSV API returns empty results (version not found)
↓
No vulnerabilities matched (expected behavior)
```

### Scenario 3: Ecosystem Not Supported
```
Package received: name="pkg", ecosystem="nuget"
↓
OSVClient.query()
↓
ecosystem.lower() = "nuget"
↓
ECOSYSTEM_MAP.get("nuget") = None
↓
Skip OSV query, return [], log DEBUG
↓
Return to caller
```

## Conclusion

The OSV API integration provides a clean, maintainable, and efficient vulnerability scanning system that:
- ✅ Eliminates static database maintenance
- ✅ Provides real-time vulnerability data
- ✅ Handles errors gracefully
- ✅ Supports intelligent caching
- ✅ Maintains backward compatibility
- ✅ Follows clean code principles
- ✅ Is well-tested and documented
