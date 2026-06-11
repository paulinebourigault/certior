# File Operations Skill

## Description
Read and write files within a sandboxed directory with path restrictions,
size limits, and extension filtering. All operations are tracked for
information flow compliance.

## Capabilities Required
- `filesystem:read` - Read files from allowed paths
- `filesystem:write` - Write files to allowed paths

## Safety Guarantees
- **Path sandboxing**: Only paths matching allowlist accessible; system paths blocked
- **Size limits**: Maximum 10 MB per file, 100 files per operation
- **Extension filtering**: Only allowed extensions (`.txt`, `.csv`, `.json`, `.md`, `.pdf`)
- **No traversal**: Path traversal (`../`) detected and blocked

## Formal Properties (Z3-verified)
1. `path_sandboxed` - All accessed paths within allowed directories
2. `no_traversal` - No path components contain `..`
3. `size_within_limits` - File sizes ≤ max_file_size_bytes

## Compliance
- **HIPAA**: Applicable - files may contain PHI
- **SOX**: Applicable - files may contain financial data
- **GDPR**: Applicable - files may contain personal data

## Usage
```python
skill = loader.load_skill("file_operations", token)
fs = skill.implementation.SafeFileOperations(skill.verification)
content = await fs.read_file("/workspace/report.csv")
await fs.write_file("/workspace/output.json", data)
```
