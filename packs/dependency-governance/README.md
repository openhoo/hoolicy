# Dependency governance pack

Maintained parsers check whether reviewed dependency resolution is reproducible. Ancestor npm/Cargo locks govern nested workspace manifests; repository-contained `workspace:`, `file:`, `link:`, and Cargo path edges count as resolved. Missing targets still fail. Test fixtures or generated trees may be removed only through narrow `excluded_manifests` globs. This pack does not find vulnerabilities and does not replace ecosystem package managers, license scanners, or SBOM tools.
