# Artifact evidence pack

Consumes pinned local SARIF, CycloneDX, SPDX, JUnit, or in-toto provenance. SPDX 2.2/2.3 subject binding may use `documentDescribes` or the standard document `DESCRIBES` relationship for a package or file. It never invokes a scanner and never treats presence alone as proof. Each configured artifact is exact-digest and subject bound.
