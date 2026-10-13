# Deployment invariants pack

Experimental structured policies for reviewed deployment risks. Every opinion is a parameter. Compose discovery covers root and nested environment directories; test or development files may be removed only through narrow `excluded_files` globs. Terraform uses generated plan JSON; Hoolicy never executes Terraform or parses HCL with regex.

Required resource limits must contain a complete positive quantity. Kubernetes
uses its case-sensitive SI, binary, or decimal-exponent units; Compose CPU
limits are numeric and memory limits use Docker byte units. Compose memory
limits must represent at least one byte after unit conversion. Malformed tails
such as `128MiJUNK` and Kubernetes millicore units in Compose CPU limits fail.
These checks do not replace deployment schema validation or prove that a
cluster can schedule the requested resources.
