# Deployment invariants pack

Experimental structured policies for reviewed deployment risks. Every opinion is a parameter. Compose discovery covers root and nested environment directories; test or development files may be removed only through narrow `excluded_files` globs. Terraform uses generated plan JSON; Hoolicy never executes Terraform or parses HCL with regex.
