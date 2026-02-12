---
name: tee-audit
description: "Launch the TEE security auditor to review attestation flows, EKM channel binding, DCAP verification, and other TEE security boundaries in the current codebase."
---

Launch the `tee-security-auditor` agent via the Task tool to perform a comprehensive security audit of all TEE-related code in the current codebase. The agent should discover and review all attestation services, aTLS implementations, EKM handling, CVM configurations, and TEE security boundaries it can find, then report its findings with severity ratings and actionable recommendations.
