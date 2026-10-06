# Security Policy

Please follow the guidelines below if you believe you have discovered a
vulnerability in this project.

> [!CAUTION]
> Please do not open GitHub issues for security vulnerabilities!

## Supported Versions

While the package is in 0.x, only the latest minor release gets security
fixes. Upgrade to it to receive them.

| Version                  | Supported |
|--------------------------|-----------|
| Latest 0.x minor release | Yes       |
| Any older release        | No        |

## What to Report

Report a vulnerability in this library's own code. One example is a link that
is not http(s) getting through to your output. Another is an affected package
being reported as clean.

Wrong data in an advisory, such as a wrong version range or severity, belongs
to the feed that published it: Packagist, OSV or NVD. Tell us anyway if the
library makes it worse.

## Reporting a Vulnerability

Please use GitHub's private vulnerability reporting. Open the
[Security tab](https://github.com/mteu/advisory-matcher/security) and click
"Report a vulnerability", or go straight to the
[report form](https://github.com/mteu/advisory-matcher/security/advisories/new).

Your report should include the following details:

* The exact version or version range that you analysed.
* The PHP version that you used for your analysis.
* The advisory source involved (Packagist, OSV or NVD), if any.
* A step-by-step explanation of how to exploit the potential vulnerability.

## What to Expect

One person maintains this project in their spare time. Expect a first reply
within 14 days. You will hear whether the report is accepted and when a fix
is planned. No bounties are offered.
