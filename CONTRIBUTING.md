# Contributing

Thank you for considering a contribution.

## Fork & Pull Request Workflow

1. Fork this repository
2. Create a feature branch: `git checkout -b feature/your-feature`
   (or `bugfix/your-bugfix`)
3. Install dependencies: `composer install`
4. Make your changes
5. Run the quality checks (see below)
6. Commit following the [commit message rules](#commit-messages)
7. Push: `git push origin feature/your-feature`
8. Create a pull request on GitHub

## Requirements

- PHP 8.3+
- All tests must pass
- Code must pass PHPStan level max
- Follow the existing code style: `final readonly` classes, and public readonly
  properties for data. Use methods only for derived values.

## Quality checks

`composer check` is the full gate. It is what CI runs.

```bash
composer check   # lint, static analysis, dependency analysis, tests
```

The parts, one by one:

| Command         | Description           |
|-----------------|-----------------------|
| `composer lint` | Check code style      |
| `composer fix`  | Apply automatic fixes |
| `composer sca`  | Static analysis       |
| `composer test` | Unit tests            |

## Testing

```bash
composer test                    # All tests
composer test:unit               # Unit tests only
composer test:coverage           # With coverage (needs a coverage driver)
```

Run specific tests. PHPUnit lives in `.build/vendor`, so call it from there:

```bash
.build/vendor/bin/phpunit -c phpunit.unit.xml tests/Unit/Advisory/AdvisoryMatcherTest.php
.build/vendor/bin/phpunit -c phpunit.unit.xml --filter testMethodName
```

Use hand-written test doubles named by role, such as `FailingAdvisorySource`.
Do not mock the library's own interfaces.

## Commit Messages

Prefix each commit with a type in brackets, followed by a short summary in the
imperative mood.

| Type         | Use for                                                                                                                                               |
|--------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| `[FEATURE]`  | New functionality                                                                                                                                     |
| `[BUGFIX]`   | Bug fixes                                                                                                                                             |
| `[TASK]`     | Maintenance, refactoring, code cleanup                                                                                                                |
| `[DOCS]`     | Documentation changes                                                                                                                                 |
| `[SECURITY]` | Security fixes. Always approach the maintainers before committing security related patches, please. Consult the [security policy](SECURITY.md) first. |
| `[!!!]`      | Breaking changes. Always include this when changing public API.                                                                                       |

Examples:

```text
[FEATURE] Add a retry hint to rate-limited failures
[BUGFIX] Keep stale cache entries for the full retention window
[TASK] Remove redundant default parameter
[DOCS] Explain the NVD API key
[!!!][FEATURE] Rename the FailureReason cases
```
