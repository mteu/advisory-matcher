<div align="center">

[![CGL](https://github.com/mteu/advisory-matcher/actions/workflows/cgl.yaml/badge.svg)](https://github.com/mteu/advisory-matcher/actions/workflows/cgl.yaml)
[![Tests](https://github.com/mteu/advisory-matcher/actions/workflows/tests.yaml/badge.svg?branch=main)](https://github.com/mteu/advisory-matcher/actions/workflows/tests.yaml)
[![PHP Version Require](https://poser.pugx.org/mteu/advisory-matcher/require/php)](https://packagist.org/packages/mteu/advisory-matcher)

# Advisory Matcher

</div>

Framework-agnostic PHP library that matches installed packages against security advisories from Packagist, OSV, and NVD.
It answers one question: is this package affected?

You hand it packages. It gives back advisories, plus a record of which packages it actually checked and which sources
failed.

> [!WARNING]
> This project is not yet intended for production use. The API may change
> without notice.

## 🚀 Features

* [Packagist](https://packagist.org/apidoc) for Composer packages
* [OSV](https://google.github.io/osv.dev/api/) for Composer and npm packages
* [NVD](https://nvd.nist.gov/developers/vulnerabilities) for the PHP runtime and the web and database servers it runs on

## ⚡️ Installation

```bash
composer require mteu/advisory-matcher
```

You also need a PSR-18 HTTP client and PSR-17 factories. A PSR-16 cache and a PSR-3 logger are optional.

See [framework setup](docs/frameworks.md) for TYPO3, Symfony, and Drupal examples.

## 💡 Usage

```php
use mteu\AdvisoryMatcher\Advisory\AdvisoryMatcher;
use mteu\AdvisoryMatcher\Package\PackageUrl;
use mteu\AdvisoryMatcher\Source\CompositeAdvisorySource;
use mteu\AdvisoryMatcher\Source\Cache\CachingAdvisorySource;
use mteu\AdvisoryMatcher\Source\PackageRef;
use mteu\AdvisoryMatcher\Source\Packagist\PackagistAdvisorySource;
use mteu\AdvisoryMatcher\Source\Osv\OsvAdvisorySource;

// $httpClient: Psr\Http\Client\ClientInterface (set timeouts on it)
// $factory: an object implementing the PSR-17 request and stream factories
// $cache: Psr\SimpleCache\CacheInterface
$source = new CompositeAdvisorySource([
    new CachingAdvisorySource(new PackagistAdvisorySource($httpClient, $factory, $factory), $cache),
    new CachingAdvisorySource(new OsvAdvisorySource($httpClient, $factory, $factory, recordCache: $cache), $cache),
]);
$matcher = new AdvisoryMatcher();

// Feed text can carry terminal control sequences.
$plain = static fn (string $text): string => preg_replace('/\p{Cc}/u', '', $text) ?? '?';

$packages = [
    new PackageRef(PackageUrl::fromString('pkg:composer/symfony/http-kernel'), '5.4.19'),
    new PackageRef(PackageUrl::fromString('pkg:npm/lodash'), '4.17.20'),
];
$batch = $source->advisoriesFor($packages);

// A package can be answered by one source while another source failed for it.
foreach ($batch->failures as $failure) {
    printf("%s failed for %s: %s\n", $failure->sourceName, $failure->ecosystem->getDisplayName(), $failure->reason->value);
}

foreach ($packages as $package) {
    if (!$batch->wasAnsweredFor($package)) {
        printf("%s: not checked, treat as unknown\n", $package->name);
        continue;
    }

    $matches = $matcher->matchAll($batch->advisoriesFor($package), $package->version);

    foreach ($matches->affected as $advisory) {
        $id = $advisory->hasCve() ? $advisory->cve : $advisory->advisoryId;
        $fix = $matcher->fixedVersionFor($advisory, $package->version);
        printf(
            "%s: %s %s, %s\n",
            $package->name,
            $advisory->severity->value,
            $plain($id),
            $fix !== '' ? 'fixed in ' . $fix : 'no fix known',
        );
    }

    foreach ($matches->undetermined as $advisory) {
        printf("%s: %s, could not tell\n", $package->name, $plain($advisory->advisoryId));
    }
}
```

## 📝 Things to know

- Call `wasAnsweredFor()` for each package. `isComplete()` only says that no source reported a failure. A package that a feed has never heard of goes unanswered without any failure.
- Matching returns affected, not affected, or undetermined. Undetermined means the version could not be parsed or no usable range existed. It does not mean clean.
- Failures are yours to handle. `$batch->failures` lists them, each with a `FailureReason`. The library does not retry. Call `isTransient()` to see if asking again makes sense.
- Advisory text comes from third parties. Escape every field before you show it.
- Packages are named by package URL. `PackageUrl` lowercases a Composer vendor and name and keeps an npm name's case, as the purl specification has it. Build one from a registry name with `PackageUrl::fromPackageName('npm', '@babel/core')`.
- Store findings by fingerprint, not by `advisoryId`. Get it with `$advisory->getFingerprint()` and look it up with `AdvisoryFingerprint::identitiesOf($advisory)`.
- The library uses your HTTP client. Timeouts and proxy settings are yours to set. Each source also accepts `userAgent:` and `endpoint:`.

## 🔧 Optional setup

### PHP runtime

Add `NvdAdvisorySource($httpClient, $factory, $nvdApiKey)` to your sources. Then check the runtime with
`new PackageRef(PackageUrl::fromString('pkg:generic/php'), '8.3.6')`.

The purl specification has no type for the PHP runtime, so it is a `generic` package. The API key is optional but
raises the rate limit.

The same source checks the platform: a web or database server named by a `PlatformProduct`, such as
`new PackageRef(PackageUrl::fromPackageName('generic', PlatformProduct::MariaDb->value), '10.11.6')`.
Products NVD files under more than one CPE name, nginx and MySQL for now, are recognized but go unanswered, because
asking under one of those names alone could miss CVEs filed under the other and pass the server as clean.

### Severity for Packagist advisories

Packagist gives no severity for advisories that only FriendsOfPHP knows, so they come back as `unknown`. To rate them
from their CVE record at NVD, wrap the source:

```php
use mteu\AdvisoryMatcher\Source\Cache\CachingSeverityLookup;
use mteu\AdvisoryMatcher\Source\Nvd\NvdSeverityLookup;
use mteu\AdvisoryMatcher\Source\SeverityEnrichingAdvisorySource;

new SeverityEnrichingAdvisorySource(
    new CachingAdvisorySource(new PackagistAdvisorySource($httpClient, $factory, $factory), $cache),
    new CachingSeverityLookup(new NvdSeverityLookup($httpClient, $factory, $nvdApiKey), $cache),
    maxLookupsPerBatch: $nvdApiKey === '' ? 5 : 50,
);
```

Keep it outside `CachingAdvisorySource`, so a failed lookup is not cached with the answer.

A severity that a feed stated is never replaced. A lookup that fails, or goes past `maxLookupsPerBatch`, leaves the
advisory `unknown` and is logged, but it is not a failure in the batch. Cached severities need no lookup, so later
batches rate the rest.

## 📙 Documentation

See the [public API reference](docs/api.md) for the supported types. Everything else is `@internal`.

## 🤝 Contributing

Contributions are very welcome. Please read the [Contribution Guide](CONTRIBUTING.md). It lays out the workflow for
submitting features and bugfixes.

## 🔒 Security

If you find a security vulnerability in this library, please follow the [Security Policy](SECURITY.md).

## ⭐ License

This library is licensed under the [MIT](LICENSE.md) license.

## 💬 Support

For issues and feature requests, use the [GitHub issue tracker](https://github.com/mteu/advisory-matcher/issues).
