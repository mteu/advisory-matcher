<div align="center">

[![CGL](https://github.com/mteu/advisory-matcher/actions/workflows/cgl.yaml/badge.svg)](https://github.com/mteu/advisory-matcher/actions/workflows/cgl.yaml)
[![Tests](https://github.com/mteu/advisory-matcher/actions/workflows/tests.yaml/badge.svg?branch=main)](https://github.com/mteu/advisory-matcher/actions/workflows/tests.yaml)
[![PHP Version Require](https://poser.pugx.org/mteu/advisory-matcher/require/php)](https://packagist.org/packages/mteu/advisory-matcher)

# Advisory Matcher

</div>

Framework-agnostic PHP library that matches installed packages against security advisories from Packagist, OSV, and NVD
to answer on whether a package is affected by a security advisory.

You hand it packages. It gives back advisories, plus a record of which packages it actually checked and which sources
failed.

> [!WARNING]
> This project is not yet intended for production use. The API may change
> without notice.

## 🚀 Features
* [Packagist](https://packagist.org/apidoc) for Composer packages
* [OSV](https://google.github.io/osv.dev/api/) for Composer and npm packages
* [NVD](https://nvd.nist.gov/developers/vulnerabilities) for the PHP runtime

## ⚡️ Installation

```bash
composer require mteu/advisory-matcher
```

You also need a PSR-18 HTTP client and PSR-17 factories. (A PSR-16 cache and a PSR-3 logger are optional.)

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

To check the PHP runtime, add `NvdAdvisorySource($httpClient, $factory, $nvdApiKey)`
and a `PackageRef(PackageUrl::fromString('pkg:generic/php'), '8.3.6')`. The purl
specification has no type for the PHP runtime, so it is a `generic` package. The
API key is optional but raises the rate limit.

## 📝 Things to know

- Check each package with `wasAnsweredFor()`. `isComplete()` only tells you that no source reported a failure. A package that a feed has never heard of goes unanswered without any failure, so `isComplete()` can be true while that package was never checked.
- Matching returns affected, not affected or undetermined. Undetermined means the version couldn't be parsed or no usable range existed. It does not mean clean.
- Failures are yours to handle. `$batch->failures` lists them, each with a `FailureReason`. The library doesn't retry. Call `isTransient()` to see whether asking again makes sense.
- Advisory text comes from third parties. Escape every field before you show it. I mean it.
- Packages are named by package URL. `PackageUrl` lowercases a Composer vendor and name and keeps an npm name's case, as the purl specification has them. Build one from a registry name with `PackageUrl::fromPackageName('npm', '@babel/core')`.
- Store findings by fingerprint, not by `advisoryId`. Get it with `$advisory->getFingerprint()` and look it up with `AdvisoryFingerprint::identitiesOf($advisory)`.
- The library uses your HTTP client, so timeouts and proxy settings are yours to set. Each source also accepts `userAgent:` and `endpoint:`.

## 📙 Documentation

See the [public API reference](docs/api.md) for the supported types.
Everything else is `@internal`. 🤷‍♂️

## 🤝 Contributing

Contributions are very welcome! Please have a look at the
[Contribution Guide](CONTRIBUTING.md). It lays out the workflow of submitting
new features or bugfixes.

## 🔒 Security

Please refer to the [Security Policy](SECURITY.md) if you discover a security
vulnerability in this library.

## ⭐ License

This library is licensed under the [MIT](LICENSE.md) license.

## 💬 Support

For issues and feature requests, please use the
[GitHub issue tracker](https://github.com/mteu/advisory-matcher/issues).
