# Public API

These types are the public API. Names are relative to `mteu\AdvisoryMatcher\`.

Everything else in `src/` is marked `@internal` and can change or disappear in
any release.

## Sources

- [`Source\AdvisorySource`](../src/Source/AdvisorySource.php): the interface every source implements
- [`Source\Packagist\PackagistAdvisorySource`](../src/Source/Packagist/PackagistAdvisorySource.php): Composer packages
- [`Source\Osv\OsvAdvisorySource`](../src/Source/Osv/OsvAdvisorySource.php): Composer and npm packages
- [`Source\Nvd\NvdAdvisorySource`](../src/Source/Nvd/NvdAdvisorySource.php): the PHP runtime
- [`Source\CompositeAdvisorySource`](../src/Source/CompositeAdvisorySource.php): asks several sources and merges the answers
- [`Source\Cache\CachingAdvisorySource`](../src/Source/Cache/CachingAdvisorySource.php): caches answers of another source
- [`Source\AdvisoryDeduplicator`](../src/Source/AdvisoryDeduplicator.php): folds reports of one vulnerability into one advisory
- [`Source\SeverityEnrichingAdvisorySource`](../src/Source/SeverityEnrichingAdvisorySource.php): rates advisories a feed left `unknown` from their CVE record

## Severity lookups

- [`Source\SeverityLookup`](../src/Source/SeverityLookup.php): the interface every severity lookup implements
- [`Source\Nvd\NvdSeverityLookup`](../src/Source/Nvd/NvdSeverityLookup.php): reads a CVE's severity from NVD
- [`Source\Cache\CachingSeverityLookup`](../src/Source/Cache/CachingSeverityLookup.php): caches the severities of another lookup

## Questions and answers

- [`Source\PackageRef`](../src/Source/PackageRef.php): a package and version to check, readable from and writable as a package URL
- [`Package\PackageUrl`](../src/Package/PackageUrl.php): a package as a canonical package URL without version
- [`Package\Ecosystem`](../src/Package/Ecosystem.php): `composer`, `npm`, `php` or `unknown`
- [`Source\AdvisoryBatch`](../src/Source/AdvisoryBatch.php): the result of one lookup
- [`Source\AnsweredPackage`](../src/Source/AnsweredPackage.php): a checked package with its advisories
- [`Source\SourceFailure`](../src/Source/SourceFailure.php): a source that did not answer
- [`Source\FailureReason`](../src/Source/FailureReason.php): why it did not answer

## Advisories

- [`Advisory\Advisory`](../src/Advisory/Advisory.php): one security advisory
- [`Advisory\AdvisoryReference`](../src/Advisory/AdvisoryReference.php): where a feed reported it
- [`Advisory\Severity`](../src/Advisory/Severity.php): `low`, `medium`, `high`, `critical` or `unknown`
- [`Advisory\AdvisoryFingerprint`](../src/Advisory/AdvisoryFingerprint.php): stable keys for storing findings

## Matching

- [`Advisory\AdvisoryMatcher`](../src/Advisory/AdvisoryMatcher.php): decides whether a version is affected
- [`Advisory\MatchResult`](../src/Advisory/MatchResult.php): affected, not affected or undetermined
- [`Advisory\AdvisoryMatches`](../src/Advisory/AdvisoryMatches.php): results grouped by outcome
- [`Version\AffectedVersions`](../src/Version/AffectedVersions.php): the affected ranges of an advisory
- [`Version\VersionRange`](../src/Version/VersionRange.php): one affected range
