# Framework setup

The library needs a PSR-18 HTTP client and PSR-17 factories. A PSR-16 cache and
a PSR-3 logger are optional. Every framework below ships most of them already.

[`PackagistAdvisorySource`](../src/Source/Packagist/PackagistAdvisorySource.php) and [`OsvAdvisorySource`](../src/Source/Osv/OsvAdvisorySource.php) take a client, a request
factory and a stream factory. [`NvdAdvisorySource`](../src/Source/Nvd/NvdAdvisorySource.php) takes a client and a request
factory only.

| | [Symfony](#symfony-example) | [TYPO3](#typo3-example) | [Drupal](#drupal-example) |
|---|---|---|---|
| PSR-18 HTTP client | `symfony/http-client` | Core (Guzzle) | Core (Guzzle) |
| PSR-17 factories | `nyholm/psr7` | Core | Add `GuzzleHttp\Psr7\HttpFactory` |
| PSR-16 cache (optional) | `symfony/cache` | Adapter over caching framework | `symfony/cache` or none |
| PSR-3 logger (optional) | Core (`@logger`) | Core, injected | Core (logger channel) |

## Symfony (Example)

```bash
composer require symfony/http-client symfony/cache nyholm/psr7
```

```yaml
# config/services.yaml
services:
  Nyholm\Psr7\Factory\Psr17Factory: ~

  Symfony\Component\HttpClient\Psr18Client:
    arguments:
      $client: '@http_client'
      $responseFactory: '@Nyholm\Psr7\Factory\Psr17Factory'
      $streamFactory: '@Nyholm\Psr7\Factory\Psr17Factory'

  Symfony\Component\Cache\Psr16Cache:
    arguments: ['@cache.app']

  mteu\AdvisoryMatcher\Source\Packagist\PackagistAdvisorySource:
    arguments:
      $httpClient: '@Symfony\Component\HttpClient\Psr18Client'
      $requestFactory: '@Nyholm\Psr7\Factory\Psr17Factory'
      $streamFactory: '@Nyholm\Psr7\Factory\Psr17Factory'
      $logger: '@logger'

  mteu\AdvisoryMatcher\Source\Cache\CachingAdvisorySource:
    arguments:
      $inner: '@mteu\AdvisoryMatcher\Source\Packagist\PackagistAdvisorySource'
      $cache: '@Symfony\Component\Cache\Psr16Cache'
```

- Set timeouts on the framework client, for example
  `framework.http_client.default_options: { timeout: 10, max_duration: 60 }`.
- The `@logger` service is the PSR-3 logger.

## TYPO3 (Example)

TYPO3 core provides the client and both factories. Its caching framework is not
PSR-16, so a small adapter connects the two.

```yaml
# Configuration/Services.yaml
services:
  _defaults:
    autowire: true

  mteu\AdvisoryMatcher\Source\Packagist\PackagistAdvisorySource:
    arguments:
      $httpClient: '@Psr\Http\Client\ClientInterface'
      $requestFactory: '@TYPO3\CMS\Core\Http\RequestFactory'
      $streamFactory: '@TYPO3\CMS\Core\Http\StreamFactory'
```

- The HTTP client `Psr\Http\Client\ClientInterface` is an alias of core's
  Guzzle client. It honors `$GLOBALS['TYPO3_CONF_VARS']['HTTP']`, so set
  timeouts and proxy there.
- Core provides the factories as `TYPO3\CMS\Core\Http\RequestFactory` and
  `TYPO3\CMS\Core\Http\StreamFactory`.
- TYPO3 injects a PSR-3 `Psr\Log\LoggerInterface` into autowired
  constructors. Leave `$logger` out of the arguments and it is filled in.
- Use TYPO3's caching framework, not a second cache library.
  Register a cache, wrap its frontend in a PSR-16 adapter, and pass the adapter
  to `CachingAdvisorySource`. The backend is then configurable (file, database,
  Redis), and the entries are flushed with the system caches, for example by
  Admin Tools › Maintenance › "Flush TYPO3 and PHP Cache".

```php
// ext_localconf.php
$GLOBALS['TYPO3_CONF_VARS']['SYS']['caching']['cacheConfigurations']['my_extension_advisories'] ??= [
    'frontend' => \TYPO3\CMS\Core\Cache\Frontend\VariableFrontend::class,
    'backend' => \TYPO3\CMS\Core\Cache\Backend\FileBackend::class,
    'options' => ['defaultLifetime' => 86400],
    'groups' => ['system'],
];
```

```php
<?php

declare(strict_types=1);

namespace Vendor\MyExtension\Cache;

use Psr\SimpleCache\CacheInterface;
use TYPO3\CMS\Core\Cache\Frontend\FrontendInterface;

final readonly class FrontendSimpleCache implements CacheInterface
{
    private const string TAG = 'advisory_matcher';

    public function __construct(private FrontendInterface $frontend) {}

    public function get(string $key, mixed $default = null): mixed
    {
        $entry = $this->frontend->get($this->identifierFor($key));

        return $entry === false ? $default : $entry;
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $lifetime = $ttl instanceof \DateInterval
            ? (new \DateTimeImmutable())->add($ttl)->getTimestamp() - time()
            : $ttl;

        if ($lifetime !== null && $lifetime <= 0) {
            return $this->delete($key);
        }

        $this->frontend->set($this->identifierFor($key), $value, [self::TAG], $lifetime);

        return true;
    }

    public function delete(string $key): bool
    {
        $this->frontend->remove($this->identifierFor($key));

        return true;
    }

    public function clear(): bool
    {
        $this->frontend->flushByTag(self::TAG);

        return true;
    }

    public function has(string $key): bool
    {
        return $this->frontend->has($this->identifierFor($key));
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    // TYPO3 entry identifiers allow only [A-Za-z0-9_%\-&]; PSR-16 keys are freer.
    private function identifierFor(string $key): string
    {
        return 'advisory_' . sha1($key);
    }
}
```

```yaml
# Configuration/Services.yaml
services:
  my_extension.cache.frontend:
    class: TYPO3\CMS\Core\Cache\Frontend\FrontendInterface
    factory: ['@TYPO3\CMS\Core\Cache\CacheManager', 'getCache']
    arguments: ['my_extension_advisories']

  Vendor\MyExtension\Cache\FrontendSimpleCache:
    arguments:
      $frontend: '@my_extension.cache.frontend'

  mteu\AdvisoryMatcher\Source\Cache\CachingAdvisorySource:
    arguments:
      $inner: '@mteu\AdvisoryMatcher\Source\Packagist\PackagistAdvisorySource'
      $cache: '@Vendor\MyExtension\Cache\FrontendSimpleCache'
```

## Drupal (Example)

Drupal core provides the client and a stream factory. It has no request factory
and no PSR-16 cache.

```yaml
# mymodule.services.yml
services:
  mymodule.psr17_factory:
    class: GuzzleHttp\Psr7\HttpFactory

  mymodule.logger:
    parent: logger.channel_base
    arguments: ['advisory_matcher']

  mymodule.packagist_source:
    class: mteu\AdvisoryMatcher\Source\Packagist\PackagistAdvisorySource
    arguments:
      $httpClient: '@http_client'
      $requestFactory: '@mymodule.psr17_factory'
      $streamFactory: '@mymodule.psr17_factory'
      $logger: '@mymodule.logger'
```

- The HTTP client `@http_client` is a Guzzle client, which implements PSR-18.
  Configure timeouts under `$settings['http_client_config']` in `settings.php`.
- Core's PSR-17 services do not include a request factory, so define one.
  `GuzzleHttp\Psr7\HttpFactory` implements every PSR-17 interface.
- A logger channel based on `logger.channel_base` writes to the Drupal log.
- Drupal's cache backends are not PSR-16, and Drupal has no
  `cache.app` pool. Install `symfony/cache`, create a PSR-6 pool yourself and
  wrap it in `Psr16Cache`. Or run without a cache.

```yaml
# mymodule.services.yml
services:
  mymodule.advisory_cache_pool:
    class: Symfony\Component\Cache\Adapter\FilesystemAdapter
    arguments: ['advisory_matcher', 0, '/var/cache/mymodule']

  mymodule.advisory_cache:
    class: Symfony\Component\Cache\Psr16Cache
    arguments: ['@mymodule.advisory_cache_pool']

  mymodule.caching_source:
    class: mteu\AdvisoryMatcher\Source\Cache\CachingAdvisorySource
    arguments:
      $inner: '@mymodule.packagist_source'
      $cache: '@mymodule.advisory_cache'
```

Point the directory at a writable path outside the web root. Without it,
`FilesystemAdapter` falls back to the system temp directory.
