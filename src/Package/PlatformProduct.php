<?php

declare(strict_types=1);

/*
 * This file is part of the library "mteu/advisory-matcher".
 *
 * Copyright (c) 2026 Martin Adler <mteu@mailbox.org>
 *
 * For the full copyright and license information, please read the
 * LICENSE.md file that was distributed with this source code.
 */

namespace mteu\AdvisoryMatcher\Package;

/**
 * Server software a PHP application runs on, such as its web server or database.
 *
 * No package registry ships these, so each is a `generic` package named by its
 * case's value. The names are the ones SBOM generators write for these
 * binaries, so a component an SBOM lists is recognized as well.
 */
enum PlatformProduct: string
{
    case ApacheHttpServer = 'httpd';
    case Nginx = 'nginx';
    case MySql = 'mysql';
    case MariaDb = 'mariadb';
    case PostgreSql = 'postgresql';
    case Sqlite = 'sqlite';

    public function getDisplayName(): string
    {
        return match ($this) {
            self::ApacheHttpServer => 'Apache HTTP Server',
            self::Nginx => 'nginx',
            self::MySql => 'MySQL',
            self::MariaDb => 'MariaDB',
            self::PostgreSql => 'PostgreSQL',
            self::Sqlite => 'SQLite',
        };
    }

    /**
     * @return CpeIdentity|null null where NVD files the product under several CPE names,
     *                          because asking under only one of them would pass it as clean
     *                          with the CVEs filed under the others missing
     */
    public function cpeIdentity(): ?CpeIdentity
    {
        return match ($this) {
            self::ApacheHttpServer => CpeIdentity::application('apache', 'http_server'),
            self::MariaDb => CpeIdentity::application('mariadb', 'mariadb'),
            self::PostgreSql => CpeIdentity::application('postgresql', 'postgresql'),
            self::Sqlite => CpeIdentity::application('sqlite', 'sqlite'),
            // f5:nginx and f5:nginx_open_source; oracle:mysql and oracle:mysql_server.
            self::Nginx, self::MySql => null,
        };
    }
}
