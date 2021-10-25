# acme ![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)

`kelunik/acme` is a non-blocking implementation of the [ACME](https://github.com/ietf-wg-acme/acme) protocol based on the [`amp`](https://github.com/amphp/amp) concurrency framework.

> If you're looking for a PHP client, have a look at [`kelunik/acme-client`](https://github.com/kelunik/acme-client) which is based on this library.

**Required PHP Version**

- PHP 7.4+

**Installation**

```bash
composer require kelunik/acme
```

This package follows semantic versioning.

**Usage**

You should be familiar with promises and [`amphp/amp`](https://github.com/amphp/amp).
You can always use `Amp\Promise\wait` to use this async library in synchronous code.
