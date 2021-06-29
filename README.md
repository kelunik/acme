# acme ![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)

`kelunik/acme` is a non-blocking implementation of the [ACME](https://github.com/ietf-wg-acme/acme) protocol based on the [`amp`](https://github.com/amphp/amp) concurrency framework.

> If you're looking for a PHP client, have a look at [`kelunik/acme-client`](https://github.com/kelunik/acme-client) which is based on this library.

**Required PHP Version**

- PHP 7.2+

**Installation**

```bash
composer require kelunik/acme
```

This package follows semantic versioning. Although there's no `v1.0.0` yet, it's safe to use it as a dependency, because breaking changes won't be installed when using it as `^0.3`.

**[Documentation](https://docs.kelunik.com/kelunik/acme)**

The library is fully documented using PHPDoc.

**Usage**

If you're not familiar with promises and `amphp/amp` yet, read my [blog post to get started](http://blog.kelunik.com/2015/09/20/getting-started-with-amp.html).
You can always use `Amp\Promise\wait` to use this async library in synchronous code.
