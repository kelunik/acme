# acme

![Unstable](https://img.shields.io/badge/api-unstable-orange.svg?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)

`kelunik/acme` is a non-blocking implementation of the [ACME](https://github.com/ietf-wg-acme/acme) protocol based on the [`amp`](https://github.com/amphp/amp) concurrency framework.

> If you're looking for a PHP client, have a look at [`kelunik/acme-client`](https://github.com/kelunik/acme-client) which is based on this library.

**Required PHP Version**

- PHP 5.5

**Installation**

```bash
composer require kelunik/acme
```

**[Documentation](http://blog.kelunik.com/docs/acme/)**

The library is fully documented using PHPDoc.

**Implementations**

 - [`kelunik/acme-client`](https://github.com/kelunik/acme-client)
 - [`kelunik/aerys-acme`](https://github.com/kelunik/aerys-acme)
 - [`Petertjuh360/da-letsencrypt`](https://github.com/Petertjuh360/da-letsencrypt)

**Usage**

If you're not familiar with promises and `amphp/amp` yet, read my [blog post to get started](http://blog.kelunik.com/2015/09/20/getting-started-with-amp.html).
You can always use `Amp\wait` to use this async library in synchronious code.
