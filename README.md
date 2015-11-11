# acme

![Unstable](https://img.shields.io/badge/api-unstable-orange.svg?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)

`kelunik/acme` is a non-blocking implementation of the [ACME](https://github.com/ietf-wg-acme/acme) protocol based on the [`amp`](https://github.com/amphp/amp) concurrency framework.

**Required PHP Version**

- PHP 7

**Installation**

```bash
composer require kelunik/acme
```

**Usage**

To interact with this library, you mainly have to use `Kelunik\Acme\AcmeService` and pass a `Kelunik\Acme\AcmeAdapter` object. There's an implementation for [`amphp/aerys`](https://github.com/amphp/aerys) which you can look at: [`kelunik/aerys-acme`](https://github.com/kelunik/aerys-acme).

----

If you're not familiar with promises and `amp` yet, read the [blog post to get started](http://blog.kelunik.com/2015/09/20/getting-started-with-amp.html). You can always use `Amp\wait` to simply use async libraries in a blocking world.
