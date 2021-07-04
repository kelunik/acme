<?php

namespace Kelunik\Acme;

use PHPUnit\Framework\TestCase;

class ParseDateTest extends TestCase
{
    public function test()
    {
        $this->assertInstanceOf(\DateTimeImmutable::class, parseDate('2021-07-10T19:55:32Z'));
    }
}
