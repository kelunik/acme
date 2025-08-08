<?php declare(strict_types=1);

namespace Kelunik\Acme;

use PHPUnit\Framework\TestCase;

final class ParseDateTest extends TestCase
{
    public function test(): void
    {
        $this->assertInstanceOf(\DateTimeImmutable::class, parseDate('2021-07-10T19:55:32Z'));
    }
}
