<?php
declare(strict_types=1);

namespace Kelunik\Acme\Domain;

class OrderStatus
{
    public const INVALID = 'invalid';
    public const VALID = 'valid';
    public const PENDING = 'pending';
    public const READY = 'ready';
    public const PROCESSING = 'processing';
}
