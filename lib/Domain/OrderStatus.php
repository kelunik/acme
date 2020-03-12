<?php
declare(strict_types=1);

namespace Kelunik\Acme\Domain;

class OrderStatus {
    const INVALID = 'invalid';
    const VALID = 'valid';
    const PENDING = 'pending';
    const READY = 'ready';
    const PROCESSING = 'processing';
}