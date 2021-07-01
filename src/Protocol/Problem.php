<?php

namespace Kelunik\Acme\Protocol;

final class Problem
{
    public static function fromResponse(string $payload): Problem
    {
        return new self(...parseResponse($payload, [
            'type' => string(),
            'title' => string(),
            'detail' => string(),
            'instance' => string(),
        ]));
    }

    private string $type;
    private string $title;
    private string $detail;
    private string $instance;

    public function __construct(string $type, string $title, string $detail, string $instance)
    {
        $this->type = $type;
        $this->title = $title;
        $this->detail = $detail;
        $this->instance = $instance;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getTitle(): string
    {
        return $this->title;
    }

    public function getDetail(): string
    {
        return $this->detail;
    }

    public function getInstance(): string
    {
        return $this->instance;
    }
}
