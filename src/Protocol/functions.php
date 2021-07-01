<?php

namespace Kelunik\Acme\Protocol;

use Assert\Assert;
use Assert\AssertionFailedException;
use Kelunik\Acme\AcmeException;
use League\Uri\Http;
use League\Uri\Uri;
use function Kelunik\Acme\parseDate;

function parseResponse(string $json, array $schema): array
{
    try {
        $data = \json_decode($json, true, 16, \JSON_THROW_ON_ERROR);

        $result = [];

        foreach ($schema as $key => $function) {
            $value = $data[$key] ?? null;

            $result[] = $function($value);
        }

        return $result;
    } catch (\JsonException $e) {
        throw new AcmeException('Invalid JSON response', 0, $e);
    } catch (AssertionFailedException $e) {
        throw new AcmeException('Invalid response', 0, $e);
    }
}

function optional(\Closure $closure): \Closure
{
    return static function ($value) use ($closure) {
        if ($value === null) {
            return null;
        }

        return $closure($value);
    };
}

function multiple(\Closure $closure): \Closure
{
    return static function ($value) use ($closure) {
        Assert::that($value)->isArray();

        foreach ($value as $k => $v) {
            $value[$k] = $closure($v);
        }

        return \array_values($value);
    };
}

function boolean(): \Closure
{
    return static function ($value) {
        Assert::that($value)->boolean();

        return $value;
    };
}

function contact(): \Closure
{
    return static function ($value) {
        Assert::that($value)->string();

        return Uri::createFromString($value);
    };
}

function identifier(): \Closure
{
    return static function ($value) {
        Assert::that($value)->isArray()->keyExists('type')->keyExists('value');
        Assert::that($value['type'])->string();
        Assert::that($value['value'])->string();

        return new Identifier($value['type'], $value['value']);
    };
}

function enum(array $values): \Closure
{
    return static function ($value) use ($values) {
        Assert::that($value)->string()->inArray($values);

        return $value;
    };
}

function dateTime(): \Closure
{
    return static function ($value) {
        Assert::that($value)->string();

        return parseDate($value);
    };
}

function url(): \Closure
{
    return static function ($value) {
        Assert::that($value)->string()->url();

        return Http::createFromString($value);
    };
}

function string(): \Closure
{
    return static function ($value) {
        Assert::that($value)->string();

        return $value;
    };
}

function challenge(): \Closure
{
    return static function ($value) {
        Assert::that($value)->isArray();

        return Challenge::fromResponse(\json_encode($value, \JSON_THROW_ON_ERROR));
    };
}

function problem(): \Closure
{
    return static function ($value) {
        Assert::that($value)->isArray();

        return Problem::fromResponse(\json_encode($value, \JSON_THROW_ON_ERROR));
    };
}
