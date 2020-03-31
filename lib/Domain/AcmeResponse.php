<?php
declare(strict_types=1);

namespace Kelunik\Acme\Domain;


use Kelunik\Acme\AcmeException;

abstract class AcmeResponse {

    /**
     * Parses the payload to the child AcmeResponse object. The constructor args are parsed from the payload and the
     * a list of the given properties. When property not exists, and a defaultValue is provided, that is used.
     * Otherwise, an exception is thrown.
     *
     * $properties format should be in the same order as the constructor:
     * [
     *   "url" => null // default value is NULL
     *   "location"    // No default value is set. When this property does not exists, an exception will be thrown.
     * ]
     *
     * The contructorArgs are returned.
     *
     * @return array $constructorArgs.
     * @throws \Kelunik\Acme\AcmeException
     * @param $payload
     *@param array $properties
     */
    protected static function parsePayloadWithProps($payload, array $properties): array {
        $constructorArgs = [];
        foreach ($properties as $property => $defaultValue) {
            // If there is no default value, the $defaultValue is handled as the property itself
            $hasDefaultValue = !is_numeric($property);
            $property = $hasDefaultValue ? $property : $defaultValue;
            $defaultValue = $hasDefaultValue ? $defaultValue : null;

            $constructorArgs[] = self::getPropertyValue($payload, $property, !$hasDefaultValue) ?? $defaultValue;
        }
        return $constructorArgs;
    }

    /**
     * Returns the property value from the payload if set. When not set, throw an exception if required.
     * @return mixed
     * @throws \Kelunik\Acme\AcmeException
     * @param bool $throwOnEmpty
     * @param $payload
     * @param string $property
     */
    protected static function getPropertyValue($payload, string $property, bool $throwOnEmpty = true) {
        $value = $payload->$property ?? null;
        if($value === null && $throwOnEmpty) {
            $className = basename(str_replace("\\", "/", static::class));
            throw new AcmeException("Error parsing property: $property for $className response");
        }
        return $value;
    }
}