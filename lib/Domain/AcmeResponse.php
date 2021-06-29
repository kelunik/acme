<?php
declare(strict_types=1);

namespace Kelunik\Acme\Domain;


use Kelunik\Acme\AcmeException;

abstract class AcmeResponse {

    /**
     * Parses the payload given a list of properties and returns the list of values in the same order the properties are given.
     * When a property does not exist and a defaultValue is provided, that defaultValue is used.
     * Otherwise an exception is thrown.
     *
     * $properties format should be in the same order as the constructor:
     * [
     *   "url" => null // default value is NULL
     *   "location"    // No default value is set. When this property does not exist, an exception will be thrown.
     * ]
     *
     * The property values are returned.
     *
     * @param $payload
     * @param array $properties
     * @return array property values.
     * @throws \Kelunik\Acme\AcmeException
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
     * @param bool $throwOnEmpty
     * @param $payload
     * @param string $property
     * @return mixed
     * @throws \Kelunik\Acme\AcmeException
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