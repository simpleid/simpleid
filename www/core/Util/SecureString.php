<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2024
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

namespace SimpleID\Util;

use \Stringable;
use Branca\Branca;
use Symfony\Component\Yaml\Tag\TaggedValue;

/**
 * A secure string
 */
final class SecureString implements \Stringable {
    /** @var string */
    private $ciphertext;

    /**
     * Creates a SecureString from the specified ciphertext
     * 
     * @param string $ciphertext the ciphertext
     */
    public function __construct(string $ciphertext) {
        $this->ciphertext = $ciphertext;
    }

    /**
     * Creates a SecureString from a plaintext string
     * 
     * @param string $plaintext the plaintext to encrypt
     * @return SecureString the secure string
     */
    static public function fromPlaintext(string $plaintext): SecureString {
        $branca = new Branca(self::getKey());
        return new SecureString($branca->encode($plaintext));
    }

    /**
     * Returns the plaintext version of the secure string
     * 
     * @return string the plaintext
     * @throws \RuntimeException if an error occurs during the decryption process
     */
    public function toPlaintext(): string {
        $branca = new Branca(self::getKey());
        return $branca->decode($this->ciphertext);
    }

    /**
     * Returns a YAML tagged value for serialisation into YAML
     * 
     * @return TaggedValue the YAML tagged value
     */
    public function toYamlTaggedValue(): TaggedValue {
        return new TaggedValue('secure_string', $this->ciphertext);
    }

    /**
     * Returns the plain text value.
     * 
     * The plaint text value is determined based on the following rules:
     * 
     * 1. If $value is a SecureString, then the value is decrypted
     * 2. If $value is a YAML !secure_string tagged value, then a SecureString is
     *    created from the YAML value and is decrypted
     * 3. If $value is or can be converted to a string, then the string value
     *    is returned
     * 4. If $value is null, then null is returned
     * 5. Otherwise an InvalidArugmentException is raised
     * 
     * @param SecureString|TaggedValue|string|Stringable|null $value the value to
     * get the plain text value
     * @return string the plain text value, or null if $value is null
     * @throws \InvalidArgumentException
     */
    static public function getPlaintext($value): ?string {
        if ($value instanceof SecureString) {
            return $value->toPlaintext();
        } elseif (($value instanceof TaggedValue) && ($value->getTag() == 'secure_string')) {
            return (new SecureString($value->getValue()))->toPlaintext();
        } elseif (is_string($value)) {
            return $value;
        } elseif ($value instanceof Stringable) {
            return $value->__toString();
        } elseif ($value == null) {
            return null;
        }
        
        throw new \InvalidArgumentException();
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string {
        return $this->ciphertext;
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array {
        return ['ciphertext' => $this->ciphertext ];
    }

    /**
     * {@inheritdoc}
     * @param array<mixed> $data
     * @return void
     */
    public function __unserialize(array $data) {
        $this->ciphertext = $data['ciphertext'];
    }

    static private function getKey(): string {
        /** @var ?string */
        static $key = null;

        if ($key == null) {
            if (isset($_ENV['SIMPLEID_SECURE_SECRET'])) {
                $secret = $_ENV['SIMPLEID_SECURE_SECRET'];
            } elseif (isset($_ENV['SIMPLEID_SECURE_SECRET_FILE'])) {
                $secret = file_get_contents($_ENV['SIMPLEID_SECURE_SECRET_FILE']);
                if ($secret === false)
                    throw new \RuntimeException('Error reading file File specified by SIMPLEID_SECURE_SECRET_FILE');
            } else {
                throw new \RuntimeException('Key not found');
            }
            $key = hash('sha256', $secret, true);
        }

        return $key;
    }
}

?>