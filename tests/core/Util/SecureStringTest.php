<?php

namespace SimpleID\Util;

use PHPUnit\Framework\TestCase;

class SecureStringTest extends TestCase {
    const SECURE_SECRET = 'FDaigcnJB1yyWoVtvamB6TJVNGr1R6hzeRZGsSHMaBebLKgvpdZAVRwpgfcxK2uq';

    static function setUpBeforeClass(): void {
        $_ENV['SIMPLEID_SECURE_SECRET'] = self::SECURE_SECRET;
    }

    function testSecureString() {
        $plaintext = 'This is a test string';

        $secure = SecureString::fromPlaintext($plaintext);

        $this->assertNotEquals($plaintext, $secure->__toString());
        $this->assertEquals($plaintext, $secure->toPlaintext());
    }
}
?>