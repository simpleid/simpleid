<?php

namespace SimpleID\Crypt;

use PHPUnit\Framework\TestCase;

class RandomTest extends TestCase {
    public function testLength() {
        $this->assertSame(32, strlen(Random::bytes(32)));
    }

}

?>