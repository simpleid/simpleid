<?php

namespace SimpleID\Crypt;

class RandomTest extends \PHPUnit_Framework_TestCase {
    public function testLength() {
        $this->assertSame(32, strlen(Random::bytes(32)));
    }

}

?>