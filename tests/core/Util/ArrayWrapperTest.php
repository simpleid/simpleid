<?php

namespace SimpleID\Util;

use PHPUnit\Framework\TestCase;

class ArrayWrapperTest extends TestCase {
    protected function getTestData() {
        return [
            'a' => 'A',
            'b' => [
                'ba' => 'BA',
                'bb' => [ 'BB0', 'BB1' ],
                'bc' => [
                    'bca' => 'BCA'
                ]
            ]
        ];
    }

    function testGet() {
        $wrapper = new ArrayWrapper($this->getTestData());

        $this->assertEquals('A', $wrapper->get('a'));
        $this->assertEquals('BA', $wrapper->get('b.ba'));
        $this->assertEquals('BB1', $wrapper->get('b.bb.1'));
        $this->assertEquals('BCA', $wrapper->get('b.bc.bca'));
        $this->assertNull($wrapper->get('invalid'));
        $this->assertNull($wrapper->get('b.ba.invalid'));
    }

    function testEmptyPath() {
        $wrapper = new ArrayWrapper($this->getTestData());

        $this->expectException(\InvalidArgumentException::class);
        $wrapper->get('');
    }

    function testSet() {
        $wrapper = new ArrayWrapper();

        $wrapper->set('a', 'A');
        $wrapper->set('b.ba', 'BA');
        $wrapper->set('b.bb', [ 'BB0', 'BB1' ]);
        $wrapper->set('b.bc.bca', 'BCA');

        $this->assertEquals('A', $wrapper->get('a'));
        $this->assertEquals('BA', $wrapper->get('b.ba'));
        $this->assertEquals('BB1', $wrapper->get('b.bb.1'));
        $this->assertEquals('BCA', $wrapper->get('b.bc.bca'));
    }

    function testAppend() {
        $wrapper = new ArrayWrapper($this->getTestData());

        $wrapper->append('b.bb', 'BB2');
        $this->assertEquals([ 'BB0', 'BB1', 'BB2' ], $wrapper->get('b.bb'));

        $wrapper->append('new_array', 'C1');
        $wrapper->append('new_array', 'C2');
        $this->assertEquals([ 'C1', 'C2' ], $wrapper->get('new_array'));
    }

    function testInvalidAppend() {
        $wrapper = new ArrayWrapper($this->getTestData());

        $this->expectException(\InvalidArgumentException::class);
        $wrapper->append('b.ba', 'BB2');
    }

    function testUnset() {
        $wrapper = new ArrayWrapper($this->getTestData());

        $wrapper->unset('a');
        $wrapper->unset('b.ba');
        $wrapper->unset('b.bb.1');
        $wrapper->unset('b.bc.bca');

        $this->assertFalse($wrapper->exists('a'));
        $this->assertNull($wrapper->get('a'));

        $this->assertTrue($wrapper->exists('b'));

        $this->assertFalse($wrapper->exists('b.ba'));
        $this->assertFalse($wrapper->exists('b.bb.1'));
        $this->assertFalse($wrapper->exists('b.bc.bca'));
        $this->assertNull($wrapper->get('b.ba'));
        $this->assertNull($wrapper->get('b.bb.1'));
        $this->assertNull($wrapper->get('b.bc.bca'));
    }

    function testOffsetGet() {
        $wrapper = new ArrayWrapper($this->getTestData());

        $this->assertEquals('A', $wrapper['a']);
        $this->assertEquals('BA', $wrapper['b']['ba']);
        $this->assertEquals('BB1', $wrapper['b']['bb'][1]);
        $this->assertEquals('BCA', $wrapper['b']['bc']['bca']);
        $this->assertNull($wrapper['invalid']);
        $this->assertNull($wrapper['b.ba.invalid']);
    }

    function testPropertySet() {
        $wrapper = new ArrayWrapper($this->getTestData());

        $wrapper->a = 'A';
        $this->assertEquals('A', $wrapper->get('a'));
    }

    function testNonExistentPropertySet() {
        $this->expectException(\InvalidArgumentException::class);

        $wrapper = new ArrayWrapper($this->getTestData());
        $wrapper->nonExistentKey = 'A';
    }
}

?>