<?php

namespace SimpleID\Crypt;

use PHPUnit\Framework\TestCase;

class BigNumTest extends TestCase {
    protected function getInstance($str, $base = 10) {
        return new BigNum($str, $base);
    }

    public function testConstructorBase10() {
        $this->assertSame('18446744073709551616', $this->getInstance('18446744073709551616')->val());
    }

    public function testConstructorBase256() {
        $this->assertSame('18446744073709551615', $this->getInstance(hex2bin('FFFFFFFFFFFFFFFF'), 256)->val());
    }

    public function testValueBase256() {
        $this->assertSame('00ffff', bin2hex($this->getInstance(hex2bin('FFFF'), 256)->val(256)));
        $this->assertSame('01ff', bin2hex($this->getInstance(hex2bin('01FF'), 256)->val(256)));
    }

    public function testAdd() {
        $x = $this->getInstance('18446744073709551615');
        $y = $this->getInstance( '100000000000');
        $a = $x->add($y);
        $b = $y->add($x);
        $this->assertTrue($a->cmp($b) == 0);
        $this->assertTrue($b->cmp($a) == 0);
        $this->assertSame('18446744173709551615', $a->val());
        $this->assertSame('18446744173709551615', $b->val());
    }
    
    public function testMul() {
        $x = $this->getInstance('8589934592'); // 2**33
        $y = $this->getInstance('36893488147419103232'); // 2**65
        $a = $x->mul($y); // 2**98
        $b = $y->mul($x); // 2**98
        $this->assertTrue($a->cmp($b) == 0);
        $this->assertTrue($b->cmp($a) == 0);
        $this->assertSame('316912650057057350374175801344', $a->val());
        $this->assertSame('316912650057057350374175801344', $b->val());
    }

    public function testDiv() {
        $x = $this->getInstance('1180591620717411303425'); // 2**70 + 1
        $y = $this->getInstance('12345678910');
        $q = $x->div($y);
        $this->assertSame('95627922070', $q->val());
    }

    public function testPowMod() {
        $a = $this->getInstance('10');
        $b = $this->getInstance('20');
        $c = $this->getInstance('30');
        $d = $a->powmod($b, $c);
        $this->assertSame('10', $d->val());
    }


    public function testCmp() {
        $a = $this->getInstance('-18446744073709551616');
        $b = $this->getInstance('36893488147419103232');
        $c = $this->getInstance('36893488147419103232');
        $d = $this->getInstance('316912650057057350374175801344');
        // a < b
        $this->assertLessThan(0, $a->cmp($b));
        $this->assertGreaterThan(0, $b->cmp($a));
        // b = c
        $this->assertSame(0, $b->cmp($c));
        $this->assertSame(0, $c->cmp($b));
        // c < d
        $this->assertLessThan(0, $c->cmp($d));
        $this->assertGreaterThan(0, $d->cmp($c));
    }


}

?>