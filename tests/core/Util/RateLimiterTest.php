<?php

namespace SimpleID\Util;

use PHPUnit\Framework\TestCase;

class RateLimiterTest extends TestCase {
    protected $source = 'test';

    protected function getRateLimiter($method, $limit = 10, $interval = 10) {
        $f3 = \Base::instance();
        $f3->set('CACHE', true);
        return new RateLimiter(uniqid($method), $limit, $interval);
    }

    public function testThrottle() {
        if (getenv('CI')) {
            $this->markTestSkipped();
            return;
        }
        $limiter = $this->getRateLimiter('testThrottle', 1, 1);

        $this->assertEquals(true, $limiter->throttle($this->source));
        $this->assertEquals(false, $limiter->throttle($this->source));
    }

    public function testThrottleWithWeight() {
        if (getenv('CI')) {
            $this->markTestSkipped();
            return;
        }
        $limiter = $this->getRateLimiter('testThrottleWithWeight', 2, 1);

        $this->assertEquals(true, $limiter->throttle($this->source, 2));
        $this->assertEquals(false, $limiter->throttle($this->source));
    }

    public function testRemainder() {
        if (getenv('CI')) {
            $this->markTestSkipped();
            return;
        }
        $limiter = $this->getRateLimiter('testRemainder', 2, 1);

        $this->assertEquals(true, $limiter->throttle($this->source));
        $this->assertEquals(1, $limiter->remainder($this->source));
    }

    public function testThrottleExpires() {
        if (getenv('CI')) {
            $this->markTestSkipped();
            return;
        }
        $limiter = $this->getRateLimiter('testThrottleExpires', 2, 2);

        $this->assertEquals(true, $limiter->throttle($this->source));
        sleep(1);
        $this->assertEquals(true, $limiter->throttle($this->source));
        sleep(1);
        $this->assertEquals(true, $limiter->throttle($this->source));
    }

    public function testRefill() {
        if (getenv('CI')) {
            $this->markTestSkipped();
            return;
        }
        $limiter = $this->getRateLimiter('testRefill', 1, 1);

        $this->assertEquals(true, $limiter->throttle($this->source));
        sleep(2);
        $this->assertEquals(true, $limiter->throttle($this->source));
    }

    public function testPenalize() {
        if (getenv('CI')) {
            $this->markTestSkipped();
            return;
        }
        $limiter = $this->getRateLimiter('testPenalize', 10, 1);

        $this->assertEquals(true, $limiter->throttle($this->source));
        $limiter->penalize($this->source);
        $this->assertEquals(false, $limiter->throttle($this->source));
    }
}