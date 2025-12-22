<?php

namespace SimpleID\Models;

use PHPUnit\Framework\TestCase;

class UserTest extends TestCase {
    protected function createUser() {
        return new User([
            'userinfo' => [
                'name' => 'Foo'
            ],
            'openid' => [
                'identity' => 'https://example.com/openid/identity'
            ]
        ]);
    }

    protected function createUserCfg() {
        $user_cfg = new User([]);

        // Set up $user_cfg->clients
        $user_cfg->clients['test_cid'] = [
            'store_id' => 'test_cid',
            'consents' => [ 'oauth' => ['openid'] ]
        ];

        // Set up $user_cfg->activities
        $refl = new \ReflectionClass($user_cfg);
        $activities_property = $refl->getProperty('activities');
        $activities_property->setAccessible(true);
        $activities_property->setValue($user_cfg, [
            'test_cid' => [
                'type' => 'app'
            ]
        ]);

        return $user_cfg;
    }

    public function testLoadData() {
        $user = $this->createUser();
        $user_cfg = $this->createUserCfg();

        $user->loadData($user_cfg);

        $this->assertContains('openid', $user->clients['test_cid']['consents']['oauth']);

        $activities = $user->getActivities();
        $this->assertEquals('app', $activities['test_cid']['type']);
    }
}

?>