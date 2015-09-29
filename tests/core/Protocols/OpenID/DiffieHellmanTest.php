<?php

namespace SimpleID\Protocols\OpenID;

class DiffieHellmanTest extends \PHPUnit_Framework_TestCase {
    protected function doTestFunctional($mac_key, $algo) {
        $consumer = new DiffieHellman(NULL, NULL, $algo);
        $server = new DiffieHellman(NULL, NULL, $algo);

        $dh_consumer_public = $consumer->getPublicKey();

        $response = $server->associateAsServer($mac_key, $dh_consumer_public);

        return base64_decode($consumer->associateAsConsumer($response['enc_mac_key'], $response['dh_server_public']));
    }

    public function testSHA1Functional() {
        $mac_key = '12345678901234567890';
        $test_mac_key = $this->doTestFunctional($mac_key, 'sha1');
        $this->assertEquals($mac_key, $test_mac_key);
    }

    public function testSHA256Functional() {
        $mac_key = '123456789012345678901234567890AB';
        $test_mac_key = $this->doTestFunctional($mac_key, 'sha256');
        $this->assertEquals($mac_key, $test_mac_key);
    }

}

?>