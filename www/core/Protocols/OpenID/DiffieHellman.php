<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2023
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
 * 
 */

namespace SimpleID\Protocols\OpenID;

use \SimpleID\Crypt\BigNum;
use \SimpleID\Crypt\Random;

/**
 * OpenID default modulus for Diffie-Hellman key exchange.
 *
 * @link http://openid.net/specs/openid-authentication-1_1.html#pvalue, http://openid.net/specs/openid-authentication-2_0.html#pvalue
 */
define('OPENID_DH_DEFAULT_MOD', '155172898181473697471232257763715539915724801'.
       '966915404479707795314057629378541917580651227423698188993727816152646631'.
       '438561595825688188889951272158842675419950341258706556549803580104870537'.
       '681476726513255747040765857479291291572334510643245094715007229621094194'.
       '349783925984760375594985848253359305585439638443');

/**
 * OpenID default generator for Diffie-Hellman key exchange.
 */
define('OPENID_DH_DEFAULT_GEN', '2');

/**
 * A class for Diffie-Hellman key exchange.
 */
class DiffieHellman {

    /** @var BigNum the private key */
    private $x;

    /** @var BigNum the public key */
    private $y;

    /** @var BigNum the modulus - a large prime number */
    protected $p;

    /** @var BigNum the generator - a primitive root modulo */
    protected $g;

    /** @var string the hashing algorithm */
    protected $algo;

    /**
     * Creates a new instance.
     *
     * The modulus and generator are specified in the $dh_modulus and $dh_gen
     * parameters.  If these are set to NULL, the default from the OpenID
     * specification are used.
     *
     * @param string $dh_modulus modulus 
     * @param string $dh_gen generator 
     * @param string $algo the hashing algorithm
     */
    function __construct($dh_modulus = NULL, $dh_gen = NULL, $algo = 'sha1') {
        if ($dh_modulus != NULL) {
            $this->p = new BigNum(base64_decode($dh_modulus), 256);
        } else {
            $this->p = new BigNum(OPENID_DH_DEFAULT_MOD);
        }

        if ($dh_gen != NULL) {
            $this->g = new BigNum(base64_decode($dh_gen), 256);
        } else {
            $this->g = new BigNum(OPENID_DH_DEFAULT_GEN);
        }

        $this->algo = $algo;

        $this->generateKeyPair();
    }


    /**
     * Generates the cryptographic values required for responding to association
     * requests
     *
     * This involves generating a key pair for the OpenID provider, then calculating
     * the shared secret.  The shared secret is then used to encrypt the MAC key.
     *
     * @param string $mac_key the MAC key, in binary representation
     * @param string $dh_consumer_public the consumer's public key, in Base64 representation
     * @return array<string, string> an array containing (a) dh_server_public - the server's public key (in Base64), and (b)
     * enc_mac_key encrypted MAC key (in Base64), encrypted using the Diffie-Hellman shared secret
     */
    public function associateAsServer($mac_key, $dh_consumer_public) {        
        // Generate the shared secret
        $ZZ = $this->getSharedSecret($dh_consumer_public);

        return [
            'dh_server_public' => $this->getPublicKey(),
            'enc_mac_key' => $this->cryptMACKey($ZZ, $mac_key)
        ];
    }

    /**
     * Complete association by obtaining the session MAC key from the key obtained
     * from the Diffie-Hellman key exchange
     *
     * @param string $enc_mac_key the encrypted session MAC key, in Base64 represnetation
     * @param string $dh_server_public the server's public key, in Base64 representation
     * @return string the decrypted session MAC key, in Base64 representation
     */
    public function associateAsConsumer($enc_mac_key, $dh_server_public) {
        // Retrieve the shared secret
        $ZZ = $this->getSharedSecret($dh_server_public);
        
        // Decode the encrypted MAC key
        $encrypted_mac_key = base64_decode($enc_mac_key);
        
        return $this->cryptMACKey($ZZ, $encrypted_mac_key);
    }

    /**
     * Returns the public key.
     *
     * @return string the public key in Base64
     */
    public function getPublicKey() {
        $key = $this->y->val(256);
        assert($key != false);
        return base64_encode($key);
    }

    /**
     * Calculates the shared secret for Diffie-Hellman key exchange.
     *
     * This is the second step in the Diffle-Hellman key exchange process.  The other
     * party (in OpenID 1.0 terms, the consumer) has already generated the public
     * key ($dh_consumer_public) and sent it to this party (the server).
     *
     * @param string $their_public the other party's public key, in Base64 representation
     * @return BigNum the shared secret
     *
     * @see generateKeyPair()
     * @link http://www.ietf.org/rfc/rfc2631.txt RFC 2631
     */
    protected function getSharedSecret($their_public) {
        // Decode the keys
        $their_y = new BigNum(base64_decode($their_public), 256);

        // Generate the shared secret = their public ^ my private mod p = my public ^ their private mod p
        $ZZ = $their_y->powmod($this->x, $this->p);

        return $ZZ;
    }

    /**
     * Encrypts/decrypts and encodes the MAC key.
     *
     * @param BigNum $ZZ the Diffie-Hellman key exchange shared secret as a bignum
     * @param string $mac_key a byte stream containing the MAC key
     * @return string the encrypted MAC key in Base64 representation
     */
    protected function cryptMACKey($ZZ, $mac_key) {
        // Encrypt/decrypt the MAC key using the shared secret and the hash function
        $encrypted_mac_key = $this->xorCrypt($ZZ, $mac_key);
        
        // Encode the encrypted/decrypted MAC key
        $enc_mac_key = base64_encode($encrypted_mac_key);
        
        return $enc_mac_key;
    }

    /**
     * Encrypts/decrypts using XOR.
     *
     * @param BigNum $key the encryption key.  This is usually
     * the shared secret (ZZ) calculated from the Diffie-Hellman key exchange
     * @param string $plain_cipher the plaintext or ciphertext
     * @return string the ciphertext or plaintext
     */
    protected function xorCrypt($key, $plain_cipher) {
        $keystream = $key->val(256);
        assert($keystream != false);
        $hashed_key = hash($this->algo, $keystream, true);
        
        $cipher_plain = "";
        for ($i = 0; $i < strlen($plain_cipher); $i++) {
            $cipher_plain .= chr(ord($plain_cipher[$i]) ^ ord($hashed_key[$i]));
        }
      
        return $cipher_plain;
    }

    /**
     * Generates a key pair for Diffie-Hellman key exchange.
     *
     * @return void
     */
    private function generateKeyPair() {
        // Generate the private key - a random number which is less than p
        $rand = $this->generateRandom($this->p);
        $this->x = $rand->add(new BigNum(1));
        
        // Calculate the public key is g ^ private mod p
        $this->y = $this->g->powmod($this->x, $this->p);
    }

    /**
     * Generates a random integer, which will be used to derive a private key
     * for Diffie-Hellman key exchange.  The integer must be less than $stop
     *
     * @param BigNum $stop a prime number as a bignum
     * @return BigNum the random integer as a bignum
     */
    private function generateRandom($stop) {
        static $duplicate_cache = [];
        $rand = new Random();
      
        // Used as the key for the duplicate cache
        $rbytes = $stop->val(256);
        assert($rbytes != false);
      
        if (array_key_exists($rbytes, $duplicate_cache)) {
            list($duplicate, $nbytes) = $duplicate_cache[$rbytes];
        } else {
            if ($rbytes[0] == "\x00") {
                $nbytes = strlen($rbytes) - 1;
            } else {
                $nbytes = strlen($rbytes);
            }
        
            $mxrand = new BigNum(256);
            $mxrand = $mxrand->pow($nbytes);

            // If we get a number less than this, then it is in the
            // duplicated range.
            $duplicate = $mxrand->mod($stop);

            if (count($duplicate_cache) > 10) {
                $duplicate_cache = [];
            }
        
            $duplicate_cache[$rbytes] = [ $duplicate, $nbytes ];
        }
      
        do {
            $bytes = "\x00" . $rand->bytes($nbytes);
            $n = new BigNum($bytes, 256);
            // Keep looping if this value is in the low duplicated range
        } while ($n->cmp($duplicate) < 0);

        return $n->mod($stop);
    }
}

?>