<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2026
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

use \SimpleID\Crypt\Random;


/**
 * A class representing an OpenID association.
 */
class Association {

    const ASSOCIATION_PRIVATE = 2;
    const ASSOCIATION_SHARED = 1;

    /** @var string the association handle */
    private $assoc_handle;

    /** @var string the association type */
    private $assoc_type;

    /** @var string the MAC key */
    private $mac_key;

    /** @var int the time the association was created */
    private $created;

    /** @var bool whether the association created is private under
     * stateless mode */
    private $private = false;


    /**
     * Creates an association for OpenID versions 1 and 2.
     *
     * This function calls {@link DiffieHellman::associateAsServer()} where required, to 
     * generate the cryptographic values required for an association response.
     *
     * @param int $mode either ASSOCIATION_SHARED or ASSOCIATION_PRIVATE
     * @param string $assoc_type a valid OpenID association type
     * @link http://openid.net/specs/openid-authentication-1_1.html#anchor14, http://openid.net/specs/openid-authentication-2_0.html#anchor20
     */
    function __construct($mode = self::ASSOCIATION_SHARED, $assoc_type = 'HMAC-SHA1') {
        $rand = new Random();        
        $assoc_types = self::getAssociationTypes();
        
        $this->assoc_handle = $rand->id();

        $this->assoc_type = $assoc_type;
        $mac_size = $assoc_types[$assoc_type]['mac_size'];
        $this->mac_key = base64_encode($rand->bytes($mac_size));

        $this->created = time();

        if ($mode == self::ASSOCIATION_PRIVATE) $this->private = true;
    }

    /**
     * Returns the association handle.
     *
     * @return string the association handle
     */
    function getHandle() {
        return $this->assoc_handle;
    }

    /**
     * Returns the creation time.
     *
     * @return int the creation time
     */
    function getCreationTime() {
        return $this->created;
    }

    /**
     * Returns whether this is a private association.
     *
     * @return bool true if this is a private association
     */
    function isPrivate() {
        return $this->private;
    }

    /**
     * Creates data an OpenID association response.
     *
     * This function calls {@link SimpleID\Protocols\OpenID\DiffieHellman::assciateAsServer()} where required, to 
     * generate the cryptographic values required for an association response.
     *
     * @param string $session_type a valid OpenID session type
     * @param string $dh_consumer_public for Diffie-Hellman key exchange, the public key of the relying party encoded in Base64
     * @param string $dh_modulus for Diffie-Hellman key exchange, the modulus encoded in Base64
     * @param string $dh_gen for Diffie-Hellman key exchange, g encoded in Base64
     * @return array<string, string> data that can be fed into an OpenID association response
     * @link http://openid.net/specs/openid-authentication-1_1.html#anchor14, http://openid.net/specs/openid-authentication-2_0.html#anchor20
     */
    function getOpenIDResponse($session_type = 'no-encryption', $dh_consumer_public = NULL, $dh_modulus = NULL, $dh_gen = NULL) {        
        $assoc_types = self::getAssociationTypes();
        $session_types = self::getSessionTypes();
        
        $response = [
            'assoc_handle' => $this->assoc_handle,
            'assoc_type' => $this->assoc_type,
        ];
        
        // If $session_type is '', then it must be using OpenID 1.1 (blank parameter
        // is not allowed for OpenID 2.0.  For OpenID 1.1 blank requests, we don't
        // put a session_type in the response.
        if ($session_type != '') $response['session_type'] = $session_type;
        
        if (($session_type == 'no-encryption') || ($session_type == '')) {
            $response['mac_key'] = $this->mac_key;
        } elseif ($session_type == 'DH-SHA1' || $session_type == 'DH-SHA256') {
            $algo = $session_types[$session_type]['algo'];
            $dh = new DiffieHellman($dh_modulus, $dh_gen, $algo);
            
            $result = $dh->associateAsServer(base64_decode($this->mac_key), $dh_consumer_public);
            $response['dh_server_public'] = $result['dh_server_public'];
            $response['enc_mac_key'] = $result['enc_mac_key'];
        }

        return $response;
    }

    /**
     * Calculates a signature of an OpenID message
     *
     * @param Message $message the message to sign
     * @return string the signature encoded in Base64
     */
    function sign($message) {
        $assoc_types = self::getAssociationTypes();
        $signature = '';
        $algo = $assoc_types[$this->assoc_type]['algo'];
        $secret = base64_decode($this->mac_key);
        $signature = hash_hmac($algo, $message->getSignatureBaseString(), $secret, true);

        return base64_encode($signature);
    }

    /**
     * Returns a string representation of the association for debugging purposes
     *
     * @return string a string representation of the association
     */
    function toString() {
        return sprintf('private: %1$s, assoc_handle: %2$s, assoc_type: %3$s', $this->private, $this->assoc_handle, $this->assoc_type);
    }

    /**
     * Returns the association types supported by this server.
     *
     * @return array<string, mixed> an array containing the association types supported by this server as keys
     * and an array containing the key size (mac_size) and HMAC algorithm (algo) as
     * values
     */
    static function getAssociationTypes() {
        $association_types = [ 'HMAC-SHA1' => [ 'mac_size' => 20, 'algo' => 'sha1' ] ];
        if (in_array('sha256', hash_algos())) $association_types['HMAC-SHA256'] = [ 'mac_size' => 32, 'algo' => 'sha256' ];
        return $association_types;
    }

    /**
     * Returns the association types supported by this server and the version of
     * OpenID.
     *
     * OpenID version 1 supports an empty string as the session type.  OpenID version 2
     * reqires a session type to be sent.
     *
     * @param bool $is_https whether the transport layer encryption is used for the current
     * connection
     * @param float $version the OpenID version, either OPENID_VERSION_1_1 and OPENID_VERSION_2
     * @return array<string, mixed> an array containing the session types supported by this server as keys
     * and an array containing the hash function (hash_func) as
     * values
     */
    static function getSessionTypes($is_https = TRUE, $version = Message::OPENID_VERSION_2) {
        $session_types = [
            'DH-SHA1' => [ 'algo' => 'sha1' ],
        ];
        if (in_array('sha256', hash_algos())) $session_types['DH-SHA256'] = [ 'algo' => 'sha256' ];
        if (($version >= Message::OPENID_VERSION_2) && ($is_https == TRUE)) {
            // Under OpenID 2.0 no-encryption is only allowed if TLS is used
            $session_types['no-encryption'] = [];
        }
        if ($version == Message::OPENID_VERSION_1_1) $session_types[''] = [];
        return $session_types;
    }
}

?>