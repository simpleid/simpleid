<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2012-2023
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

namespace SimpleID\Protocols\Connect;

use \Base;
use SimpleID\Crypt\Random;
use SimpleID\Util\ArrayWrapper;
use SimpleJWT\JWT;
use SimpleJWT\JWE;
use SimpleJWT\Crypt\AlgorithmFactory;
use SimpleJWT\Crypt\CryptException;

/**
 * A class representing a JWT response, which can be signed and/or
 * encrypted.
 *
 * The exact format of the response is determined by the configuration
 * of the specified client.
 *
 * This class is a subclass of {@link ArrayWrapper}.  Token claims
 * are stored in {@link ArrayWrapper->$container} and are accessed
 * using array syntax.  Token headers are set using the {@link setHeaders()}
 * and {@link setHeader()} methods.
 */
class JOSEResponse extends ArrayWrapper {
    /** @var string */
    protected $issuer;

    /** @var \SimpleID\Protocols\OAuth\OAuthClient */
    protected $client;

    /** @var string */
    protected $signed_response_alg = null;

    /** @var string */
    protected $encrypted_response_alg = null;

    /** @var string */
    protected $encrypted_response_enc = null;

    /** @var array<string, string> */
    protected $headers = [];

    /**
     * Creates a response.
     *
     * `$path_prefix` is used to construct paths to the configuration variables, which
     * are then accessed using {@link ArrayWrapper::pathGet()}.  For example, if
     * `$path_prefix` is `connect.userinfo`, then this will configure the JOSE
     * algorithms using the following paths:
     *
     * - `connect.userinfo_signed_response_alg`
     * - `connect.userinfo_encrypted_response_alg`
     * - `connect.userinfo_encrypted_response_enc`
     *
     * @param string $issuer the issuer ID
     * @param \SimpleID\Protocols\OAuth\OAuthClient $client the OAuth client to which the response
     * will be sent
     * @param string $path_prefix the prefix from which paths will be formed and passed
     * to {@link ArrayWrapper::get()} to get the client configuration
     * @param array<string, mixed> $data the initial claims
     * @param string $default_signed_response_alg the default `_signed_response_alg` value
     * if the client configuration is not found
     */
    function __construct($issuer, $client, $path_prefix, $data = [], $default_signed_response_alg = null) {
        parent::__construct($data);
        $this->issuer = $issuer;
        $this->client = $client;
        
        if ($this->client->exists($path_prefix . '_signed_response_alg')) {
            $this->signed_response_alg = $this->client->get($path_prefix . '_signed_response_alg');
        } elseif ($default_signed_response_alg != null) {
            $this->signed_response_alg = $default_signed_response_alg;
        }

        if ($this->client->exists($path_prefix . '_encrypted_response_alg')) {
            $this->encrypted_response_alg = $this->client->get($path_prefix . '_encrypted_response_alg');
            if ($this->client->exists($path_prefix . '_encrypted_response_enc')) {
                $this->encrypted_response_enc = $this->client->get($path_prefix . '_encrypted_response_enc');
            } else {
                $this->encrypted_response_enc = 'A128CBC-HS256';
            }
        }
    }

    /**
     * Sets the headers for the JWT, overwriting all existing headers.
     *
     * @param array<string, string> $headers the headers to set
     * @return void
     */
    function setHeaders($headers) {
        $this->headers = $headers;
    }

    /**
     * Sets a specified header for the JWT.
     *
     * @param string $header the header to set
     * @param string $value the header value
     * @return void
     */
    function setHeader($header, $value) {
        $this->headers[$header] = $value;
    }

    /**
     * Sets a claim to be the short hash of a particular value.
     *
     * The OpenID Connect specification requires, in certain circumstances, the
     * short hash of OAuth response parameters to be included in an ID token.
     * This function calculates the short hash of the OAuth response parameter
     * (specified in `$value`) and places it as a claim with a name specified
     * by `$claim`.  Normally `$claim` will be `c_hash` or `at_hash` and `$value`
     * will be the authorisation code or access token respectively.
     *
     * The short hash is the left-most half of the hash, with the hash algorithm
     * being the one underlying the signature algorithm.  For instance, if the signature
     * algorithm is RS256, the underlying hash algorithm is SHA-256, and this function
     * will return the encoded value of the left-most 128 bits of the SHA-256 hash.
     *
     * @param string $claim the name of the claim
     * @param string $value the value over which the short hash to be calculated
     * @return void
     */
    function setShortHashClaim($claim, $value) {
        $alg = ($this->signed_response_alg) ? $this->signed_response_alg : 'HS256';

        try {
            /** @var \SimpleJWT\Crypt\Signature\SignatureAlgorithm $signer */
            $signer = AlgorithmFactory::create($alg);
            $this->container[$claim] = $signer->shortHash($value);
        } catch (\UnexpectedValueException $e) {
            // Do nothing
        }
    }

    /**
     * Renders the response.
     *
     * This function calls the {@link buildJOSE()} method to get the response
     * body, then renders it with the appropriate HTTP headers.
     *
     * @param \SimpleJWT\Keys\KeySet $set the key set to be passed to the
     * {@link buildJOSE()} method.
     * @return void
     */
    function render($set = null) {
        $jose = $this->buildJOSE($set);

        if ($jose == null) {
            $f3 = Base::instance();
            $f3->status(500);
        } else {
            header('Content-Type: application/' . $this->getType());
            print $this->buildJOSE($set);
        }        
    }

    /**
     * Builds the JOSE response.  This will return one of the following:
     *
     * - A JSON encoded string, if {@link $signed_response_alg} and
     *   {@link $encrypted_response_alg} are both null
     * - A signed JWT (JWS), if {@link $signed_response_alg} is set
     * - A JWE containing a nested JWT, if both {@link $signed_response_alg}
     *   and {@link $encrypted_response_alg} are set
     *
     * @param \SimpleJWT\Keys\KeySet $set the key set used to sign and/or
     * encrypt the token.  If set to null, the default set of keys
     * configured for the client and the server are loaded
     * @return string|null the response body
     */
    function buildJOSE($set = null) {
        $rand = new Random();
        $typ = $this->getType();

        if ($typ == 'json') {
            $json = json_encode($this->container);
            if ($json == false) return null;
            return $json;
        }
        
        if ($set == null) {
            $builder = new KeySetBuilder($this->client);
            $set = $builder->addClientSecret()->addClientPublicKeys()->addServerPrivateKeys()->toKeySet();
        }

        $headers = array_merge($this->headers, [ 'alg' => $this->signed_response_alg ]);
        $claims = array_merge($this->container, [
            'iss' => $this->issuer,
            'aud' => $this->client->getStoreID(),
            'jti' => $rand->id()
        ]);

        $jwt = new JWT($headers, $claims);
        try {
            $token = $jwt->encode($set);
        } catch (CryptException $e) {
            return null;
        }

        if ($typ == 'jwt') return $token;

        $headers = [
            'alg' => $this->encrypted_response_alg,
            'enc' => $this->encrypted_response_enc,
            'cty' => 'JWT'
        ];

        $jwe = new JWE($headers, $token);
        try {
            return $jwe->encrypt($set);
        } catch (CryptException $e) {
            return null;
        }
    }

    /**
     * Determines the type of response body.  This type can be appended
     * to `application/` to form a proper MIME media type.
     *
     * @return string the type
     */
    protected function getType() {
        if (($this->encrypted_response_enc != null) && ($this->encrypted_response_alg != null)) {
            return 'jwe';
        } elseif ($this->signed_response_alg != null) {
            return 'jwt';
        } else {
            return 'json';
        }
    }
}
?>
