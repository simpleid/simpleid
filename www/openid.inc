<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-8
 *
 * Includes code Drupal OpenID module (http://drupal.org/project/openid)
 * Rowan Kerr <rowan@standardinteractive.com>
 * James Walker <james@bryght.com>
 *
 * Copyright (C) Rowan Kerr and James Walker
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
 * $Id$
 */

/**
 * OpenID related functions.
 *
 * @package simpleid
 * @filesource
 */
 
include_once "bignum.inc";
 
/**
 * Diffie-Hellman Key Exchange Default Value
 */
define('OPENID_DH_DEFAULT_MOD', '155172898181473697471232257763715539915724801'.
       '966915404479707795314057629378541917580651227423698188993727816152646631'.
       '438561595825688188889951272158842675419950341258706556549803580104870537'.
       '681476726513255747040765857479291291572334510643245094715007229621094194'.
       '349783925984760375594985848253359305585439638443');

define('OPENID_DH_DEFAULT_GEN', '2');

define('OPENID_SHA1_BLOCKSIZE', 64);

define('OPENID_RAND_SOURCE', '/dev/urandom');

define('OPENID_VERSION_2', 2);
define('OPENID_VERSION_1_1', 1);

define('OPENID_NS_2_0', 'http://specs.openid.net/auth/2.0');
define('OPENID_NS_1_1', 'http://openid.net/signon/1.1');
define('OPENID_NS_1_0', 'http://openid.net/signon/1.0');

define('OPENID_IDENTIFIER_SELECT', 'http://specs.openid.net/auth/2.0/identifier_select');
define('OPENID_RETURN_TO', 'http://specs.openid.net/auth/2.0/return_to');

/**
 * Detects the OpenID version of the current request
 *
 * @param mixed $request the OpenID request
 * @param string $key the key to look for to determine the OpenID
 * version
 * @return int either OPENID_NS_2_0 or OPENID_VERSION_1_1
 *
 */
function openid_get_version($request, $key = 'openid.ns') {
    if (!isset($request[$key])) return OPENID_VERSION_1_1;
    if ($request[$key] != OPENID_NS_2_0) return OPENID_VERSION_1_1;
    return OPENID_VERSION_2;
}

/**
 * Creates a OpenID message for direct response.
 *
 * The response will be encoded using Key-Value Form Encoding. [4.1.1]
 *
 * @param mixed $data the data in the response
 * @param int $version the message version
 * @return string the message in key-value form encoding
 */
function openid_direct_message($data, $version = OPENID_VERSION_2) {
    $encoded = '';
    if ($version == OPENID_VERSION_2) {
        $data['ns'] = OPENID_NS_2_0;
    }
    foreach ($data as $key => $value) {
        if (strpos($key, ':') !== false) {
            return null;
        }
    
        if (strpos($key, "\n") !== false) {
            return null;
        }
    
        if (strpos($value, "\n") !== false) {
            return null;
        }
        $encoded .= "$key:$value\n";
    }
    return $encoded;
}

/**
 * Sends a direct response.
 *
 * @param string $message an OpenID message encoded using Key-Value Form
 * @param string $status the HTTP status to send
 */
function openid_direct_response($message, $status = '200 OK') {
    header("HTTP/1.1 $status");
    header("Content-Type: text/plain");
    print $message;
}

/**
 * Creates a OpenID message for indirect response.
 *
 * The response will be encoded using HTTP Encoding. [4.1.2]
 *
 * @param mixed $data the data in the response
 * @param int $version the message version
 * @return mixed the message
 */
function openid_indirect_message($data, $version = OPENID_VERSION_2) {
    if ($version == OPENID_VERSION_2) {
        return array_merge($data, array('openid.ns' => OPENID_NS_2_0));
    }
    return $data;
}

/**
 * Sends an indirect response to a URL.
 *
 * @param string $url the URL to which the response is to be sent
 * @param mixed $message an OpenID message
 * @param string $response_func the method by which the indirect response is to
 * be sent, either openid_indirect_response_form or openid_indirect_response_redirect
 */
function openid_indirect_response($url, $message, $response_func = 'openid_indirect_response_form') {
    call_user_func($response_func, $url, $message);
}

/**
 * Sends an indirect message via an HTTP redirect
 *
 * @param string $url the URL to which the response is to be sent
 * @param mixed $message an OpenID message
 */ 
function openid_indirect_response_redirect($url, $message) {    
    header('Status: 303 See Other');
    header('Location: ' . openid_indirect_response_url($url, $message));
    exit;
}

/**
 * Encodes an indirect message into a URL
 * @param string $url the URL to which the response is to be sent
 * @param mixed $message an OpenID message
 * @return string the URL to which the response is to be sent, with the
 * encoded message
 */
function openid_indirect_response_url($url, $message) {
    if (is_array($message)) {
        $pairs = array();
        
        foreach ($message as $key => $value) {
            $pairs[] = urlencode($key) . '=' . urlencode($value);
        }
        
        $encoded_message = implode('&', $pairs);
    } else {
        $encoded_message = $message;
    }    
    
    return $url . '?' . $encoded_message;
}

/**
 * Sends an indirect message via an HTML form
 *
 * @param string $url the URL to which the response is to be sent
 * @param mixed $message an OpenID message
 */
function openid_indirect_response_form($url, $message) {
    $html = '<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xml:lang="en-AU" lang="en-AU" xmlns="http://www.w3.org/1999/xhtml"><body>';

    $html .= '<form action="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '" enctype="application/x-www-form-urlencoded" id="redirect"><p>Redirecting...</p>';

    foreach ($message as $key => $value) {
        if ($key) {
            $html .= '<input type="hidden" name="' . htmlspecialchars($key, ENT_QUOTES, 'UTF-8') . '" value="' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '" />';
        }
    }

    $html .= '<noscript><input type="submit" value="Continue" /></noscript>
                <script type="text/javascript">document.getElementById("redirect").submit();</script>
            </form></body></html>';
            
    print $html;
    
    exit;
}

/**
 * Sends a direct message indicating an error.  This is a convenience function
 * for {@link openid_direct_response()}.
 *
 * @param string $error the error message
 * @param array $additional any additional data to be sent with the error
 * message
 * @param int $version the message version
 */
function openid_direct_error($error, $additional = array(), $version = OPENID_VERSION_2) {
    $message = openid_direct_message(array_merge(array('error' => $error), $additional), $version);
    openid_direct_response($message, '400 Bad Request');
}

/**
 * Sends an indirect message indicating an error.  This is a convenience function
 * for {@link openid_indirect_response()}.
 *
 * @param string $url the URL to which the error message is to be sent
 * @param string $error the error message
 * @param array $additional any additional data to be sent with the error
 * message
 * @param int $version the message version
 * @param string $response_func the method by which the indirect response is to
 * be sent, either openid_indirect_response_form or openid_indirect_response_redirect
 */
function openid_indirect_error($url, $error, $additional = array(), $version = OPENID_VERSION_2, $response_func = 'openid_indirect_response_form') {
    $message = openid_indirect_message(array_merge(array('openid.mode'=> 'error', 'openid.error' => $error), $additional), $version);
    openid_indirect_response($url, $message, $response_func);
}

/**
 * Gets the realm from the OpenID request.  This is specified differently
 * depending on the OpenID version.
 *
 * @param mixed $request the OpenID request
 * @param int $version the OpenID version for the message
 * @return string the realm URI
 */
function openid_get_realm($request, $version) {
    if ($version == OPENID_VERSION_1_1) {
        $realm = $request['openid.trust_root'];
    }

    if ($version == OPENID_VERSION_2) {
        $realm = $request['openid.realm'];
    }
    
    if (!$realm) {
        $realm = $request['openid.return_to'];
    }
    
    return $realm;
}


/**
 * Fix PHP's handling of POST data.  PHP changes dots in keys of
 * associative arrays to underscores.
 *
 * @param array &$post the HTTP post data as returned by PHP
 */
function openid_fix_post(&$post) {
    global $ns_to_alias;    
    
    foreach ($post as $key => $value) {
        if (strpos($key, 'openid_') === 0) {
            $fixed_key = str_replace('openid_', 'openid.', $key);
            $fixed_key = str_replace('openid.ns_', 'openid.ns.', $fixed_key);
            
            if (strpos($fixed_key, 'openid.ns.') === 0) {
                $alias = substr($fixed_key, 10);
                $ns_to_alias[$value] = $alias;
            }
            unset($post[$key]);
            $post[$fixed_key] = $value;
        }
    }
    
    $aliases = array_values($ns_to_alias);
    
    foreach ($post as $key => $value) {
        $fixed_key = $key;
        
        foreach ($aliases as $alias) {
            $fixed_key = str_replace('openid.' . $alias . '_', 'openid.' . $alias . '.', $key);
        }
        
        if ($fixed_key != $key) {
            unset($post[$key]);
            $post[$fixed_key] = $value;
        }
    }
}

/**
 * Determine whether a URL matches a realm.
 *
 * A URL matches a realm if:
 *
 * 1. The URL scheme and port of the URL are identical to those in the realm.
 *    See RFC 3986, section 3.1 for rules about URI matching.
 * 2. The URL's path is equal to or a sub-directory of the realm's path.
 * 3. Either:
 *    (a) The realm's domain contains the wild-card characters "*.", and the
 *        trailing part of the URL's domain is identical to the part of the
 *        realm following the "*." wildcard, or
 *    (b) The URL's domain is identical to the realm's domain
 *
 * @param string $url to URL to test
 * @param string $realm the realm
 * @return bool true if the URL matches the realm
 * @since 0.6
 */
function openid_url_matches_realm($url, $realm) {
    $url = parse_url($url);
    $realm = parse_url($realm);
    
    if (array_key_exists('user', $url) || array_key_exists('pass', $url) || array_key_exists('fragment', $url)) return false;
    if (array_key_exists('user', $realm) || array_key_exists('pass', $realm) || array_key_exists('fragment', $realm)) return false;    
    
    if ($url['scheme'] != $realm['scheme']) return false;
    
    if ((!array_key_exists('port', $url)) && (!array_key_exists('port', $realm))) {
        $url['port'] = '';
        $realm['port'] = '';
    }
    if (($url['port'] != $realm['port']))
            return false;
    
    if (substr($realm['host'], 0, 2) == '*.') {
        $realm_re = '/^.*' . preg_quote(substr($realm['host'], 2)) . '$/i';
    } else {
        $realm_re = '/^' . preg_quote($realm['host']) . '$/i';
    }
    
    if (!preg_match($realm_re, $url['host'])) return false;
    
    if ((!array_key_exists('path', $url)) && (!array_key_exists('path', $realm))) {
        $url['path'] = '';
        $realm['path'] = '';
    }
    if (substr($realm['path'], -1) == '/') $realm['path'] = substr($realm['path'], 0, -1);
    if (($url['path'] != $realm['path']) && !preg_match('#^' . preg_quote($realm['path']) . '/.*$#', $url['path'])) return false;
    
    return true;
}

/**
 * Returns the URL of a relying party endpoint for a specified realm.  This URL
 * is used to discover services associated with the realm.
 *
 * If the realm's domain contains the wild-card characters "*.", this is substituted
 * with "www.".
 *
 * @param string $realm the realm
 * @url string the URL
 *
 * @since 0.7
 */
function openid_realm_discovery_url($realm) {
    $parts = parse_url($realm);
    $host = strtr($parts['host'], array('*.' => 'www.'));;
    
    $url = $parts['scheme'] . '://';
    if (isset($parts['user'])) {
        $url .= $parts['user'];
        if (isset($parts['pass'])) $url .= ':' . $parts['pass'];
        $url .= '@';
    }
    $url .= $host;
    if (isset($parts['port'])) $url .= ':' . $parts['port'];
    $url .= $parts['path'];
    if (isset($parts['query'])) $url .= '?' . $parts['query'];
    if (isset($parts['fragment'])) $url .= '#' . $parts['fragment'];
    return $url;
}

/* ------- Random byte and nonce functions ----------------------------------- */
/**
 * Obtains a number of random bytes.  This function uses an entropy source specified
 * in OPENID_RAND_SOURCE.
 *
 * @param int $num_bytes the number of bytes to generate
 * @return string a string containing random bytes
 */
function _openid_get_bytes($num_bytes) {
    static $f = null;
    $bytes = '';
    if ($f === null) {
        if (OPENID_RAND_SOURCE === null) {
            $f = FALSE;
        } else {
            $f = @fopen(OPENID_RAND_SOURCE, "r");
        }
    }
    if ($f === FALSE) {
        $bytes = '';
        for ($i = 0; $i < $num_bytes; $i += 4) {
            $bytes .= pack('L', mt_rand());
        }
        $bytes = substr($bytes, 0, $num_bytes);
    } else {
        $bytes = fread($f, $num_bytes);
    }
    return $bytes;
}

/**
 * Obtains a nonce [10.1]
 *
 * @return string an OpenID nonce
 */
function openid_nonce() {
    return gmstrftime('%Y-%m-%dT%H:%M:%SZ') . bin2hex(_openid_get_bytes(4));
}

/* ------- Diffie-Hellman Key Exchange functions ----------------------------- */

/**
 * Returns the association types supported by this server.
 *
 * @return array an array containing the association types supported by this server as keys
 * and an array containing the key size (mac_size) and HMAC function (hmac_func) as
 * values
 */
function openid_association_types() {
    $association_types = array('HMAC-SHA1' => array('mac_size' => 20, 'hmac_func' => '_openid_hmac_sha1'));
    if (OPENID_SHA256_SUPPORTED) $association_types['HMAC-SHA256'] = array('mac_size' => 32, 'hmac_func' => '_openid_hmac_sha256');
    return $association_types;
}

/**
 * Returns the association types supported by this server and the version of
 * OpenID.
 *
 * OpenID version 1 supports an empty string as the session type.  OpenID version 2
 * reqires a session type to be sent.
 *
 * @param int $version the OpenID version, either OPENID_VERSION_1_1 and OPENID_VERSION_2
 * @return array an array containing the session types supported by this server as keys
 * and an array containing the hash function (hash_func) as
 * values
 */
function openid_session_types($version = OPENID_VERSION_2) {
    $session_types = array(
        'no-encryption' => array(),
        'DH-SHA1' => array('hash_func' => '_openid_sha1'),
    );
    if (OPENID_SHA256_SUPPORTED) $session_types['DH-SHA256'] = array('hash_func' => '_openid_sha256');
    if ($version == OPENID_VERSION_1_1) $session_types[''] = array();
    return $session_types;
}


/**
 * Generates the cryptographic values required for responding to association
 * requests [8.4.2]
 *
 * @param string $mac_key the MAC key, in binary representation
 * @param string $dh_consumer_public the consumer's public key, in Base64 representation
 * @param string $dh_modulus modulus - a large prime number
 * @param string $dh_gen generator - a primitive root modulo
 * @param string $hash_func the hash function
 * @return array an array containing the server's public key (in Base64), and encrypted MAC key
 * (in Base64), encrypted using the Diffie-Hellman shared secret
 */
function openid_dh_server_assoc($mac_key, $dh_consumer_public, $dh_modulus = NULL, $dh_gen = NULL, $hash_func = '_openid_sha1') {
    $shared = openid_dh_generate_public_and_shared_secret($dh_consumer_public, $dh_modulus, $dh_gen);

    return array(
        'dh_server_public' => $shared['dh_server_public'],
        'enc_mac_key' => openid_encrypt_mac_key($shared['ZZ'], $mac_key, $hash_func)
    );
}

/**
 * Generates a public key and a shared secret for Diffie-Hellman key exchange.
 *
 * This is the second step in the Diffle-Hellman key exchange process.  The other
 * party (in OpenID 1.0 terms, the consumer) has already generated the public
 * key ($dh_consumer_public) and sent it to this party (the server).  The Diffie-Hellman
 * modulus ($dh_modulus) and generator ($dh_gen) have either been sent or previously agreed.
 *
 * @param string $dh_consumer_public the consumer's public key, in Base64 representation
 * @param string $dh_modulus modulus, in Base64 representation
 * @param string $dh_gen generator, in Base64 representation
 * @return array an array containing: (a) dh_server_public - the server's public
 * key (in Base64) and (b) ZZ - the shared secret (as a bignum)
 *
 * @link http://www.ietf.org/rfc/rfc2631.txt RFC 2631
 */
function openid_dh_generate_public_and_shared_secret($dh_consumer_public, $dh_modulus = NULL, $dh_gen = NULL) {
    // Decode the consumer's public key
    $y_consumer = _openid_base64_to_bignum($dh_consumer_public);
    
    if ($dh_modulus) {
        $p = _openid_base64_to_bignum($dh_modulus);
    } else {
        //$p = OPENID_DH_DEFAULT_MOD;
        $p = bignum_new(OPENID_DH_DEFAULT_MOD);
    }

    if ($dh_gen) {
        $g = _openid_base64_to_bignum($dh_gen);
    } else {
        //$g = OPENID_DH_DEFAULT_GEN;
        $g = bignum_new(OPENID_DH_DEFAULT_GEN);
    }

    // Generate the server's private key - a random number which is less than p
    $rand = _openid_dh_rand($p);
    $x_server = bignum_add($rand, 1);
    
    // Server's public key is g ^ private mod p
    $y_server = bignum_powmod($g, $x_server, $p);

    // Encode the server's public key
    $dh_server_public = _openid_bignum_to_base64($y_server, 256);

    // Generate the shared secret = consumer's public ^ server's private mod p = server's public ^ consumer's private mod p
    $ZZ = bignum_powmod($y_consumer, $x_server, $p);


    return array(
        'dh_server_public' => $dh_server_public,
        'ZZ' => $ZZ
    );
}

/**
 * Encrypts and encodes the MAC key.
 *
 * @param string $ZZ the Diffie-Hellman key exchange shared secre as a bignum
 * @param string $mac_key a byte stream containing the MAC key
 * @param string $hash_func the hash function
 * @param string the encrypted MAC key in Base64 representation
 */
function openid_encrypt_mac_key($ZZ, $mac_key, $hash_func = '_openid_sha1') {
    // Encrypt the MAC key using the shared secret and the hash function
    $encrypted_mac_key = _openid_xor($ZZ, $mac_key, $hash_func);
    
    // Encode the encrypted MAC key
    $enc_mac_key = base64_encode($encrypted_mac_key);
    
    return $enc_mac_key;
}

/**
 * Encrypts/decrypts using XOR.
 *
 * @param string $key the encryption key as a bignum.  This is usually
 * the shared secret (ZZ) calculated from the Diffie-Hellman key exchange
 * @param string $plain_cipher the plaintext or ciphertext
 * @param string $hash_func the hash function
 * @return string the ciphertext or plaintext
 */
function _openid_xor($key, $plain_cipher, $hash_func = '_openid_sha1') {
    $decoded_key = bignum_val($key, 256);
    $hashed_key = call_user_func($hash_func, $decoded_key);
    
    $cipher_plain = "";
    for ($i = 0; $i < strlen($plain_cipher); $i++) {
        $cipher_plain .= chr(ord($plain_cipher[$i]) ^ ord($hashed_key[$i]));
    }
  
    return $cipher_plain;
}

/**
 * Generates a random integer, which will be used to derive a private key
 * for Diffie-Hellman key exchange.  The integer must be less than $stop
 *
 * @param resource $stop a prime number as a bignum
 * @param resource the random integer as a bignum
 */
function _openid_dh_rand($stop) {
    static $duplicate_cache = array();
  
    // Used as the key for the duplicate cache
    $rbytes = bignum_val($stop, 256);
  
    if (array_key_exists($rbytes, $duplicate_cache)) {
        list($duplicate, $nbytes) = $duplicate_cache[$rbytes];
    } else {
        if ($rbytes[0] == "\x00") {
            $nbytes = strlen($rbytes) - 1;
        } else {
            $nbytes = strlen($rbytes);
        }
    
        $mxrand = bignum_pow(bignum_new(256), $nbytes);

        // If we get a number less than this, then it is in the
        // duplicated range.
        $duplicate = bignum_mod($mxrand, $stop);

        if (count($duplicate_cache) > 10) {
            $duplicate_cache = array();
        }
    
        $duplicate_cache[$rbytes] = array($duplicate, $nbytes);
    }
  
    do {
        $bytes = "\x00" . _openid_get_bytes($nbytes);
        $n = bignum_new($bytes, 256);
        // Keep looping if this value is in the low duplicated range
    } while (bignum_cmp($n, $duplicate) < 0);

    return bignum_mod($n, $stop);
}

/* ------- Arbitary precision arithmetic and conversion functions ------------ */
/**
 * Converts an arbitary precision integer, encoded in Base64, to a bignum
 *
 * @param string $str arbitary precision integer, encoded in Base64
 * @return resource the string representation
 */
function _openid_base64_to_bignum($str) {
    return bignum_new(base64_decode($str), 256);
}

/**
 * Converts a string representation of an integer to an arbitary precision
 * integer, then converts it to Base64 encoding.
 *
 * @param string $str the string representation
 * @return string the Base64 encoded arbitary precision integer
 */
function _openid_bignum_to_base64($str) {
    return base64_encode(bignum_val($str, 256));
}

/**
 * Encode an integer as big-endian signed two's complement binary string.
 * [4.2]
 *
 * @param string $num the binary integer
 * @return string the signed two's complement binary string
 */
function _openid_btwoc($num) {
    return pack('H*', $num);
}

/* ------- Hash and HMAC functions ------------------------------------------- */

/**
 * Sign certain keys in a message
 *
 * @param mixed $association the association containing the signature information
 * @param array $message_array array of entire message about to be sent
 * @param array $keys_to_sign keys in the message to include in signature (without
 * 'openid.' appended)
 * @return string the signature encoded in Base64
 */
function _openid_signature($association, $message_array, $keys_to_sign) {
    $hmac_funcs = array('HMAC-SHA1' => '_openid_hmac_sha1', 'HMAC-SHA256' => '_openid_hmac_sha256');
    
    $hmac_func = $hmac_funcs[$association['assoc_type']];
    
    $signature = '';
    $sign_data = array();

    foreach ($keys_to_sign as $key) {
        if (isset($message_array['openid.' . $key])) {
            $sign_data[$key] = $message_array['openid.' . $key];
        }
    }

    // We set OPENID_VERSION_1_1 because we don't want to sign the namespace header
    $message = openid_direct_message($sign_data, OPENID_VERSION_1_1);
    $secret = base64_decode($association['mac_key']);
    $signature = call_user_func($hmac_func, $secret, $message);

    return base64_encode($signature);
}

/**
 * Obtains the SHA1 hash of a string in binary representation.
 *
 * @param string $text the text to be hashed
 * @return string the hash in binary representation
 */
function _openid_sha1($text) {
    if (function_exists('hash_hmac') && function_exists('hash_algos') && (in_array('sha256', hash_algos()))) {
        return hash('sha1', $text, true);
    } else {
        $hex = sha1($text);
        $raw = '';
        for ($i = 0; $i < 40; $i += 2) {
            $hexcode = substr($hex, $i, 2);
            $charcode = (int) base_convert($hexcode, 16, 10);
            $raw .= chr($charcode);
        }
        return $raw;
    }
}

/**
 * Obtains the keyed hash value using the HMAC method and the SHA1 algorithm
 *
 * @param string $key the key in binary representation
 * @param string $text the text to be hashed
 * @return string the hash in binary representation
 */
function _openid_hmac_sha1($key, $text) {
    if (strlen($key) > OPENID_SHA1_BLOCKSIZE) {
        $key = _openid_sha1($key);
    }

    $key = str_pad($key, OPENID_SHA1_BLOCKSIZE, chr(0x00));
    $ipad = str_repeat(chr(0x36), OPENID_SHA1_BLOCKSIZE);
    $opad = str_repeat(chr(0x5c), OPENID_SHA1_BLOCKSIZE);
    $hash1 = _openid_sha1(($key ^ $ipad) . $text, true);
    $hmac = _openid_sha1(($key ^ $opad) . $hash1, true);
    return $hmac;
}

// Check if SHA-256 support is available
if (function_exists('hash_hmac') && function_exists('hash_algos') && (in_array('sha256', hash_algos()))) {
    
    /**
     * Whether the current installation of PHP supports SHA256.  SHA256 is supported
     * if the hash module is properly compiled and loaded into PHP.
     */
    define('OPENID_SHA256_SUPPORTED', true);
    
    /**
     * Obtains the SHA256 hash of a string in binary representation.
     *
     * @param string $text the text to be hashed
     * @return string $hash the hash in binary representation
     */
    function _openid_sha256($text) {
        return hash('sha256', $text, true);
    }
    
    /**
     * Obtains the keyed hash value using the HMAC method and the SHA256 algorithm
     *
     * @param string $key the key in binary representation
     * @param string $text the text to be hashed
     * @return string the hash in binary representation
     */
    function _openid_hmac_sha256($key, $text) {
        return hash_hmac('sha256', $text, true);
    }
} else {
    /** @ignore */
    define('OPENID_SHA256_SUPPORTED', false);
}


?>