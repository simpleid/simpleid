<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-10
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
 
include_once "bignum.inc.php";
include_once "random.inc.php";
 
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

/** Constant for the global variable {@link $version} */
define('OPENID_VERSION_2', 2);
/** Constant for the global variable {@link $version} */
define('OPENID_VERSION_1_1', 1);

/** Constant for OpenID namespace */
define('OPENID_NS_2_0', 'http://specs.openid.net/auth/2.0');
/** Constant for OpenID namespace */
define('OPENID_NS_1_1', 'http://openid.net/signon/1.1');
/** Constant for OpenID namespace */
define('OPENID_NS_1_0', 'http://openid.net/signon/1.0');

/**
 * Constant for the OP-local identifier which indicates that SimpleID should choose an identifier
 *
 * @link http://openid.net/specs/openid-authentication-2_0.html#anchor27
 */
define('OPENID_IDENTIFIER_SELECT', 'http://specs.openid.net/auth/2.0/identifier_select');
/** Constant for the XRDS service type for return_to verification */
define('OPENID_RETURN_TO', 'http://specs.openid.net/auth/2.0/return_to');

/** Parameter for {@link openid_indirect_response_url()} */
define('OPENID_RESPONSE_QUERY', 0);
/** Parameter for {@link openid_indirect_response_url()} */
define('OPENID_RESPONSE_FRAGMENT', 1);

/**
 * A mapping of Type URIs of OpenID extnesions to aliases provided in an OpenID
 * request.
 *
 * @global array $openid_ns_to_alias
 */
$openid_ns_to_alias = array("http://openid.net/extensions/sreg/1.1" => "sreg"); // For sreg 1.0 compatibility


/**
 * Detects the OpenID version of the current request
 *
 * @param mixed $request the OpenID request
 * @param string $key the key to look for to determine the OpenID
 * version
 * @return float either OPENID_VERSION_2 or OPENID_VERSION_1_1
 * @see $version
 *
 */
function openid_get_version($request, $key = 'openid.ns')
{
    if (!isset($request[$key])) {
        return OPENID_VERSION_1_1;
    }
    if ($request[$key] != OPENID_NS_2_0) {
        return OPENID_VERSION_1_1;
    }
    return OPENID_VERSION_2;
}

/**
 * Creates a OpenID message for direct response.
 *
 * The response will be encoded using Key-Value Form Encoding.
 *
 * @param array $data the data in the response
 * @param float $version the message version
 * @return string the message in key-value form encoding
 * @link http://openid.net/specs/openid-authentication-1_1.html#anchor32, http://openid.net/specs/openid-authentication-2_0.html#kvform
 */
function openid_direct_message($data, $version = OPENID_VERSION_2)
{
    $message = '';
    $ns = '';
    
    // Add namespace for OpenID 2
    if ($version == OPENID_VERSION_2) {
        $ns = OPENID_NS_2_0;
    }
    if (($ns != '') && !isset($data['ns'])) {
        $data['ns'] = $ns;
    }
    
    foreach ($data as $key => $value) {
        // Filter out invalid characters
        if (strpos($key, ':') !== false) {
            return null;
        }
        if (strpos($key, "\n") !== false) {
            return null;
        }
        if (strpos($value, "\n") !== false) {
            return null;
        }
        
        $message .= "$key:$value\n";
    }
    return $message;
}

/**
 * Sends a direct response.
 *
 * @param string $message an OpenID message encoded using Key-Value Form
 * @param string $status the HTTP status to send
 */
function openid_direct_response($message, $status = '200 OK')
{
    if (substr(PHP_SAPI, 0, 3) === 'cgi') {
        header("Status: $status");
    } else {
        header($_SERVER['SERVER_PROTOCOL'] . ' ' . $status);
    }
    
    header("Content-Type: text/plain");
    print $message;
}

/**
 * Creates a OpenID message for indirect response.
 *
 * The response will be encoded using HTTP Encoding.
 *
 * @param array $data the data in the response
 * @param float $version the message version
 * @return array the message
 * @link http://openid.net/specs/openid-authentication-2_0.html#indirect_comm
 */
function openid_indirect_message($data, $version = OPENID_VERSION_2)
{
    $ns = '';
    
    // Add namespace for OpenID 2
    if ($version == OPENID_VERSION_2) {
        $ns = OPENID_NS_2_0;
    }
    if (($ns != '') && !isset($data['openid.ns'])) {
        $data['openid.ns'] = $ns;
    }
    
    return $data;
}

/**
 * Sends an indirect response to a URL.
 *
 * The indirect message is encoded in the URL and returned to the user agent using
 * a HTTP redirect response.  The message can be encoded in either the query component
 * or the fragment component of the URL.
 *
 * @param string $url the URL to which the response is to be sent
 * @param array|string $message an OpenID message, which can either be an array of keys
 * and values, or a URL-encoded query string
 * @param int $component the component of the URL in which the indirect message is
 * encoded, either OPENID_RESPONSE_QUERY or OPENID_RESPONSE_FRAGMENT
 */
function openid_indirect_response($url, $message, $component = OPENID_RESPONSE_QUERY)
{
    if (substr(PHP_SAPI, 0, 3) === 'cgi') {
        header('Status: 303 See Other');
    } else {
        header($_SERVER['SERVER_PROTOCOL'] . ' 303 See Other');
    }

    header('Location: ' . openid_indirect_response_url($url, $message, $component));
    exit;
}

/**
 * Encodes an indirect message into a URL
 *
 * @param string $url the URL to which the response is to be sent
 * @param array|string $message an OpenID message, which can either be an array of keys
 * and values, or a URL-encoded query string
 * @param int $component the component of the URL in which the indirect message is
 * encoded, either OPENID_RESPONSE_QUERY or OPENID_RESPONSE_FRAGMENT
 * @return string the URL to which the response is to be sent, with the
 * encoded message
 */
function openid_indirect_response_url($url, $message, $component = OPENID_RESPONSE_QUERY)
{
    // 1. Firstly, get the query string
    $query = '';
    
    if (is_array($message)) {
        $query = openid_urlencode_message($message);
    } else {
        $query = $message;
    }
    
    // 2. If there is no query string, then we just return the URL
    if (!$query) {
        return $url;
    }
    
    // 3. The URL may already have a query and a fragment.  If this is so, we
    //    need to slot in the new query string properly.  We disassemble and
    //    reconstruct the URL.
    $parts = parse_url($url);
    
    $url = $parts['scheme'] . '://';
    if (isset($parts['user'])) {
        $url .= $parts['user'];
        if (isset($parts['pass'])) {
            $url .= ':' . $parts['pass'];
        }
        $url .= '@';
    }
    $url .= $parts['host'];
    if (isset($parts['port'])) {
        $url .= ':' . $parts['port'];
    }
    if (isset($parts['path'])) {
        $url .= $parts['path'];
    }
    
    if (($component == OPENID_RESPONSE_QUERY) || (strpos($url, '#') === false)) {
        $url .= '?' . ((isset($parts['query'])) ? $parts['query'] . '&' : '') . $query;
        if (isset($parts['fragment'])) {
            $url .= '#' . $parts['fragment'];
        }
    } elseif ($component == OPENID_RESPONSE_FRAGMENT) {
        // In theory $parts['fragment'] should be an empty string, but the
        // current draft specification does not prohibit putting other things
        // in the fragment.
        
        if (isset($parts['query'])) {
            $url .= '?' . $parts['query'] . '#' . $parts['fragment'] . '&' . $query;
        } else {
            $url .= '#' . $parts['fragment'] . '?' . $query;
        }
    }
    return $url;
}

/**
 * Encodes a message in application/x-www-form-urlencoded format.
 *
 * @param array $message the OpenID message to encode
 * @return string the encoded message
 * @since 0.8
 */
function openid_urlencode_message($message)
{
    $pairs = array();
    
    foreach ($message as $key => $value) {
        $pairs[] = $key . '=' . rfc3986_urlencode($value);
    }
        
    return implode('&', $pairs);
}

/**
 * Sends a direct message indicating an error.  This is a convenience function
 * for {@link openid_direct_response()}.
 *
 * @param string $error the error message
 * @param array $additional any additional data to be sent with the error
 * message
 * @param float $version the message version
 */
function openid_direct_error($error, $additional = array(), $version = OPENID_VERSION_2)
{
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
 * @param float $version the message version
 * @param int $component the component of the URL in which the indirect message is
 * encoded, either OPENID_RESPONSE_QUERY or OPENID_RESPONSE_FRAGMENT
 */
function openid_indirect_error($url, $error, $additional = array(), $version = OPENID_VERSION_2, $component = OPENID_RESPONSE_QUERY)
{
    $message = openid_indirect_message(array_merge(array('openid.mode'=> 'error', 'openid.error' => $error), $additional), $version);
    openid_indirect_response($url, $message, $component);
}

/**
 * Gets the realm from the OpenID request.  This is specified differently
 * depending on the OpenID version.
 *
 * @param mixed $request the OpenID request
 * @param float $version the OpenID version for the message
 * @return string the realm URI
 */
function openid_get_realm($request, $version)
{
    if ($version == OPENID_VERSION_1_1) {
        $realm = $request['openid.trust_root'];
    }

    if ($version >= OPENID_VERSION_2) {
        $realm = $request['openid.realm'];
    }
    
    if (!$realm) {
        $realm = $request['openid.return_to'];
    }
    
    return $realm;
}

/**
 * Parses a direct message.
 *
 * @param string $message the direct message to parse
 * @return array an array containing the parsed key-value pairs
 *
 * @since 0.7
 */
function openid_parse_direct_message($message)
{
    $data = array();

    $items = explode("\n", $message);
    foreach ($items as $item) {
        list ($key, $value) = explode(':', $item, 2);
        $data[$key] = $value;
    }

    return $data;
}

/**
 * Parses a query string.
 *
 * Query strings can be used to receive OpenID indirect messages.
 *
 * @param string $query the query string to parse
 * @return array an array containing the parsed key-value pairs
 *
 * @since 0.7
 */
function openid_parse_query($query)
{
    $data = array();
    
    if ($query === null) {
        return array();
    }
    if ($query === '') {
        return array();
    }
    
    $pairs = explode('&', $query);
    
    foreach ($pairs as $pair) {
        list ($key, $value) = explode('=', $pair, 2);
        $data[$key] = urldecode($value);
    }

    return $data;
}

/**
 * Parses the OpenID request to extract namespace information.
 *
 * This function builds a map between namespace aliases and their Type URIs.
 *
 * @param array $request the OpenID request
 */
function openid_parse_request($request)
{
    global $openid_ns_to_alias;
    
    foreach ($request as $key => $value) {
        if (strpos($key, 'openid.ns.') === 0) {
            $alias = substr($key, 10);
            $openid_ns_to_alias[$value] = $alias;
        }
    }
}

/**
 * Determines whether a URL matches a realm.
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
function openid_url_matches_realm($url, $realm)
{
    $url = parse_url($url);
    $realm = parse_url($realm);
    
    foreach (array('user', 'pass', 'fragment') as $key) {
        if (array_key_exists($key, $url) || array_key_exists($key, $realm)) {
            return false;
        }
    }
    
    if ($url['scheme'] != $realm['scheme']) {
        return false;
    }
    
    if (!isset($url['port'])) {
        $url['port'] = '';
    }
    if (!isset($realm['port'])) {
        $realm['port'] = '';
    }
    if (($url['port'] != $realm['port'])) {
        return false;
    }
    
    if (substr($realm['host'], 0, 2) == '*.') {
        $realm_re = '/^([^.]+\.)?' . preg_quote(substr($realm['host'], 2)) . '$/i';
    } else {
        $realm_re = '/^' . preg_quote($realm['host']) . '$/i';
    }
    
    if (!preg_match($realm_re, $url['host'])) {
        return false;
    }
    
    if (!isset($url['path'])) {
        $url['path'] = '';
    }
    if (!isset($realm['path'])) {
        $realm['path'] = '';
    }
    if (substr($realm['path'], -1) == '/') {
        $realm['path'] = substr($realm['path'], 0, -1);
    }
    if (($url['path'] != $realm['path']) && !preg_match('#^' . preg_quote($realm['path']) . '/.*$#', $url['path'])) {
        return false;
    }
    
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
function openid_realm_discovery_url($realm)
{
    $parts = parse_url($realm);
    $host = strtr($parts['host'], array('*.' => 'www.'));
    ;
    
    $url = $parts['scheme'] . '://';
    if (isset($parts['user'])) {
        $url .= $parts['user'];
        if (isset($parts['pass'])) {
            $url .= ':' . $parts['pass'];
        }
        $url .= '@';
    }
    $url .= $host;
    if (isset($parts['port'])) {
        $url .= ':' . $parts['port'];
    }
    if (isset($parts['path'])) {
        $url .= $parts['path'];
    }
    if (isset($parts['query'])) {
        $url .= '?' . $parts['query'];
    }
    if (isset($parts['fragment'])) {
        $url .= '#' . $parts['fragment'];
    }
    return $url;
}

/**
 * Verifies a return_to URL against the actual URL of the HTTP request.
 *
 * The return_to URL matches if:
 *
 * - The URL scheme, authority, and path are the same; and
 * - Any query parameters that are present in the return_to URL are also present
 *   with the same values in the actual request.
 *
 * @param string $return_to the URL specified in the openid.return_to parameter
 * @param string $actual_url the actual URL requested
 * @return bool true if the URLs match
 *
 * @since 0.7
 */
function openid_verify_return_to($return_to, $actual_url)
{
    $expected = parse_url($return_to);
    $actual = parse_url($actual_url);
    
    // Schemes are case insensitive
    if (strtoupper($expected['scheme']) != strtoupper($actual['scheme'])) {
        return false;
    }
    
    // Hosts are case insensitive
    if (strtoupper($expected['host']) != strtoupper($actual['host'])) {
        return false;
    }
    
    if (!isset($expected['port'])) {
        $expected['port'] = '';
    }
    if (!isset($actual['port'])) {
        $actual['port'] = '';
    }
    if ($expected['port'] != $actual['port']) {
        return false;
    }
    
    if (!isset($expected['path'])) {
        $expected['path'] = '';
    }
    if (!isset($actual['path'])) {
        $actual['path'] = '';
    }
    if ($expected['path'] != $actual['path']) {
        return false;
    }
    
    if ($expected['query']) {
        $expected_query = openid_parse_query($expected['query']);
        $actual_query = openid_parse_query($actual['query']);
        
        foreach ($expected_query as $key => $value) {
            if (!array_key_exists($key, $actual_query)) {
                return false;
            }
            if ($value != $actual_query[$key]) {
                return false;
            }
        }
    }
    
    return true;
}

/**
 * Filters an OpenID request to find keys specific to an extension, as specified
 * by the Type URI.
 *
 * For exmaple, if the extension has the Type URI http://example.com/ and the
 * alias example, this function will return an array of all the keys in the
 * OpenID request which starts with openid.example
 *
 * @param string $ns the Type URI of the extension
 * @param array $request the OpenID request
 * @return array the filtered request, with the prefix (in the example above,
 * openid.example.) stripped in the keys.
 */
function openid_extension_filter_request($ns, $request)
{
    global $openid_ns_to_alias;
    
    if (!isset($openid_ns_to_alias[$ns])) {
        return array();
    }
    
    $alias = $openid_ns_to_alias[$ns];
    $return = array();
    
    if (is_array($request)) {
        foreach ($request as $key => $value) {
            if ($key == 'openid.' . $alias) {
                $return['#default'] = $value;
            }
            if (strpos($key, 'openid.' . $alias . '.') === 0) {
                $return[substr($key, strlen('openid.' . $alias . '.'))] = $value;
            }
        }
    }
    
    return $return;
}

/**
 * Determines whether an extension is present in an OpenID request.
 *
 * @param string $ns the Type URI of the extension
 * @param array $request the OpenID request
 * @return bool true if the extension is present in the request
 */
function openid_extension_requested($ns, $request)
{
    global $openid_ns_to_alias;
    
    if (!isset($openid_ns_to_alias[$ns])) {
        return false;
    }
    $alias = $openid_ns_to_alias[$ns];
    
    if (is_array($request)) {
        foreach ($request as $key => $value) {
            if ((strpos($key, 'openid.' . $alias . '.') === 0) || (strpos($key, 'openid.' . $alias . '=') === 0)) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Returns the OpenID alias for an extension, given a Type URI, based on the
 * alias definitions in the current OpenID request.
 *
 * @param string $ns the Type URI
 * @param bool|string $create whether to create an alias if the Type URI does not already
 * have an alias in the current OpenID request.  If this parameter is a string,
 * then the string specified is the preferred alias to be created, unless a collision
 * occurs
 * @return string the alias, or NULL if the Type URI does not already
 * have an alias in the current OpenID request <i>and</i> $create is false
 */
function openid_extension_alias($ns, $create = false)
{
    global $openid_ns_to_alias;
    static $e = 1;
    
    if (isset($openid_ns_to_alias[$ns])) {
        return $openid_ns_to_alias[$ns];
    }
    if ($create !== false) {
        if ($create === true) {
            $alias = 'e' . $e;
            $e++;
        } elseif (is_string($create)) {
            $used_aliases = array_values($openid_ns_to_alias);
        
            $alias = $create;
            $i = 0;
        
            while (in_array($alias, $used_aliases)) {
                $i++;
                $alias = $create . $i;
            }
        }
        $openid_ns_to_alias[$ns] = $alias;
        return $alias;
    }
    return null;
}


/* ------- OpenID nonce functions -------------------------------------------- */
/**
 * Generates a nonce for use in OpenID responses
 *
 * @return string an OpenID nonce
 * @link http://openid.net/specs/openid-authentication-2_0.html#positive_assertions
 */
function openid_nonce()
{
    return gmstrftime('%Y-%m-%dT%H:%M:%SZ') . bin2hex(random_bytes(4));
}

/* ------- Diffie-Hellman Key Exchange functions ----------------------------- */

/**
 * Returns the association types supported by this server.
 *
 * @return array an array containing the association types supported by this server as keys
 * and an array containing the key size (mac_size) and HMAC function (hmac_func) as
 * values
 */
function openid_association_types()
{
    $association_types = array('HMAC-SHA1' => array('mac_size' => 20, 'hmac_func' => '_openid_hmac_sha1'));
    if (OPENID_SHA256_SUPPORTED) {
        $association_types['HMAC-SHA256'] = array('mac_size' => 32, 'hmac_func' => '_openid_hmac_sha256');
    }
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
 * @return array an array containing the session types supported by this server as keys
 * and an array containing the hash function (hash_func) as
 * values
 */
function openid_session_types($is_https = false, $version = OPENID_VERSION_2)
{
    $session_types = array(
        'DH-SHA1' => array('hash_func' => '_openid_sha1'),
    );
    if (OPENID_SHA256_SUPPORTED) {
        $session_types['DH-SHA256'] = array('hash_func' => '_openid_sha256');
    }
    if (($version >= OPENID_VERSION_2) && ($is_https == true)) {
        // Under OpenID 2.0 no-encryption is only allowed if TLS is used
        $session_types['no-encryption'] = array();
    }
    if ($version == OPENID_VERSION_1_1) {
        $session_types[''] = array();
    }
    return $session_types;
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
 * @param string $dh_modulus modulus - a large prime number
 * @param string $dh_gen generator - a primitive root modulo
 * @param string $hash_func the hash function
 * @return array an array containing (a) dh_server_public - the server's public key (in Base64), and (b)
 * enc_mac_key encrypted MAC key (in Base64), encrypted using the Diffie-Hellman shared secret
 */
function openid_dh_server_assoc($mac_key, $dh_consumer_public, $dh_modulus = null, $dh_gen = null, $hash_func = '_openid_sha1')
{
    
    // Generate a key pair for the server
    $key_pair = openid_dh_generate_key_pair($dh_modulus, $dh_gen);
    
    // Generate the shared secret
    $ZZ = openid_dh_shared_secret($dh_consumer_public, $key_pair['private'], $dh_modulus);

    return array(
        'dh_server_public' => $key_pair['public'],
        'enc_mac_key' => openid_encrypt_mac_key($ZZ, $mac_key, $hash_func)
    );
}

/**
 * Complete association by obtaining the session MAC key from the key obtained
 * from the Diffie-Hellman key exchange
 *
 * @param string $enc_mac_key the encrypted session MAC key, in Base64 represnetation
 * @param string $dh_server_public the server's public key, in Base64 representation
 * @param string $dh_consumer_private the consumer's private key, in Base64 representation
 * @param string $dh_modulus modulus, in Base64 representation
 * @param string $hash_func the hash function
 * @return string the decrypted session MAC key, in Base64 representation
 */
function openid_dh_consumer_assoc($enc_mac_key, $dh_server_public, $dh_consumer_private, $dh_modulus = null, $hash_func = '_openid_sha1')
{
    // Retrieve the shared secret
    $ZZ = openid_dh_shared_secret($dh_server_public, $dh_consumer_private, $dh_modulus);
    
    // Decode the encrypted MAC key
    $encrypted_mac_key = base64_decode($enc_mac_key);
    
    return openid_encrypt_mac_key($ZZ, $encrypted_mac_key, $hash_func);
}

/**
 * Calculates the shared secret for Diffie-Hellman key exchange.
 *
 * This is the second step in the Diffle-Hellman key exchange process.  The other
 * party (in OpenID 1.0 terms, the consumer) has already generated the public
 * key ($dh_consumer_public) and sent it to this party (the server).  The Diffie-Hellman
 * modulus ($dh_modulus) and generator ($dh_gen) have either been sent or previously agreed.
 *
 * @param string $their_public the other party's public key, in Base64 representation
 * @param string $my_private this party's private key, in Base64 representation
 * @param string $dh_modulus modulus, in Base64 representation
 * @return resource the shared secret (as a bignum)
 *
 * @see openid_dh_generate_key_pair()
 * @link http://www.ietf.org/rfc/rfc2631.txt RFC 2631
 */
function openid_dh_shared_secret($their_public, $my_private, $dh_modulus = null)
{
    // Decode the keys
    $y = _openid_base64_to_bignum($their_public);
    $x = _openid_base64_to_bignum($my_private);
    
    if ($dh_modulus != null) {
        $p = _openid_base64_to_bignum($dh_modulus);
    } else {
        $p = bignum_new(OPENID_DH_DEFAULT_MOD);
    }

    // Generate the shared secret = their public ^ my private mod p = my public ^ their private mod p
    $ZZ = bignum_powmod($y, $x, $p);

    return $ZZ;
}

/**
 * Generates a key pair for Diffie-Hellman key exchange.
 *
 * @param string $dh_modulus modulus, in Base64 representation
 * @param string $dh_gen generator, in Base64 representation
 * @return array an array containing: (a) private - the private key, in Base64
 * and (b) public - the public key, in Base64
 */
function openid_dh_generate_key_pair($dh_modulus = null, $dh_gen = null)
{
    if ($dh_modulus != null) {
        $p = _openid_base64_to_bignum($dh_modulus);
    } else {
        $p = bignum_new(OPENID_DH_DEFAULT_MOD);
    }

    if ($dh_gen != null) {
        $g = _openid_base64_to_bignum($dh_gen);
    } else {
        $g = bignum_new(OPENID_DH_DEFAULT_GEN);
    }

    // Generate the private key - a random number which is less than p
    $rand = _openid_dh_rand($p);
    $x = bignum_add($rand, 1);
    
    // Calculate the public key is g ^ private mod p
    $y = bignum_powmod($g, $x, $p);
    
    return array('private' => _openid_bignum_to_base64($x), 'public' => _openid_bignum_to_base64($y));
}


/**
 * Encrypts/decrypts and encodes the MAC key.
 *
 * @param resource $ZZ the Diffie-Hellman key exchange shared secret as a bignum
 * @param string $mac_key a byte stream containing the MAC key
 * @param string $hash_func the hash function
 * @return string the encrypted MAC key in Base64 representation
 */
function openid_encrypt_mac_key($ZZ, $mac_key, $hash_func = '_openid_sha1')
{
    // Encrypt/decrypt the MAC key using the shared secret and the hash function
    $encrypted_mac_key = _openid_xor($ZZ, $mac_key, $hash_func);
    
    // Encode the encrypted/decrypted MAC key
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
function _openid_xor($key, $plain_cipher, $hash_func = '_openid_sha1')
{
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
 * @return resource the random integer as a bignum
 */
function _openid_dh_rand($stop)
{
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
        $bytes = "\x00" . random_bytes($nbytes);
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
function _openid_base64_to_bignum($str)
{
    return bignum_new(base64_decode($str), 256);
}

/**
 * Converts a string representation of an integer to an arbitary precision
 * integer, then converts it to Base64 encoding.
 *
 * @param string $str the string representation
 * @return string the Base64 encoded arbitary precision integer
 */
function _openid_bignum_to_base64($str)
{
    return base64_encode(bignum_val($str, 256));
}

/**
 * Encode an integer as big-endian signed two's complement binary string.
 *
 * @param string $num the binary integer
 * @return string the signed two's complement binary string
 * @link http://openid.net/specs/openid-authentication-2_0.html#btwoc
 */
function _openid_btwoc($num)
{
    return pack('H*', $num);
}

/* ------- Hash and HMAC functions ------------------------------------------- */
/**
 * Calculates a signature of an OpenID message
 *
 * @param array $data the data in the message
 * @param array $keys a list of keys in the message to be signed (without the
 * 'openid.' prefix)
 * @param string $mac_key the MAC key used to sign the message, in Base64 representation
 * @param string $hmac_func the HMAC function used in the signing process
 * @param float $version the OpenID version
 * @return string the signature encoded in Base64
 */
function openid_sign($data, $keys, $mac_key, $hmac_func = '_openid_hmac_sha1', $version = OPENID_VERSION_2)
{
    $signature = '';
    $sign_data = array();

    foreach ($keys as $key) {
        if (array_key_exists('openid.' . $key, $data)) {
            $sign_data[$key] = $data['openid.' . $key];
        }
    }
    
    $signature_base_string = _openid_signature_base_string($sign_data, $version);
    $secret = base64_decode($mac_key);
    $signature = call_user_func($hmac_func, $secret, $signature_base_string);

    return base64_encode($signature);
}

/**
 * Calculates the base string from which an OpenID signature is generated.
 *
 * OpenID versions 1 and 2 specify that messages are to be encoded using Key-Value
 * Encoding when generating signatures.  However, future OpenID version may
 * specify different ways of encoding the message, such as OAuth.
 *
 * @param array $data the data to sign
 * @param float $version the OpenID version
 * @return string the signature base string
 * @link http://openid.net/specs/openid-authentication-2_0.html#anchor11
 */
function _openid_signature_base_string($data, $version)
{
    switch ($version) {
        case OPENID_VERSION_1_1:
        case OPENID_VERSION_2:
            // We set OPENID_VERSION_1_1 because we don't want to sign the namespace header
            $signature_base_string = openid_direct_message($data, OPENID_VERSION_1_1);
            break;
        default:
            // We set OPENID_VERSION_1_1 because we don't want to sign the namespace header
            $signature_base_string = openid_direct_message($data, OPENID_VERSION_1_1);
    }
    return $signature_base_string;
}

/**
 * Obtains the SHA1 hash of a string in binary representation.
 *
 * @param string $text the text to be hashed
 * @return string the hash in binary representation
 */
function _openid_sha1($text)
{
    return sha1($text, true);
}

/**
 * Obtains the keyed hash value using the HMAC method and the SHA1 algorithm
 *
 * @param string $key the key in binary representation
 * @param string $text the text to be hashed
 * @return string the hash in binary representation
 */
function _openid_hmac_sha1($key, $text)
{
    if (function_exists('hash_hmac') && function_exists('hash_algos') && (in_array('sha1', hash_algos()))) {
        return hash_hmac('sha1', $text, $key, true);
    } else {
        if (!defined('OPENID_SHA1_BLOCKSIZE')) {
            define('OPENID_SHA1_BLOCKSIZE', 64);
        }
        
        if (strlen($key) > OPENID_SHA1_BLOCKSIZE) {
            $key = _openid_sha1($key);
        }
    
        $key = str_pad($key, OPENID_SHA1_BLOCKSIZE, chr(0x00));
        $ipad = str_repeat(chr(0x36), OPENID_SHA1_BLOCKSIZE);
        $opad = str_repeat(chr(0x5c), OPENID_SHA1_BLOCKSIZE);
        $hash1 = _openid_sha1(($key ^ $ipad) . $text);
        $hmac = _openid_sha1(($key ^ $opad) . $hash1);
        return $hmac;
    }
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
    function _openid_sha256($text)
    {
        return hash('sha256', $text, true);
    }
    
    /**
     * Obtains the keyed hash value using the HMAC method and the SHA256 algorithm
     *
     * @param string $key the key in binary representation
     * @param string $text the text to be hashed
     * @return string the hash in binary representation
     */
    function _openid_hmac_sha256($key, $text)
    {
        return hash_hmac('sha256', $text, $key, true);
    }
} else {
    /** @ignore */
    define('OPENID_SHA256_SUPPORTED', false);
}

if (!function_exists('rfc3986_urlencode')) {
    /**
     * Encodes a URL using RFC 3986.
     *
     * PHP's rfc3986_urlencode function encodes a URL using RFC 1738 for PHP versions
     * prior to 5.3.  RFC 1738 has been
     * updated by RFC 3986, which change the list of characters which needs to be
     * encoded.
     *
     * Strictly correct encoding is required for various purposes, such as OAuth
     * signature base strings.
     *
     * @param string $s the URL to encode
     * @return string the encoded URL
     */
    function rfc3986_urlencode($s)
    {
        if (version_compare(PHP_VERSION, '5.3.0', '>=')) {
            return rawurlencode($s);
        } else {
            return str_replace('%7E', '~', rawurlencode($s));
        }
    }
}
