<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007
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
 * From Appendix B: Diffie-Hellman Key Exchange Default Value
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

function openid_get_version($request) {
    if ($request["openid.ns"] != 'http://specs.openid.net/auth/2.0/signon') return OPENID_VERSION_1_1;
    return OPENID_VERSION_2;
}

/**
 * Creates a OpenID message for direct response.
 *
 * The response will be encoded using Key-Value Form Encoding. [4.1.1]
 *
 * @param $data the data in the response
 * @param $version the message version
 */
function openid_direct_message($data, $version = OPENID_VERSION_2) {
    if ($version == OPENID_VERSION_2) {
        $data['ns'] = 'http://specs.openid.net/auth/2.0';
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
 * @param $message an OpenID message encoded using Key-Value Form
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
 * @param $data the data in the response
 * @param $version the message version
 */
function openid_indirect_message($data, $version = OPENID_VERSION_2) {
    if ($version == OPENID_VERSION_2) {
        return array_merge($data, array('openid.ns' => 'http://specs.openid.net/auth/2.0'));
    }
    return $data;
}

function openid_indirect_response($url, $message, $response_func = 'openid_indirect_response_form') {
    call_user_func($response_func, $url, $message);
}

function openid_indirect_response_redirect($url, $message) {    
    if (is_array($message)) {
        $pairs = array();
        
        foreach ($message as $key => $value) {
            $pairs[] = urlencode($key) . '=' . urlencode($value);
        }
        
        $encoded_message = implode('&', $pairs);
    } else {
        $encoded_message = $message;
    }    
    
    header('Status: 303 See Other');
    header('Location: ' . $url . '?' . $encoded_message);
    exit;
}

function openid_indirect_response_form($url, $message) {
    $html = '<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xml:lang="en-AU" lang="en-AU" xmlns="http://www.w3.org/1999/xhtml"><body>';

    $html .= '<form action="' . htmlspecialchars($url) . '" method="post" enctype="application/x-www-form-urlencoded" id="redirect"><p>Redirecting...</p>';

    foreach ($message as $key -> $value) {
        if ($key) {
            $html .= '<input type="hidden" name="' . htmlspecialchars($key) . '" value="' . htmlspecialchars($value) . '" />';
        }
    }

    $html .= '<noscript><input type="submit" value="Continue" /></noscript>
                <script type="text/javascript">document.getElementById("redirect").submit();</script>
            </form></body></html>';
            
    print $html;
    
    exit;
}

function openid_direct_error($error, $additional = array(), $version = OPENID_VERSION_2) {
    $message = openid_direct_message(array_merge(array('error' => $error), $additional), $version);
    openid_direct_response($message, '400 Bad Request');
}

function openid_indirect_error($url, $error, $additional = array(), $version = OPENID_VERSION_2, $response_func = 'openid_indirect_response_form') {
    $message = openid_indirect_message(array_merge(array('error' => $error), $additional), $version);
    openid_indirect_response($url, $message, $response_func);
}

/**
 * Encodes a message using Key-Value Form Encoding [4.1.1]
 *
 */
function _openid_create_message($data) {
  $serialized = '';  

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
    $serialized .= "$key:$value\n";
  }
  return $serialized;
}

/**
 * Converts a message encoded using Key-Value Form Encoding into HTTP Encoding
 * [4.1.2]
 */
function _openid_encode_message($message) {
  $encoded_message = '';

  // Content-Type: application/x-www-form-urlencoded
  $items = explode("\n", $message);
  foreach ($items as $item) {
    list($key, $value) = explode(':', $item, 2);

    if ($key != '') {
      if ($encoded_message != '') {
        $encoded_message .= '&';
      }
      $encoded_message .= rawurlencode(trim($key)) . '=' . rawurlencode(trim($value));
    }
  }

  return $encoded_message;
}

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
 * Signatures
 * Sign certain keys in a message
 * $association - object loaded from openid_association or openid_server_association table
 *              - important fields are ->assoc_type and ->mac_key
 * $message_array - array of entire message about to be sent
 * $keys_to_sign - keys in the message to include in signature (without
 * 'openid.' appended)
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
 * Encoded an integer as big-endian signed two's complement binary strings.
 * [4.2]
 */
function _openid_btwoc($num) {
    return pack('H*', $num);
}

/**
 * Fix PHP's braindead handling of POST data.  PHP changes dots in keys of
 * associative arrays to underscores.
 */
function _openid_fix_post(&$post) {
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

/* ------- Random byte and nonce functions ----------------------------------- */
/**
 * Obtains a number of random bytes.  This function uses an entropy source.
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
 */
function openid_nonce() {
    return gmstrftime('%Y-%m-%dT%H:%M:%SZ') . bin2hex(_openid_get_bytes(4));
}

/* ------- Diffie-Hellman Key Exchange functions ----------------------------- */

/**
 * Associate using Diffie-Hellman key exchange [8.4.2]
 *
 * @param $dh_modulus a prime number
 * @param $dh_gen a primitive root modulo $dh_modulus
 */
function openid_dh_server_assoc($secret, $dh_consumer_public, $dh_modulus = NULL, $dh_gen = NULL, $hash_func = '_openid_sha1') {
    $cpub = _openid_dh_base64_to_long($dh_consumer_public);
    
    if ($dh_modulus) {
        $mod = _openid_dh_base64_to_long($dh_modulus);
    } else {
        $mod = OPENID_DH_DEFAULT_MOD;
    }

    if ($dh_gen) {
        $gen = _openid_dh_base64_to_long($dh_gen);
    } else {
        $gen = OPENID_DH_DEFAULT_GEN;
    }

    $r = _openid_dh_rand($mod);
    $private = bcadd($r, 1);
    $public = bcpowmod($gen, $private, $mod);

    $shared = bcpowmod($cpub, $private, $mod);
    $mac_key = _openid_dh_xorsecret($shared, $secret, $hash_func);
    $enc_mac_key = base64_encode($mac_key);
    $spub64 = _openid_dh_long_to_base64($public);
    return array(
        'dh_server_public' => $spub64,
        'enc_mac_key' => $enc_mac_key
    );
}

function _openid_dh_base64_to_long($str) {
    return _openid_dh_binary_to_long(base64_decode($str));
}

function _openid_dh_long_to_base64($str) {
    return base64_encode(_openid_dh_long_to_binary($str));
}

function _openid_dh_binary_to_long($str) {
    $bytes = array_merge(unpack('C*', $str));

    $n = 0;
  
    foreach ($bytes as $byte) {
        $n = bcmul($n, pow(2, 8));
        $n = bcadd($n, $byte);
    }

    return $n;
}

function _openid_dh_long_to_binary($long) {
    $cmp = bccomp($long, 0);
    if ($cmp < 0) {
        return FALSE;
    }

    if ($cmp == 0) {
        return "\x00";
    }

    $bytes = array();
  
    while (bccomp($long, 0) > 0) {
        array_unshift($bytes, bcmod($long, 256));
        $long = bcdiv($long, pow(2, 8));
    }
  
    if ($bytes && ($bytes[0] > 127)) {
        array_unshift($bytes, 0);
    }
  
    $string = '';
    foreach ($bytes as $byte) {
        $string .= pack('C', $byte);
    }
  
    return $string;
}

function _openid_dh_xorsecret($shared, $secret, $hash_func = '_openid_sha1') {
    $dh_shared_str = _openid_dh_long_to_binary($shared);
    $hashed_dh_shared = call_user_func($hash_func, $dh_shared_str);
    $xsecret = "";
    for ($i = 0; $i < strlen($secret); $i++) {
        $xsecret .= chr(ord($secret[$i]) ^ ord($hashed_dh_shared[$i]));
    }
  
    return $xsecret;
}

function _openid_dh_rand($stop) {
  static $duplicate_cache = array();
  
  // Used as the key for the duplicate cache
  $rbytes = _openid_dh_long_to_binary($stop);
  
  if (array_key_exists($rbytes, $duplicate_cache)) {
    list($duplicate, $nbytes) = $duplicate_cache[$rbytes];
  } else {
    if ($rbytes[0] == "\x00") {
      $nbytes = strlen($rbytes) - 1;
    } else {
      $nbytes = strlen($rbytes);
    }
    
    $mxrand = bcpow(256, $nbytes);

    // If we get a number less than this, then it is in the
    // duplicated range.
    $duplicate = bcmod($mxrand, $stop);

    if (count($duplicate_cache) > 10) {
      $duplicate_cache = array();
    }
    
    $duplicate_cache[$rbytes] = array($duplicate, $nbytes);
  }
  
  do {
    $bytes = "\x00" . _openid_get_bytes($nbytes);
    $n = _openid_dh_binary_to_long($bytes);
    // Keep looping if this value is in the low duplicated range
  } while (bccomp($n, $duplicate) < 0);

  return bcmod($n, $stop);
}

/* ------- Hash and HMAC functions ------------------------------------------- */

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
    define('OPENID_SHA256_SUPPORTED', true);
    
    function _openid_sha256($text) {
        return hash('sha256', $text, true);
    }
    
    function _openid_hmac_sha256($key, $text) {
        return hash_hmac('sha256', $text, true);
    }
} else {
    define('OPENID_SHA256_SUPPORTED', false);
}



// Provide bcpowmod support for PHP4
if (!function_exists('bcpowmod')) {
    function bcpowmod($base, $exp, $mod) {
        $square = bcmod($base, $mod);
        $result = 1;
        while (bccomp($exp, 0) > 0) {
            if (bcmod($exp, 2)) {
                $result = bcmod(bcmul($result, $square), $mod);
            }
            $square = bcmod(bcmul($square, $square), $mod);
            $exp = bcdiv($exp, 2);
        }
        return $result;
    }
}

?>