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

/**
 * Convert a direct communication message
 * into an associative array.
 */
function _openid_parse_message($message) {
  $parsed_message = array();

  $items = explode("\n", $message);
  foreach ($items as $item) {
    list($key, $value) = explode(':', $item, 2);

    if ($key != '') {
      $parsed_message[$key] = $value;
    }
  }

  return $parsed_message;
}

function _openid_nonce() {
  // YYYY-MM-DDThh:mm:ssTZD UTC, plus some optional extra unique chars
  return gmstrftime('%Y-%m-%dT%H:%M:%S%Z') .
    chr(mt_rand(0, 25) + 65) .
    chr(mt_rand(0, 25) + 65) .
    chr(mt_rand(0, 25) + 65) .
    chr(mt_rand(0, 25) + 65);
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
  $signature = '';
  $sign_data = array();

  foreach ($keys_to_sign as $key) {
    if (isset($message_array['openid.' . $key])) {
      $sign_data[$key] = $message_array['openid.' . $key];
    }
  }

  $message = _openid_create_message($sign_data);
  $secret = base64_decode($association['mac_key']);
  $signature = _openid_hmac($secret, $message);

  return base64_encode($signature);
}

function _openid_hmac($key, $text) {
   if (strlen($key) > OPENID_SHA1_BLOCKSIZE) {
        $key = _openid_sha1($key, true);
    }

    $key = str_pad($key, OPENID_SHA1_BLOCKSIZE, chr(0x00));
    $ipad = str_repeat(chr(0x36), OPENID_SHA1_BLOCKSIZE);
    $opad = str_repeat(chr(0x5c), OPENID_SHA1_BLOCKSIZE);
    $hash1 = _openid_sha1(($key ^ $ipad) . $text, true);
    $hmac = _openid_sha1(($key ^ $opad) . $hash1, true);
    return $hmac;
}

function _openid_sha1($text) {
  $hex = sha1($text);
  $raw = '';
  for ($i = 0; $i < 40; $i += 2) {
    $hexcode = substr($hex, $i, 2);
    $charcode = (int)base_convert($hexcode, 16, 10);
    $raw .= chr($charcode);
  }
  return $raw;
}

function _openid_dh_base64_to_long($str) {
  $b64 = base64_decode($str);

  return _openid_dh_binary_to_long($b64);
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

function _openid_dh_xorsecret($shared, $secret) {
  $dh_shared_str = _openid_dh_long_to_binary($shared);
  $sha1_dh_shared = _openid_sha1($dh_shared_str);
  $xsecret = "";
  for ($i = 0; $i < strlen($secret); $i++) {
    $xsecret .= chr(ord($secret[$i]) ^ ord($sha1_dh_shared[$i]));
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
    // pseudorandom used
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

// 7.4.4.1. Integer Representations
function _openid_btwoc($num) {
  return pack('H*', $num);
}

// Fix PHP's braindead handling of POST data
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
            $fixed_key = str_replace('openid.'.$alias.'_', 'openid.'.$alias.'.', $key);
        }
        
        if ($fixed_key != $key) {
            unset($post[$key]);
            $post[$fixed_key] = $value;
        }
    }
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