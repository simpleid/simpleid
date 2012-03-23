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
 * Common functions used by SimpleID, and the implementation of extensions.
 *
 * @package simpleid
 * @filesource
 */
 
/**
 * Sets a message to display to the user on the rendered SimpleID page.
 *
 * @param string $msg the message to set
 */
function set_message($msg) {
    global $xtpl;
    
    $xtpl->assign('message', $msg);
    $xtpl->parse('main.message');
}

/**
 * Displays a fatal error message and exits.
 *
 * @param string $error the message to set
 */
function indirect_fatal_error($error) {
    global $xtpl;
    
    set_message($error);
    
    $xtpl->parse('main');
    $xtpl->out('main');
    exit;
}

/**
 * Determines whether the current connection with the user agent is via
 * HTTPS.
 *
 * HTTPS is detected if one of the following occurs:
 *
 * - $_SERVER['HTTPS'] is set to 'on' (Apache installations)
 * - $_SERVER['HTTP_X_FORWARDED_PROTO'] is set to 'https' (reverse proxies)
 * - $_SERVER['HTTP_FRONT_END_HTTPS'] is set to 'on'
 *
 * @return bool true if the connection is via HTTPS
 */
function is_https() {
    return (isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] == 'on'))
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && (strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) == 'https'))
        || (isset($_SERVER['HTTP_FRONT_END_HTTPS']) && ($_SERVER['HTTP_FRONT_END_HTTPS'] == 'on'));
}


/**
 * Determines whether the user agent supplied valid a certificate identifying the
 * user.
 *
 * A valid certificate is supplied if all of the following occurs:
 *
 * - the connection is done using HTTPS (i.e. {@link is_https()} is true)
 * - the web server has been set up to request a certificate from the user agent
 * - the web server has been set up to pass the certificate details to PHP
 * - the certificate has not been revoked
 * - the certificate contains a serial number and a valid issuer
 *
 * @return true if the user agent has supplied a valid SSL certificate
 */
function has_ssl_client_cert() {
    // False if we are not in HTTP
    if (!is_https()) return false;
    
    // False if certificate is not valid
    if (!isset($_SERVER['SSL_CLIENT_VERIFY']) || ($_SERVER['SSL_CLIENT_VERIFY'] !== 'SUCCESS')) return false;
    
    // False if certificate is expired or has no expiry date
    if (!isset($_SERVER['SSL_CLIENT_V_REMAIN']) || ($_SERVER['SSL_CLIENT_V_REMAIN'] < 0)) return false;
    if (!isset($_SERVER['SSL_CLIENT_V_END'])) return false;
    
    // False if no serial number
    if (!isset($_SERVER['SSL_CLIENT_M_SERIAL'])) return false;
    
    // False if no issuer
    if (!isset($_SERVER['SSL_CLIENT_I_DN'])) return false;
    
    return true;
}

/**
 * Ensure the current connection with the user agent is secure with HTTPS.
 *
 * This function uses {@link is_https()} to determine whether the connection
 * is via HTTPS.  If it is, this function will return successfully.
 *
 * If it is not, what happens next is determined by the following steps.
 *
 * 1. If $allow_override is true and {@link SIMPLEID_ALLOW_PLAINTEXT} is also true,
 * then the function will return successfully
 * 2. Otherwise, then it will either redirect (if $action is
 * redirect) or return an error (if $action is error)
 *
 * @param string $action what to do if connection is not secure - either
 * 'redirect' or 'error'
 * @param boolean $allow_override whether SIMPLEID_ALLOW_PLAINTEXT is checked
 * to see if an unencrypted connection is allowed
 * @param string $redirect_url if $action is redirect, what URL to redirect to.
 * If null, this will redirect to the same page (albeit with an HTTPS connection)
 * @param boolean $strict whether HTTP Strict Transport Security is active
 * @see SIMPLEID_ALLOW_PLAINTEXT
 */
function check_https($action = 'redirect', $allow_override = false, $redirect_url = null, $strict = true) {
    if (is_https()) {
        if ($strict) header('Strict-Transport-Security: max-age=3600');
        return;
    }
    
    if ($allow_override && SIMPLEID_ALLOW_PLAINTEXT) return;
    
    if ($action == 'error') {
        header('HTTP/1.1 426 Upgrade Required');
        header('Upgrade: TLS/1.2, HTTP/1.1');
        header('Connection: Upgrade');
        indirect_fatal_error(t('An encrypted connection (HTTPS) is required for this page.'));
        return;
    }
    
    if ($redirect_url == null) $redirect_url = simpleid_url('', $_SERVER['QUERY_STRING'], false, 'https');
    
    header('HTTP/1.1 301 Moved Permanently');
    header('Location: ' . $redirect_url);
}

/**
 * Content type negotiation using the Accept Header.
 *
 * Under HTTP, the user agent is able to negoatiate the content type returned with
 * the server using HTTP Accept header.  This header contains a comma-delimited
 * list of items (e.g. content types) which the user agent is able to
 * accept, ranked by a quality parameter.
 *
 * This function takes the header from the user agent, compares it against the
 * content types which the server can provide, then returns the item which the highest
 * quality which the server can provide.
 *
 * @param array $content_types an array of content types which the server can
 * provide
 * @param string $accept_header the header string provided by the user agent.
 * If NULL, this defaults to $_SERVER['HTTP_ACCEPT'] if available
 * @return string the negotiated content type, FALSE if $accept_header is NULL and
 * the user agent did not provide an Accept header, or NULL if the negotiation is
 * unsuccessful
 *
 * @since 0.8
 *
 */
function negotiate_content_type($content_types, $accept_header = NULL) {
    $content_types = array_map("strtolower", $content_types);
    if (($accept_header == NULL) && isset($_SERVER['HTTP_ACCEPT'])) $accept_header = $_SERVER['HTTP_ACCEPT'];
    
    if ($accept_header) {
        $acceptible = preg_split('/\s*,\s*/', strtolower(trim($accept_header)));
        for ($i = 0; $i < count($acceptible); $i++) {
            $split = preg_split('/\s*;\s*q\s*=\s*/', $acceptible[$i], 2);
            $item = strtolower($split[0]);
            
            if (count($split) == 1) {
                $q = 1.0;
            } else {
                $q = doubleval($split[1]);
            }
            
            if ($q > 0.0) {
                if (in_array($item, $content_types)) {
                    if ($q == 1.0) {
                        return $item;
                    }
                    $candidates[$item] = $q;
                } else {
                    $item = preg_quote($item, '/');
                    $item = strtr($item, array('\*' => '[^\\x00-\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-\\x3c\\x3e\\x40\\x5b-\\x5d\\x7f-\\xff]+'));
                    
                    foreach ($content_types as $value) {
                        if (preg_match("/^$item$/", $value)) {
                            if ($q == 1.0) {
                                return $value;
                            }
                            $candidates[$value] = $q;
                            break;
                        }
                    }
                }
            }
        }
        if (isset($candidates)) {
            arsort($candidates);
            reset($candidates);
            return key($candidates);
        }
        return NULL;
    } else {
        // No headers
        return FALSE;
    }
}

/**
 * Serialises a variable for inclusion as a URL parameter.
 *
 * @param mixed $data the data to serialise
 * @return string serialised data
 * @see unpickle()
 */
function pickle($data) {
    return base64_encode(gzcompress(serialize($data)));
}

/**
 * Deserialises data specified in a URL parameter as a variable.
 *
 * @param string $pickle the serialised data
 * @return mixed the deserialised data
 * @see pickle()
 */
function unpickle($pickle) {
    return unserialize(gzuncompress(base64_decode($pickle)));
}

/**
 * Obtains the URI of the current request, given a base URI.
 *
 * @param string $base the base URI
 * @return string the request URI
 */
function get_request_uri($base) {
    $i = strpos($base, '//');
    $i = strpos($base, '/', $i + 2);
    
    if ($i === false) {
        return $base . $_SERVER['REQUEST_URI'];
    } else {
        return substr($base, 0, $i) . $_SERVER['REQUEST_URI'];
    }
}

/**
 * Returns the base URL path, relative to the current host, of the SimpleID
 * installation.
 *
 * This is worked out from {@link SIMPLEID_BASE_URL}.  It will always contain
 * a trailing slash.
 *
 * @return string the base URL path
 * @since 0.8
 * @see SIMPLEID_BASE_URL
 */
function get_base_path() {
    static $base_path;
    
    if (!$base_path) {
        if ((substr(SIMPLEID_BASE_URL, -1) == '/') || (substr(SIMPLEID_BASE_URL, -9) == 'index.php')) {
            $url = SIMPLEID_BASE_URL;
        } else {
            $url = SIMPLEID_BASE_URL . '/';
        }
        
        $parts = parse_url($url);
        $base_path = $parts['path'];
    }
    
    return $base_path;
}

/**
 * Determines whether the {@link SIMPLEID_BASE_URL} configuration option is a
 * HTTPS URL.
 *
 * @return true if SIMPLEID_BASE_URL is a HTTPS URL
 */
function is_base_https() {
    return (stripos(SIMPLEID_BASE_URL, 'https:') === 0));
}

/**
 * Obtains a SimpleID URL.  URLs produced by SimpleID should use this function.
 *
 * @param string $q the q parameter
 * @param string $params a properly encoded query string
 * @param bool $relative whether a relative URL should be returned
 * @param string $secure if $relative is false, either 'https' to force an HTTPS connection, 'http' to force
 * an unencrypted HTTP connection, 'detect' to base on the current connection, or NULL to vary based on SIMPLEID_BASE_URL
 * @return string the url
 *
 * @since 0.7
 */
function simpleid_url($q = '', $params = '', $relative = false, $secure = null) {
    if ($relative) {
        $url = get_base_path();
    } else {
        // Make sure that the base has a trailing slash
        if ((substr(SIMPLEID_BASE_URL, -1) == '/') || (substr(SIMPLEID_BASE_URL, -9) == 'index.php')) {
            $url = SIMPLEID_BASE_URL;
        } else {
            $url = SIMPLEID_BASE_URL . '/';
        }
        
        if (($secure == 'https') && (stripos($url, 'http:') === 0)) {
            $url = 'https:' . substr($url, 5);
        }
        if (($secure == 'http') && (stripos($url, 'https:') === 0)) {
            $url = 'http:' . substr($url, 6);
        }
        if (($secure == 'detect') && (is_https()) && (stripos($url, 'http:') === 0)) {
            $url = 'https:' . substr($url, 5);
        }
        if (($secure == 'detect') && (!is_https()) && (stripos($url, 'https:') === 0)) {
            $url = 'http:' . substr($url, 6);
        }
    }
    
    if (SIMPLEID_CLEAN_URL) {
        $url .= $q . (($params == '') ? '' : '?' . $params);
    } elseif (($q == '') && ($params == '')) {
        $url .= '';
    } elseif ($q == '') {
        $url .= 'index.php?' . $params;
    } else {
        $url .= 'index.php?q=' . $q . (($params == '') ? '' : '&' . $params);
    }
    return $url;
}

/**
 * Obtains the URL of the host of the SimpleID's installation.  The host is worked
 * out based on SIMPLEID_BASE_URL
 *
 * @param string $secure if $relative is false, either 'https' to force an HTTPS connection, 'http' to force
 * an unencrypted HTTP connection, or NULL to vary based on SIMPLEID_BASE_URL
 * @return string the url
 */
function simpleid_host_url($secure = null) {
    $parts = parse_url(SIMPLEID_BASE_URL);
    
    if ($secure == 'https') {
        $scheme = 'https';
    } elseif ($secure == 'http') {
        $scheme = 'http';
    } else {
        $scheme = $parts['scheme'];
    }
    
    $url = $scheme . '://';
    if (isset($parts['user'])) {
        $url .= $parts['user'];
        if (isset($parts['pass'])) $url .= ':' . $parts['pass'];
        $url .= '@';
    }
    $url .= $parts['host'];
    if (isset($parts['port'])) $url .= ':' . $parts['port'];

    return $url;
}

/**
 * Obtains a form token given a form ID.
 *
 * Form tokens are used in SimpleID forms to guard against cross-site forgery
 * attacks.
 *
 * @param string $id the form ID
 * @return string a form token
 */
function get_form_token($id) {
    global $user;

    if (store_get('site-token') == NULL) {
        $site_token = mt_rand();
        store_set('site-token', $site_token);
    } else {
        $site_token = store_get('site-token');
    }
    
    if ($user == NULL) {
        return md5($id . $site_token);
    } else {
        return md5(session_id() . $id . $site_token);
    }
}

/**
 * Checks whether a form token is valid
 *
 * @param string $token the token returned by the user agent
 * @param string $id the form ID
 * @return bool true if the form token is valid
 */
function validate_form_token($token, $id) {
    global $user;
    
    $site_token = store_get('site-token');
    
    if ($user == NULL) {
        return ($token == md5($id . $site_token));
    } else {
        return ($token == md5(session_id() . $id . $site_token));
    }
}

/* ------- SimpleID extension support ---------------------------------------- */


/**
 * This variable holds an array of extensions specified by the user
 *
 * @global array $simpleid_extensions
 * @see SIMPLEID_EXTENSIONS
 */
$simpleid_extensions = array();

/**
 * Initialises the extension mechanism.  This function looks up the extensions
 * to load in the {@link SIMPLEID_EXTENSIONS} constants, loads them, then
 * calls the ns hook.
 */
function extension_init() {
    global $simpleid_extensions;
    
    $simpleid_extensions = preg_split('/,\s*/', SIMPLEID_EXTENSIONS);
    
    foreach ($simpleid_extensions as $extension) {
        include_once 'extensions/' . $extension . '/' . $extension . '.extension.php';
    }
}

/**
 * Invokes a hook in all the loaded extensions.
 *
 * @param string $function the name of the hook to call
 * @param mixed $args the arguments to the hook
 * @return array the return values from the hook
 */
function extension_invoke_all() {
    global $simpleid_extensions;
    
    $args = func_get_args();
    $function = array_shift($args);
    $return = array();
    
    foreach ($simpleid_extensions as $extension) {
        if (function_exists($extension . '_' . $function)) {
            log_debug('extension_invoke_all: ' . $extension . '_' . $function);
            $result = call_user_func_array($extension . '_' . $function, $args);
            if (isset($result) && is_array($result)) {
                $return = array_merge($return, $result);
            } elseif (isset($result)) {
                $return[] = $result;
            } 
        }
    }
    
    return $return;
}

/**
 * Invokes a hook in a specified extension.
 *
 * @param string $extension the extension to call
 * @param string $function the name of the hook to call
 * @param mixed $args the arguments to the hook
 * @return mixed the return value from the hook
 */
function extension_invoke() {
    $args = func_get_args();
    $extension = array_shift($args);
    $function = array_shift($args);
    
    if (function_exists($extension . '_' . $function)) {
        log_debug('extension_invoke: ' . $extension . '_' . $function);
        return call_user_func_array($extension . '_' . $function, $args);
    }
}

/**
 * Returns an array of currently loaded extensions.
 *
 * @param array a list of the names of the currently loaded extensions.
 */
function get_extensions() {
    global $simpleid_extensions;
    
    return $simpleid_extensions;
}
?>
