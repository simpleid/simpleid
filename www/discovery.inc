<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-9
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
 * Support for XRDS and XRD based discovery.
 *
 * The functions for this file supports HTTP-based identifiers.  For XRIs, the
 * resolution service xri.net is used to resolve to HTTP-based URLs.
 *
 * @package simpleid
 * @since 0.7
 * @filesource
 */
 
include_once "http.inc";

/**
 * The namespace identifier for an XRDS document.
 */
define('XRDS_NS', 'xri://$xrds');

/**
 * The namespace identifier for XRDS version 2.
 */
define('XRD2_NS', 'xri://$xrd*($v*2.0)');

/**
 * The namespace identifier for XRDS Simple.
 */
define('XRDS_SIMPLE_NS', 'http://xrds-simple.net/core/1.0');

/**
 * The type identifier for XRDS Simple.
 */
define('XRDS_SIMPLE_TYPE', 'xri://$xrds*simple');

/**
 * The namespace identifier for an XRD document.
 */
define('XRD_NS', 'http://docs.oasis-open.org/ns/xri/xrd-1.0');

/**
 * The namespace identifier for an host metadata.
 */
define('HOST_META_NS', 'http://host-meta.net/ns/1.0');

/**
 * The namespace identifier for OpenID services.
 */
define('XRD_OPENID_NS', 'http://openid.net/xmlns/1.0');

/**
 * Obtains the services for particular identifier.
 *
 * This function attempts to discover and obtain the XRDS document associated
 * with the identifier, parses the XRDS document and returns an array of
 * services.
 *
 * If an XRDS document is not found, and $openid is set to true, this function
 * will also attempt to discover OpenID services by looking for link elements
 * with rel of openid.server or openid2.provider in the discovered HTML document.
 *
 * @param string $identifier the identifier
 * @param bool $openid if true, performs additional discovery of OpenID services
 * by looking for link elements within the discovered document
 * @return array an array of discovered services, or an empty array if no services
 * are found
 */
function discovery_get_services($identifier, $openid = FALSE) {
    $identifier = discovery_normalize($identifier);
    $url = discovery_get_url($identifier);
    
    $xrds = discovery_get_xrds($url);

    if ($xrds) {
        return discovery_parse_xrds($xrds);
    } else {
        if ($openid) return discovery_get_openid_services($url);
        return array();
    }
}

/**
 * Given an array of discovered services, obtains information on services of
 * a particular type.
 *
 * @param array $services the discovered services
 * @param string $type the URI of the type of service to obtain
 * @return array an array of matching services, or an empty array of no services
 * match
 */
function discovery_get_service_by_type($services, $type) {
    $matches = array();
    
    foreach ($services as $service) {
        foreach ($service['type'] as $service_type) {
            if ($service_type == $type) $matches[] = $service;
        }
    }
    return $matches;
}

/**
 * Given an array of discovered services, obtains information on the service of
 * a specified ID.
 *
 * @param array $services the discovered services
 * @param string $id the XML ID of the service in the XRDS document
 * @return array the matching service, or NULL of no services
 * are found
 */
function discovery_get_service_by_id($services, $id) {
    foreach ($services as $service) {
        if ($service['#id'] == $id) return $service;
    }
    return NULL;
}

/**
 * Obtains a XRDS document at a particular URL.  Performs Yadis discovery if
 * the URL does not produce a XRDS document.
 *
 * @param string $url the URL
 * @param bool $check whether to check the content type of the response is
 * application/xrds+xml
 * @param int $retries the number of tries to make
 * @return string the contents of the XRDS document
 */
function discovery_get_xrds($url, $check = TRUE, $retries = 5) {
    if ($retries == 0) return NULL;
    
    $response = http_make_request($url, array('Accept' => 'application/xrds+xml'));

    if (isset($response['http-error'])) return NULL;
    if (($response['content-type'] == 'application/xrds+xml') || ($check == FALSE)) {
        return $response['data'];
    } elseif (isset($response['headers']['x-xrds-location'])) {
        return discovery_get_xrds($response['headers']['x-xrds-location'], false, $retries - 1);
    } else {
        $location = _discovery_meta_httpequiv('X-XRDS-Location', $response['data']);
        if ($location) {
            return discovery_get_xrds($location, false, $retries - 1);
        }
        return NULL;
    }
}

/**
 * Normalises an identifier for discovery.
 *
 * If the identifier begins with xri://, acct: or mailto:, this is stripped out.  If the identifier
 * does not begin with a valid URI scheme, http:// is assumed and added to the
 * identifier.
 *
 * @param string $identifier the identifier to normalise
 * @return string the normalised identifier
 */
function discovery_normalize($identifier) {
    $normalized = $identifier;
    
    if (discovery_is_xri($identifier)) {
        if (stristr($identifier, 'xri://') !== false) $normalized = substr($identifier, 6);
    } elseif (discovery_is_email($identifier)) {
        if (stristr($identifier, 'acct:') !== false) $normalized = substr($identifier, 5);
        if (stristr($identifier, 'mailto:') !== false) $normalized = substr($identifier, 7);
    } else {
        if (stristr($identifier, '://') === false) $normalized = 'http://'. $identifier;
        if (substr_count($normalized, '/') < 3) $normalized .= '/';
    }
    
    return $normalized;
}

/**
 * Obtains a URL for an identifier.  If the identifier is a XRI, the XRI resolution
 * service is used to convert the identifier to a URL.
 *
 * @param string $identifier the identifier
 * @return string the URL
 */
function discovery_get_url($identifier) {
    if (discovery_is_xri($identifier)) {
        return 'http://xri.net/' . $identifier;
    } elseif (discovery_is_email($identifier)) {
        //list($user, $host) = explode('@', $identifier, 2);
        //$host_meta = 'http://' . $host . '/.well-known/host-meta';
    } else {
        return $identifier;
    }

}

/**
 * Determines whether an identifier is an XRI.
 *
 * XRI identifiers either start with xri:// or with @, =, +, $ or !.
 *
 * @param string $identifier the parameter to test
 * @return bool true if the identifier is an XRI
 */
function discovery_is_xri($identifier) {
    $firstchar = substr($identifier, 0, 1);
    if ($firstchar == "@" || $firstchar == "=" || $firstchar == "+" || $firstchar == "\$" || $firstchar == "!") return true;
    if (stristr($identifier, 'xri://') !== FALSE) return true;
    return false;
}

/**
 * Determines whether an identifier is an e-mail address.
 *
 * An identifier is an e-mail address if it:
 *
 * - has a single @ character
 * - does not have a slash character
 *
 * @param string $identifier the parameter to test
 * @return bool true if the identifier is an e-mail address
 */
function discovery_is_email($identifier) {
    // If it begins with acct: or mailto:, strip it out
    if (stristr($identifier, 'acct:') !== false) $identifier = substr($identifier, 5);
    if (stristr($identifier, 'mailto:') !== false) $identifier = substr($identifier, 7);
    
    // If it contains a slash, it is not an e-mail address
    if (strpos($identifier, "/") !== false) return false;
    
    $at = strpos($identifier, "@");
    
    // If it does not contain a @, it is not an e-mail address
    if ($at === false) return false;
    
    // If it contains more than one @, it is not an e-mail
    if (strrpos($identifier, "@") != $at) return false;
    
    return true;
}


/**
 * Callback function to sort service and URI elements based on priorities
 * specified in the XRDS document.
 *
 * The XRDS specification allows multiple instances of certain elements, such
 * as Service and URI.  The specification allows an attribute called priority
 * so that the document creator can specify the order the elements should be used.
 *
 * @param array $a
 * @param array $b
 * @return int
 */
function discovery_priority_sort($a, $b) {
    if (!isset($a['#priority']) && !isset($b['#priority'])) return 0;
    
    // if #priority is missing, #priority is assumed to be infinity
    if (!isset($a['#priority'])) return 1;
    if (!isset($b['#priority'])) return -1;
    
    if ($a['#priority'] == $b['#priority']) return 0;
    return ($a['#priority'] < $b['#priority']) ? -1 : 1;
}

/**
 * Parses an XRDS document to return services available.
 *
 * @param string $xrds the XRDS document
 * @return array the parsed structure
 *
 * @see XRDSParser
 */
function discovery_parse_xrds($xrds) {
    // Allow for PHP5 version of xtemplate
    if (version_compare(PHP_VERSION, '5.0.0') === 1) {
        $parser = new XRDSParser();
    } else {
        $parser =& new XRDSParser();
    }
    
    $parser->parse($xrds);
    $parser->free();
    $services = $parser->services();
    uasort($services, 'discovery_priority_sort');

    return $services;
}

/**
 * Obtains the OpenID services for particular identifier by scanning for link
 * elements in the returned document.
 *
 * Note that this function does not use the YADIS protocol to scan for services.
 * To use the YADIS protocol, use {@link discovery_get_services()}.
 *
 * @param string $url the URL
 * @return array an array of discovered services, or an empty array if no services
 * are found
 */
function discovery_get_openid_services($url) {
    $services = array();
        
    $response = http_make_request($url);
    $html = $response['data'];
        
    $uri = _discovery_link_rel('openid2.provider', $html);
    $delegate = _discovery_link_rel('openid2.local_id', $html);
    
    if ($uri) {
        $service = array(
            'type' => 'http://specs.openid.net/auth/2.0/signon',
            'uri' => $uri
            );
        if ($delegate) $service['localid'] = $delegate;
        $services[] = $service;
    }

    $uri = _discovery_link_rel('openid.server', $html);
    $delegate = _discovery_link_rel('openid.delegate', $html);
        
    if ($uri) {
        $service = array(
            'type' => 'http://openid.net/signon/1.0',
            'uri' => $uri
            );
        if ($delegate) $service['localid'] = $delegate;
        $services[] = $service;
    }
    
    return $services;
}

/**
 * Generates a URI from a URI template and another URI.
 *
 * The URI must be able to be parsed by PHP's parse_url function.
 *
 * @param string $template the URI template
 * @param string $uri the input URI
 * @return string the generated URI
 *
 */
function discovery_uri_template($template, $uri) {
    $parts = @parse_url($uri);
    
    // The {uri} template variable excludes the fragment
    $short_uri = array_shift(explode('#', $uri, 2));
    
    // The {userinfo} template variable is the user and the pass
    $userinfo = (isset($parts['user'])) ? $parts['user'] . ((isset($parts['pass'])) ? ':' . $parts['pass'] : '') : '';
    
    // The {authority] tempalte is the userinfo, host and port
    $authority = $userinfo . ((isset($parts['host'])) ? '@' . $parts['host'] . ((isset($parts['port'])) ? ':' . $parts['port'] : '') : '');
    
    $args = array(
        'uri' => $short_uri,
        'scheme' => (isset($parts['scheme'])) ? $parts['scheme'] : '',
        'authority' => $authority,
        'path' => (isset($parts['path'])) ? $parts['path'] : '',
        'query' => (isset($parts['query'])) ? $parts['query'] : '',
        'fragment' => (isset($parts['fragment'])) ? $parts['fragment'] : '',
        'userinfo' => $userinfo,
        'host' => (isset($parts['host'])) ? $parts['host'] : '',
        'port' => (isset($parts['port'])) ? $parts['port'] : ''
    );
    
    // Define the % encoded versions
    foreach ($args as $key => $value) {
        $args['%' . $key] = rfc3986_urlencode($value);
    }
    
    return strtr($template, $args);
}

/**
 * Searches through an HTML document to obtain the value of a meta
 * element with a specified http-equiv attribute.
 *
 * @param string $equiv the http-equiv attribute for which to search
 * @param string $html the HTML document to search
 * @return mixed the value of the meta element, or FALSE if the element is not
 * found
 */
function _discovery_meta_httpequiv($equiv, $html) {
    $html = preg_replace('/<!(?:--(?:[^-]*|-[^-]+)*--\s*)>/', '', $html); // Strip html comments
    
    $equiv = preg_quote($equiv);
    preg_match('|<meta\s+http-equiv=["\']'. $equiv .'["\'](.*)/?>|iUs', $html, $matches);
    if (isset($matches[1])) {
        preg_match('|content=["\']([^"]+)["\']|iUs', $matches[1], $content);
        if (isset($content[1])) {
            return $content[1];
        }
    }
    return FALSE;
}

/**
 * Searches through an HTML document to obtain the value of a link
 * element with a specified rel attribute.
 *
 * @param string $rel the rel attribute for which to search
 * @param string $html the HTML document to search
 * @return mixed the href of the link element, or FALSE if the element is not
 * found
 */
function _discovery_link_rel($rel, $html) {
    $html = preg_replace('/<!(?:--(?:[^-]*|-[^-]+)*--\s*)>/s', '', $html); // Strip html comments
    
    $rel = preg_quote($rel);
    preg_match('|<link\s+rel=["\'](.*)'. $rel .'(.*)["\'](.*)/?>|iUs', $html, $matches);
    if (isset($matches[3])) {
        preg_match('|href=["\']([^"]+)["\']|iU', $matches[3], $href);
        return trim($href[1]);
    }
    return FALSE;
}

/**
 * A simple XRDS parser.
 *
 * This parser uses the classic expat functions available in PHP to parse the
 * XRDS Simple XML document.
 *
 * The result is an array of discovered services.
 *
 * @link http://xrds-simple.net/
 */
class XRDSParser {
    /**
     * XML parser
     * @var resource
     * @access private
     */
    var $parser;
    
    /**
     * Discovered services
     * @var array
     * @access private
     */
    var $services = array();
    
    /**
     * State: are we parsing a service element?
     * @var bool
     * @access private
     */
    var $in_service = FALSE;
    
    /**
     * CDATA buffer
     * @var string
     * @access private
     */
    var $_buffer;
    /**
     * Attributes buffer
     * @var array
     * @access private
     */
    var $_attribs = array();
    
    /**
     * priority attribute buffer
     * @var string
     * @access private
     */
    var $priority = NULL;
    
    /**
     * Currently parsed service buffer
     * @var array
     * @access private
     */
    var $service = array();
    
    /**
     * The canonical identifier for the resource described.  Used in XRD
     * documents only.
     * @var string
     * @access private
     * @since 0.8
     */
    var $subject = NULL;
    
    /**
     * Additional identifies for the resource described.  Used in XRD
     * documents only.
     * @var array
     * @access private
     * @since 0.8
     */
    var $aliases = array();
    
    /**
     * Additional properties for the resource described.  Used in XRD
     * documents only.
     * @var array
     * @access private
     * @since 0.8
     */
    var $properties = array();

    /**
     * Mapping between XRDS elements and XRD attributes
     * @var array
     * @access private
     * @since 0.8
     */
    var $xrds_map = array(
        'rel' => 'type',
        'href' => 'uri'
    );
    
    /**
     * Creates an instance of the XRDS parser.
     *
     * This constructor also initialises the underlying XML parser.
     */
    function XRDSParser() {
        $this->parser = xml_parser_create_ns();
        xml_parser_set_option($this->parser, XML_OPTION_CASE_FOLDING,0);
        xml_set_object($this->parser, $this);
        xml_set_element_handler($this->parser, 'element_start', 'element_end');
        xml_set_character_data_handler($this->parser, 'cdata');
    }
    
    /**
     * Frees memory associated with the underlying XML parser.
     *
     * Note that only the memory associated with the underlying XML parser is
     * freed.  Memory associated with the class itself is not freed.
     *
     * @access public
     */
    function free() {
        xml_parser_free($this->parser);
    }
    
    /**
     * Parses an XRDS document.
     *
     * Once the parsing is complete, use {@link XRDSParser::services()} to obtain
     * the services extracted from the document.
     *
     * @param string $xml the XML document to parse
     * @access public
     */
    function parse($xml) {
        xml_parse($this->parser, $xml);
    }
    
    /**
     * Gets an array of discovered services.
     *
     * @return array an array of discovered services, or an empty array
     * @access public
     * @see XRDSParser::parse()
     */
    function services() {
        return $this->services;
    }
    
    /**
     * Returns the canonical identifier.
     *
     * @return string the canonical identifier
     * @access public
     * @since 0.8
     */
    function subject() {
        return $this->subject;
    }
    
    /**
     * Returns additional identifiers.
     *
     * @return array the additional identifiers
     * @access public
     * @since 0.8
     */
    function aliases() {
        return $this->aliases;
    }

    /**
     * Returns additional properties.
     *
     * @return array the additional properties
     * @access public
     * @since 0.8
     */
    function properties() {
        return $this->properties;
    }
    
    /**
     * XML parser callback
     *
     * @access private
     */
    function element_start(&$parser, $qualified, $attribs) {
        list($ns, $name) = $this->parse_namespace($qualified);

        // Strictly speaking, XML namespace URIs are semi-case sensitive
        // (i.e. the scheme and host are not case sensitive, but other elements
        // are).  However, the XRDS-Simple specifications defines a
        // namespace URI for XRD (xri://$XRD*($v*2.0) rather than xri://$xrd*($v*2.0))
        // with an unusual case.
        if ((strtolower($ns) == strtolower(XRD2_NS)) && ($name == 'Service')) {
            $this->in_service = TRUE;
            $this->service = array();
            
            if (in_array('priority', $attribs)) {
                $this->service['#priority'] = $attribs['priority'];
            }
            if (in_array('id', $attribs)) {
                $this->service['#id'] = $attribs['id'];
            }
        }
        if (($ns == XRD_NS) && ($name == 'Link')) {
            $this->in_service = TRUE;
            $this->service = array();
            
            foreach ($attribs as $name => $value) {
                $this->service[(in_array($name, $this->xrds_map)) ? $this->xrds_map[$name] : $name] = $value;
            }
        }
        
        if ((strtolower($ns) == strtolower(XRD2_NS)) && ($this->in_service)) {
            switch ($name) {
                case 'Type':
                case 'LocalID':
                case 'URI':
                    if (in_array('priority', $attribs)) {
                        $this->priority = $attribs['priority'];
                    } else {
                        $this->priority = NULL;
                    }
            }
        }
        if (strtolower($ns) == strtolower(XRD_NS)) {
            $this->priority = NULL;
        }
        
        $this->_buffer = '';
        $this->_attribs = $attribs;
    }

    /**
     * XML parser callback
     *
     * @access private
     */
    function element_end(&$parser, $qualified) {
        list($ns, $name) = $this->parse_namespace($qualified);
        
        if (($ns == XRD_NS) && !$this->in_service) {
            switch ($name) {
                case 'Subject':
                    $this->subject = trim($this->_buffer);
                    break;
                case 'Alias':
                    $this->aliases[] = trim($this->_buffer);
                    break;
                case 'Property':
                    $this->properties[$this->_attribs['type']] = trim($this->_buffer);
                    break;
            }
        }
        
        if ((strtolower($ns) == strtolower(XRD2_NS)) && ($this->in_service)) {
            switch ($name) {
                case 'Service':
                    foreach (array('type', 'localid', 'uri') as $key) {
                        if (!isset($this->service[$key])) continue;
                        $this->service[$key] = $this->flatten_uris($this->service[$key]);
                    }
                
                    $this->services[] = $this->service;
                    $this->in_service = FALSE;
                    break;

                case 'Type':
                case 'LocalID':
                case 'URI':
                    $key = strtolower($name);
                    if (!isset($this->service[$key])) {
                        $this->service[$key] = array();
                    }
                    if ($this->priority != NULL) {
                        $this->service[$key][] = array('#uri' => trim($this->_buffer), '#priority' => $this->priority);
                    } else {
                        $this->service[$key][] = array('#uri' => trim($this->_buffer));
                    }
                    $this->priority = NULL;
                    break;
            }
        }
        if (($ns == XRD_NS) && ($this->in_service)) {
            switch ($name) {
                case 'Link':
                    $this->services[] = $this->service;
                    $this->in_service = FALSE;
                    break;
                case 'Property':
                    if (!isset($this->service['properties'])) $this->service['properties'] = array();
                    $this->service['properties'][$this->_attribs['type']] = trim($this->_buffer);
                case 'Title':
                    $this->service['title'] = trim($this->_buffer);
                    break;
            }
        }
        
        if ((strtolower($ns) == strtolower(XRD_OPENID_NS)) && ($this->in_service)) {
            switch ($name) {
                case 'Delegate':
                    $this->service['delegate'] = trim($this->_buffer);
            }
        }

        $this->_attribs = array();
    }

    /**
     * XML parser callback
     *
     * @access private
     */
    function cdata(&$parser, $data) {
        $this->_buffer .= $data;
    }
    
    /**
     * Parses a namespace-qualified element name.
     *
     * @param string $qualified the qualified name
     * @return array an array with two elements - the first element contains
     * the namespace qualifier (or an empty string), the second element contains
     * the element name
     * @access protected
     */
    function parse_namespace($qualified) {
        $pos = strrpos($qualified, ':');
        if ($pos !== FALSE) return array(substr($qualified, 0, $pos), substr($qualified, $pos + 1, strlen($qualified)));
        return array('', $qualified);
    }
    
    /**
     * Flattens the service array.
     *
     * In an XRDS document, child elements of the service element often contains
     * a list of URIs, with the priority specified in the priority attribute.
     *
     * When the document is parsed in this class, the URI and the priority are first
     * extracted into the #uri and the #priority keys respectively.  This function
     * takes this array, sorts the elements using the #priority keys (if $sort is
     * true), then collapses the array using the value associated with the #uri key.
     *
     * @param array $array the service array, with URIs and priorities
     * @param bool $sort whether to sort the service array using the #priority
     * keys
     * @return array the services array with URIs sorted by priority
     * @access protected
     */
    function flatten_uris($array, $sort = TRUE) {
        $result = array();
        
        if ($sort) uasort($array, 'discovery_priority_sort');
        
        for ($i = 0; $i < count($array); $i++) {
            $result[] = $array[$i]['#uri'];
        }
        
        return $result;
    }
}

if (!function_exists('rfc3986_urlencode')) {
    /**
     * Encodes a URL using RFC 3986.
     *
     * PHP's rawurlencode function encodes a URL using RFC 1738.  RFC 1738 has been
     * updated by RFC 3986, which change the list of characters which needs to be
     * encoded.
     *
     * Strictly correct encoding is required for various purposes, such as OAuth
     * signature base strings.
     *
     * @param string $s the URL to encode
     * @return string the encoded URL
     */
    function rfc3986_urlencode($s) {
        return str_replace('%7E', '~', rawurlencode($s));
    }
}
?>
