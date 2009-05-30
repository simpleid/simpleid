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
 * Support for XRDS based discovery.
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
 * @param string $identifier the identifier
 * @param bool $openid if true, performs additional discovery of OpenID services
 * by looking for link elements within the discovered document
 * @param array an array of discovered services, or an empty array if no services
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
    
    $response = http_request($url, array('Accept' => 'application/xrds+xml'));

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
 * If the identifier begins with xri://, this is stripped out.  If the identifier
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
    $parser =& new XRDSParser();
    
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
 * @param array an array of discovered services, or an empty array if no services
 * are found
 */
function discovery_get_openid_services($url) {
    $services = array();
        
    $response = http_request($url);
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
 * Searches through an HTML document to obtain the value of a meta
 * element with a specified http-equiv attribute.
 *
 * @param string $equiv the http-equiv attribute for which to search
 * @param string $html the HTML document to search
 * @return mixed the value of the meta element, or FALSE if the element is not
 * found
 */
function _discovery_meta_httpequiv($equiv, $html) {
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
 * XRDS XML document.
 *
 * The result is an array of discovered services.
 */
class XRDSParser {
    var $parser;
    var $services = array();
    
    var $in_service = FALSE;
    var $buffer;
    var $priority = NULL;
    var $service = array();
    
    function XRDSParser() {
        $this->parser = xml_parser_create_ns();
        xml_set_object($this->parser, $this);
        xml_set_element_handler($this->parser, 'element_start', 'element_end');
        xml_set_character_data_handler($this->parser, 'cdata');
    }
    
    function free() {
        xml_parser_free($this->parser);
    }
    
    function parse($xml) {
        xml_parse($this->parser, $xml);
    }
    
    function services() {
        return $this->services;
    }

    function element_start(&$parser, $qualified, $attribs) {
        list($ns, $name) = $this->parse_namespace($qualified);
        $name = strtolower($name);
        
        // Expat XML parser returns namespaces in uppercase
        if (($ns == strtoupper(XRD2_NS)) && ($name == 'service')) {
            $this->in_service = TRUE;
            $this->service = array();
            
            if (in_array('priority', $attribs)) {
                $this->service['#priority'] = $attribs['priority'];
            }
            if (in_array('id', $attribs)) {
                $this->service['#id'] = $attribs['id'];
            }
        }
        
        if (($ns == strtoupper(XRD2_NS)) && ($this->in_service)) {
            switch ($name) {
                case 'type':
                case 'localid':
                case 'uri':
                    if (in_array('priority', $attribs)) {
                        $this->priority = $attribs['priority'];
                    } else {
                        $this->priority = NULL;
                    }
            }
        }
        
        $this->buffer = '';
    }

    function element_end(&$parser, $qualified) {
        list($ns, $name) = $this->parse_namespace($qualified);
        $name = strtolower($name);
        
        if (($ns == strtoupper(XRD2_NS)) && ($this->in_service)) {
            switch ($name) {
                case 'service':
                    foreach (array('type', 'localid', 'uri') as $key) {
                        if (!isset($this->service[$key])) continue;
                        $this->service[$key] = $this->flatten_uris($this->service[$key]);
                    }
                
                    $this->services[] = $this->service;
                    $this->in_service = FALSE;
                    break;

                case 'type':
                case 'localid':
                case 'uri':
                    if (!isset($this->service[$name])) {
                        $this->service[$name] = array();
                    }
                    if ($this->priority != NULL) {
                        $this->service[$name][] = array('#uri' => trim($this->buffer), '#priority' => $this->priority);
                    } else {
                        $this->service[$name][] = array('#uri' => trim($this->buffer));
                    }
                    $this->priority = NULL;
                    break;
            }
        }
        
        if (($ns == strtoupper(XRD_OPENID_NS)) && ($this->in_service)) {
            switch ($name) {
                case 'delegate':
                    $this->service['delegate'] = trim($this->buffer);
            }
        }

    }

    function cdata(&$parser, $data) {
        $this->buffer .= $data;
    }
    
    function parse_namespace($qualified) {
        $pos = strrpos($qualified, ':');
        if ($pos !== FALSE) return array(substr($qualified, 0, $pos), substr($qualified, $pos + 1, strlen($qualified)));
        return array('', $qualified);
    }
    
    function flatten_uris($array) {
        $result = array();
        
        uasort($array, 'discovery_priority_sort');
        
        for ($i = 0; $i < count($array); $i++) {
            $result[] = $array[$i]['#uri'];
        }
        
        return $result;
    }
}

?>
