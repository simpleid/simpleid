<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014-2022
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

namespace SimpleID\Protocols\XRDS;

use \Prefab;
use SimpleID\Protocols\HTTPResponse;

/**
 * Utility class for XRDS discovery.
 */
class XRDSDiscovery extends Prefab {
    /**
     * Discovers the services for particular identifier.
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
     * @return XRDSServices
     */
    public function discover($identifier, $openid = FALSE) {
        $identifier = $this->normalize($identifier);
        $url = $this->getURL($identifier);

        $xrds = $this->getXRDSDocument($url);

        if ($xrds) {
            return $this->parseXRDS($xrds);
        } else {
            if ($openid) return $this->discoverByHTMLLinks($url);
            return null;
        }
    }

    /**
     * Obtains the OpenID services for particular identifier by scanning for link
     * elements in the returned document.
     *
     * Note that this function does not use the YADIS protocol to scan for services.
     * To use the YADIS protocol, use {@link discovery_get_services()}.
     *
     * @param string $url the URL
     * @return XRDSServices an array of discovered services, or an empty array if no services
     * are found
     */
    public function discoverByHTMLLinks($url) {
        $services = new XRDSServices();
            
        $response = $this->request($url);
        $html = $response->getBody();
            
        $uri = $this->getLinkRel('openid2.provider', $html);
        $delegate = $this->getLinkRel('openid2.local_id', $html);

        if ($uri) {
            $service = [
                'type' => [ 'http://specs.openid.net/auth/2.0/signon' ],
                'uri' => [ $uri ]
            ];
            if ($delegate) $service['localid'] = $delegate;
            $services->add($service, false);
        }

        $uri = $this->getLinkRel('openid.server', $html);
        $delegate = $this->getLinkRel('openid.delegate', $html);
            
        if ($uri) {
            $service = [
                'type' => [ 'http://openid.net/signon/1.0' ],
                'uri' => [ $uri ]
            ];
            if ($delegate) $service['localid'] = $delegate;
            $services->add($service, false);
        }
        
        return $services;
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
    protected function getXRDSDocument($url, $check = TRUE, $retries = 5) {
        if ($retries == 0) return NULL;
        
        $response = $this->request($url, 'Accept: application/xrds+xml');

        if ($response->isHTTPError()) return NULL;
        if (($response->getHeader('Content-Type') == 'application/xrds+xml') || ($check == FALSE)) {
            return $response->getBody();
        } elseif ($response->hasHeader('X-XRDS-Location')) {
            return $this->getXRDSDocument($response->getHeader('X-XRDS-Location'), false, $retries - 1);
        } else {
            $location = $this->getMetaHttpEquiv('X-XRDS-Location', $response->getBody());
            if ($location) {
                return $this->getXRDSDocument($location, false, $retries - 1);
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
    protected function normalize($identifier) {
        $normalized = $identifier;
        
        if ($this->isXRI($identifier)) {
            if (stristr($identifier, 'xri://') !== false) $normalized = substr($identifier, 6);
        } elseif ($this->isEmail($identifier)) {
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
    private function getURL($identifier) {
        if ($this->isXRI($identifier)) {
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
    private function isXRI($identifier) {
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
    private function isEmail($identifier) {
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
     * Parses an XRDS document to return services available.
     *
     * @param string $xrds the XRDS document
     * @return array the parsed structure
     *
     * @see XRDSParser
     */
    protected function parseXRDS($xrds) {
        $parser = new XRDSParser();
        $parser->load($xrds);
        $services = $parser->parse();
        $parser->close();

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
    protected function getMetaHttpEquiv($equiv, $html) {
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
    protected function getLinkRel($rel, $html) {
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
     * Performs an HTTP request.
     *
     * Communication with the web server is conducted using libcurl where possible.
     * Where libcurl does not exist, then sockets will be used.
     *
     * Note that the request must be properly prepared before passing onto this function.
     * For example, for POST requests, the Content-Type and Content-Length headers must be
     * included in $headers.
     *
     * @param string $url the URL
     * @param array|string $headers HTTP headers containing name => value pairs
     * @return HTTPResponse
     */
    protected function request($url, $headers = '') {
        $web = \Web::instance();
        $result = $web->request($url, [ 'header' => $headers ]);
        return new HTTPResponse($result);
    }
}

?>
