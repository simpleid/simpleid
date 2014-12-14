<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2007-14
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

/**
 * The namespace identifier for an XRDS document.
 */
const XRDS_NS = 'xri://$xrds';

/**
 * The namespace identifier for XRDS version 2.
 */
const XRD2_NS = 'xri://$xrd*($v*2.0)';

/**
 * The namespace identifier for XRDS Simple.
 */
const XRDS_SIMPLE_NS = 'http://xrds-simple.net/core/1.0';

/**
 * The type identifier for XRDS Simple.
 */
const XRDS_SIMPLE_TYPE = 'xri://$xrds*simple';

/**
 * The namespace identifier for OpenID services.
 */
const XRD_OPENID_NS = 'http://openid.net/xmlns/1.0';


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
     */
    private $parser;
    
    /**
     * Discovered services
     * @var XRDSServices
     */
    private $services;
    
    /**
     * State: are we parsing a service element?
     * @var bool
     */
    private $in_service = FALSE;
    
    /**
     * CDATA buffer
     * @var string
     */
    private $_buffer;
    /**
     * Attributes buffer
     * @var array
     */
    private $_attribs = array();
    
    /**
     * priority attribute buffer
     * @var string
     */
    private $priority = NULL;
    
    /**
     * Currently parsed service buffer
     * @var array
     */
    private $service = array();
    
    /**
     * Creates an instance of the XRDS parser.
     *
     * This constructor also initialises the underlying XML parser.
     */
    public function __construct() {
        $this->services = new XRDSServices();
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
     */
    public function free() {
        xml_parser_free($this->parser);
    }
    
    /**
     * Parses an XRDS document.
     *
     * Once the parsing is complete, use {@link XRDSParser::services()} to obtain
     * the services extracted from the document.
     *
     * @param string $xml the XML document to parse
     */
    public function parse($xml) {
        xml_parse($this->parser, $xml);
    }
    
    /**
     * Gets an array of discovered services.
     *
     * @return array an array of discovered services, or an empty array
     * @see XRDSParser::parse()
     */
    public function services() {
        return $this->services;
    }
    
    /**
     * XML parser callback
     *
     */
    private function element_start(&$parser, $qualified, $attribs) {
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
        
        $this->_buffer = '';
        $this->_attribs = $attribs;
    }

    /**
     * XML parser callback
     *
     */
    private function element_end(&$parser, $qualified) {
        list($ns, $name) = $this->parse_namespace($qualified);
        
        if ((strtolower($ns) == strtolower(XRD2_NS)) && ($this->in_service)) {
            switch ($name) {
                case 'Service':
                    foreach (array('type', 'localid', 'uri') as $key) {
                        if (!isset($this->service[$key])) continue;
                        $this->service[$key] = $this->flatten_uris($this->service[$key]);
                    }
                
                    $this->services->add($this->service);
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
     */
    private function cdata(&$parser, $data) {
        $this->_buffer .= $data;
    }
    
    /**
     * Parses a namespace-qualified element name.
     *
     * @param string $qualified the qualified name
     * @return array an array with two elements - the first element contains
     * the namespace qualifier (or an empty string), the second element contains
     * the element name
     */
    protected function parse_namespace($qualified) {
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
     */
    protected function flatten_uris($array, $sort = TRUE) {
        $result = array();
        
        if ($sort) uasort($array, '\SimpleID\Protocols\XRDS\XRDSServices::sortByPriority');
        
        for ($i = 0; $i < count($array); $i++) {
            $result[] = $array[$i]['#uri'];
        }
        
        return $result;
    }
}
?>
