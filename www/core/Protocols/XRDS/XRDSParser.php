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

use \XMLReader;

/**
 * A simple XRDS parser.
 *
 * This parser uses the classic expat functions available in PHP to parse the
 * XRDS Simple XML document.
 *
 * The result is a {@link XRDSServices} object.
 *
 * @link http://xrds-simple.net/
 */
class XRDSParser {

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
     * XML reader
     * @var XMLReader
     */
    private $reader;
    
    /**
     * Discovered services
     * @var XRDSServices
     */
    private $services;
    
    /**
     * Creates an instance of the XRDS parser.
     *
     * This constructor also initialises the underlying XML parser.
     */
    public function __construct() {
        $this->services = new XRDSServices();
        $this->reader = new XMLReader();
    }
    
    /**
     * Frees memory associated with the underlying XML parser.
     *
     * Note that only the memory associated with the underlying XML parser is
     * freed.  Memory associated with the class itself is not freed.
     *
     * @return void
     */
    public function close() {
        $this->reader->close();
    }

    /**
     * Loads an XRDS document.
     *
     * @param string $xml the XML document to load
     * @return void
     */
    public function load($xml) {
        $this->reader->xml($xml);
    }
    
    /**
     * Parses an XRDS document and returns the discovered services.
     *
     * @return XRDSServices the discovered services
     */
    public function parse() {
        while ($this->reader->read()) {
            if (($this->reader->nodeType == XMLReader::ELEMENT) 
                && (strtolower($this->reader->namespaceURI) == strtolower(self::XRD2_NS))) {
                switch ($this->reader->localName) {
                    case 'Service':
                        $this->services->add($this->parseService());
                        break;
                }
            
            }
        }

        return $this->services;
    }

    /**
     * @return array<string, mixed>
     */
    private function parseService() {
        $service = [];

        if ($this->reader->getAttribute('priority')) {
            $service['#priority'] = $this->reader->getAttribute('priority');
        }
        if ($this->reader->getAttribute('id')) {
            $service['#id'] = $this->reader->getAttribute('id');
        }

        if ($this->reader->isEmptyElement) return $service;

        while ($this->reader->read()) {
            if (($this->reader->nodeType == XMLReader::END_ELEMENT) &&
                (strtolower($this->reader->namespaceURI) == strtolower(self::XRD2_NS)) &&
                ($this->reader->localName == 'Service')) {

                foreach ([ 'type', 'localid', 'uri' ] as $key) {
                    if (!isset($service[$key])) continue;
                    $service[$key] = $this->flatten_uris($service[$key]);
                }
                break;
            }
                

            if (($this->reader->nodeType == XMLReader::ELEMENT) 
                && (strtolower($this->reader->namespaceURI) == strtolower(self::XRD2_NS))) {
                switch ($this->reader->localName) {
                    case 'Type':
                    case 'LocalID':
                    case 'URI':
                        $key = strtolower($this->reader->localName);
                        if (!isset($service[$key])) {
                            $service[$key] = [];
                        }

                        $item = [ '#uri' => trim($this->reader->readString()) ];
                        if ($this->reader->getAttribute('priority'))
                            $item['#priority'] = $this->reader->getAttribute('priority');

                        $service[$key][] = $item;
                        break;
                }
            }

            if (($this->reader->nodeType == XMLReader::ELEMENT) 
                && (strtolower($this->reader->namespaceURI) == strtolower(self::XRD_OPENID_NS)) &&
                ($this->reader->localName == 'Delegate')) {
                $service['delegate'] = trim($this->reader->readString());
            }

        }

        return $service;        
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
     * @param array<array<string, mixed>> $array the service array, with URIs and priorities
     * @param bool $sort whether to sort the service array using the #priority
     * keys
     * @return array<array<string, mixed>> the services array with URIs sorted by priority
     */
    protected function flatten_uris($array, $sort = TRUE) {
        $result = [];
        
        if ($sort) uasort($array, '\SimpleID\Protocols\XRDS\XRDSServices::sortByPriority');
        
        for ($i = 0; $i < count($array); $i++) {
            $result[] = $array[$i]['#uri'];
        }
        
        return $result;
    }
}
?>
