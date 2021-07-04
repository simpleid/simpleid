<?php

namespace SimpleID\Protocols\XRDS;

use PHPUnit\Framework\TestCase;
use SimpleID\Util\HTTPResponse;

class XRDSDiscoveryStub extends XRDSDiscovery {
    protected function request($url, $headers = '') {
        switch ($url) {
            case 'http://example.com/xrds':
                return new HTTPResponse(array(
                    'body' => XRDSTest::getXRDSDocument(),
                    'headers' => array(
                        'HTTP/1.1 200 OK',
                        'Content-Type: application/xrds+xml'
                    )
                ));
                break;
            case 'http://example.com/xrds-redirect':
                return new HTTPResponse(array(
                    'body' => '<html><head><link rel="openid.server" href="http://www.example.com/simpleid/" /><link rel="openid2.provider" href="http://www.example.com/simpleid/" /></head><body></body></html>',
                    'headers' => array(
                        'HTTP/1.1 200 OK',
                        'Content-Type: text/html',
                        'X-XRDS-Location: http://example.com/xrds'
                    )
                ));
                break;
            case 'http://example.com/xrds-html':
                return new HTTPResponse(array(
                    'body' => '<html><head><meta http-equiv="X-XRDS-Location" content="http://example.com/xrds" /></head><body></body></html>',
                    'headers' => array(
                        'HTTP/1.1 200 OK',
                        'Content-Type: text/html'
                    )
                ));
                break;
            case 'http://example.com/html-links':
                return new HTTPResponse(array(
                    'body' => '<html><head><link rel="openid.server" href="http://www.example.com/simpleid/" /><link rel="openid2.provider" href="http://www.example.com/simpleid/" /></head><body></body></html>',
                    'headers' => array(
                        'HTTP/1.1 200 OK',
                        'Content-Type: text/html'
                    )
                ));
                break;
        }
        
    }
}

class XRDSTest extends TestCase {
    static function getXRDSDocument() {
        return
'<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)" xmlns:openid="http://openid.net/xmlns/1.0">
    <XRD ref="xri://=example">
        <Query>*example</Query>
        <Status ceid="off" cid="verified" code="100"/>
        <Expires>2008-05-05T00:15:00.000Z</Expires>
        <ProviderID>xri://=</ProviderID>
        <!-- synonym section -->
        <LocalID priority="10">!4C72.6C81.D78F.90B2</LocalID>
        <EquivID priority="10">http://example.com/example-user</EquivID>
        <EquivID priority="15">http://example.net/blog</EquivID>
        <CanonicalID>xri://=!4C72.6C81.D78F.90B2</CanonicalID>
        <!-- service section -->
        <Service>
            <!-- XRI resolution service -->
            <ProviderID>xri://=!F83.62B1.44F.2813</ProviderID>
            <Type>xri://$res*auth*($v*2.0)</Type>
            <MediaType>application/xrds+xml</MediaType>
            <URI priority="10">http://resolve.example.com</URI>
            <URI priority="15">http://resolve2.example.com</URI>
            <URI>https://resolve.example.com</URI>
        </Service>
        <!-- OpenID 2.0 login service -->
        <Service priority="10">
            <Type>http://specs.openid.net/auth/2.0/signon</Type>
            <URI>http://www.myopenid.com/server</URI>
            <LocalID>http://example.myopenid.com/</LocalID>
        </Service>
        <!-- OpenID 1.0 login service -->
        <Service priority="20">
            <Type>http://openid.net/server/1.0</Type>
            <URI>http://www.livejournal.com/openid/server.bml</URI>
            <openid:Delegate>http://www.livejournal.com/users/example/</openid:Delegate>
        </Service>
        <!-- untyped service for access to files of media type JPEG -->
        <Service priority="10">
            <Type match="null" />
            <Path select="true">/media/pictures</Path>
            <MediaType select="true">image/jpeg</MediaType>
            <URI append="path" >http://pictures.example.com</URI>
        </Service>
    </XRD>
</xrds:XRDS>';
    }

    protected function getParser() {
        return new XRDSParser();
    }

    protected function getHTMLDiscoveryStub() {
        $stub = $this->getMockBuilder('\SimpleID\Protocols\XRDS\XRDSDiscovery')->getMock();
        $stub->method('request')->willReturn();
        return $stub;
    }

    public function testParser() {
        $parser = $this->getParser();
        $parser->load(self::getXRDSDocument());
        $services = $parser->parse();
        $parser->close();

        $this->assertEquals(4, $services->getLength());
    }

    public function testType() {
        $parser = $this->getParser();
        $parser->load(self::getXRDSDocument());
        $services = $parser->parse();
        $parser->close();

        $service = $services->getByType('http://openid.net/server/1.0');
        $this->assertCount(1, $service);
        $this->assertEquals('http://www.livejournal.com/openid/server.bml', $service[0]['uri'][0]);
    }

    public function testXRDS() {
        $discovery = new XRDSDiscoveryStub();
        $services = $discovery->discover('http://example.com/xrds');
        $this->assertEquals(4, $services->getLength());
    }

    public function testXRDSWithRedirect() {
        $discovery = new XRDSDiscoveryStub();        
        $services = $discovery->discover('http://example.com/xrds-redirect');
        $this->assertEquals(4, $services->getLength());
    }

    public function testXRDSWithHTML() {
        $discovery = new XRDSDiscoveryStub();        
        $services = $discovery->discover('http://example.com/xrds-html');
        $this->assertEquals(4, $services->getLength());
    }

    public function testHTMLDiscovery() {
        $discovery = new XRDSDiscoveryStub();
        $services = $discovery->discoverByHTMLLinks('http://example.com/html-links');

        $service = $services->getByType('http://specs.openid.net/auth/2.0/signon');
        $this->assertCount(1, $service);
        $this->assertEquals('http://www.example.com/simpleid/', $service[0]['uri'][0]);
    }
}

?>