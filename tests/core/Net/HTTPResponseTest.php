<?php

namespace SimpleID\Net;

class HTTPResponseTest extends \PHPUnit_Framework_TestCase {
    protected function getOKResponse() {
        return array(
            'body' => '<html><body><h1>It works!</h1></body></html>',
            'headers' => array(
                'HTTP/1.1 200 OK',
                'Date: Sun, 18 Oct 2009 08:56:53 GMT',
                'Server: Apache/2.2.14 (Win32)',
                'Last-Modified: Sat, 20 Nov 2004 07:16:26 GMT',
                'ETag: "10000000565a5-2c-3e94b66c2e680"',
                'Accept-Ranges: bytes',
                'Content-Length: 44',
                'Connection: close',
                'Content-Type: text/html'
            )
        );
    }

    protected function getErrorResponse() {
        return array(
            'body' => '<html><head><title>Not Found</title></head><body>Sorry, the object you requested was not found.</body><html>',
            'headers' => array(
                'HTTP/1.1 404 Not Found',
                'Date: Sun, 18 Oct 2009 08:56:53 GMT',
                'Server: Apache/2.2.14 (Win32)',
                'Content-Length: 108',
                'Connection: close',
                'Content-Type: text/html'
            )
        );
    }

    protected function getInstance($response) {
        return new HTTPResponse($response);
    }

    public function testNetworkError() {
        $response = $this->getInstance(false);
        $this->assertTrue($response->isNetworkError());
        $this->assertTrue($response->isHTTPError());
    }

    public function testHTTPError() {
        $response = $this->getInstance($this->getErrorResponse());
        $this->assertFalse($response->isNetworkError());
        $this->assertTrue($response->isHTTPError());
    }    

    public function testOK() {
        $response = $this->getInstance($this->getOKResponse());
        $this->assertEquals('<html><body><h1>It works!</h1></body></html>', $response->getBody());
        $this->assertEquals(200, $response->getResponseCode());
        $this->assertEquals('"10000000565a5-2c-3e94b66c2e680"', $response->getHeader('ETag'));
        $this->assertFalse($response->hasHeader('X-XRDS-Location'));
    }
}

?>