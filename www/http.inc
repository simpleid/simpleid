<?php

function http_request($url, $headers = array(), $method = 'GET', $retry = 3) {
    $curl = curl_init($url);
    
    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($curl, CURLOPT_MAXREDIRS, $retry);
    curl_setopt($curl, CURLOPT_HTTPHEADER, array(implode("\n", $headers) . "\n"));
    
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HEADER, true);
    
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    
    $response = curl_exec($curl);
    $result = array();
    
    if ($response === FALSE) {
        $result['code'] = -curl_errno($curl);
        $result['error'] = curl_error($curl);
    } else {
        
        $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        
        $result['content-type'] = curl_getinfo($curl, CURLINFO_CONTENT_TYPE);
        $result['headers'] = array();
        
        // Parse response.
        $result['raw'] = $response;
        
        $header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        $result['data'] = substr($response, $header_size);
        
        $headers = substr($response, 0, $header_size - 4);

        // In case where redirect occurs, we want the last set of headers
        $header_blocks = explode("\r\n\r\n", $headers);
        $header_block = array_pop($header_blocks);

        $lines = preg_split("/\r\n|\n|\r/", $header_block);
        array_shift($lines);  // Get rid of the status
    
        // Parse headers.
        while ($line = trim(array_shift($lines))) {
            list($header, $value) = explode(':', $line, 2);
            if (isset($result->headers[$header]) && $header == 'Set-Cookie') {
                // RFC 2109: the Set-Cookie response header comprises the token Set-
                // Cookie:, followed by a comma-separated list of one or more cookies.
                $result['headers'][$header] .= ','. trim($value);
            } else {
                $result['headers'][$header] = trim($value);
            }
        }
        
        $valid_responses = array(
            100, 101,
            200, 201, 202, 203, 204, 205, 206,
            300, 301, 302, 303, 304, 305, 307,
            400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417,
            500, 501, 502, 503, 504, 505
        );
    
        // RFC 2616 states that all unknown HTTP codes must be treated the same as the
        // base code in their class.
        if (!in_array($code, $valid_responses)) {
            $code = floor($code / 100) * 100;
        }
    
        switch ($code) {
            case 200: // OK
            case 304: // Not modified
                break;
            case 301: // Moved permanently
            case 302: // Moved temporarily
            case 307: // Moved temporarily
                $result['error'] = 'Redirected too many times.';
                break;
            default:
                $result['error'] = $code;
        }
    
        $result['code'] = $code;
    }
    curl_close($curl);

    return $result;
}

?>
