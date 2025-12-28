<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2024-2025
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
 */

namespace SimpleID\Util;

use \Base;
use \SMTP as F3SMTP;

/**
 * This extends the F3 SMTP class with the following additional features:
 * 
 * - Correct encoding of non-ASCII values in MIME headers
 * - Ability to specify Content-Type for attachments
 * - Send messages in HTML
 * 
 * In the F3 implementation, the following special MIME headers are
 * specified.  These headers are not included in the mail message, but
 * instead are used to provide additional commands to the SMTP server
 * 
 * - Sender - specifies the address for the `MAIL FROM` command
 * - Bcc - specifies additional recipients for the `RCPT TO` command
 */
class SMTP extends F3SMTP {
    /**
     * OAuth access token
     * @var string
     */
    protected $oauthToken;

    /**
     * Instantiate class
     * 
     * @param string $host server name
     * @param int $port port
     * @param string|null $scheme security, one of ssl (SSL) or tls (STARTTLS)
     * @param string|null $user user name
     * @param string|null $pw password
     * @param string|null $oauthToken OAuth token
     * @param array<mixed>|null $ctx resource options
     */
    function __construct($host = 'localhost', $port = 25, $scheme = NULL, $user = NULL, $pw = NULL, $oauthToken = NULL, $ctx = NULL) {
        parent::__construct($host, $port, $scheme, $user, $pw, $ctx);
        $this->oauthToken = $oauthToken;
    }

    /**
     * Encodes a MIME header value.
     * 
     * If the value has non-ASCII characters, this function
     * assumes that the value is already UTF-8 encoded.  It then further
     * encodes the entire string in base64.
     * 
     * @param string $val the value to encode
     * @return string the encoded value
     */
    protected function encodeHeaderValue(string $val): string {
        if (preg_match('/[^\x00-\x7F]/', $val) === 1) return sprintf("=?utf-8?B?%s?=", base64_encode($val));;
        return $val;
    }

    /**
     * Encodes a body.
     * 
     * The body can either be a string, or an array with 'html' and (optionally) 'text' keys.
     * If the 'text' key is not specified, the plain text version is automatically generated
     * from the HTML.
     * 
     * @param string|array<string, string> $body the body to encode
     * @param array<string, mixed> &$headers MIME headers.
     * @return string the encoded body
     */
    protected function encodeBody($body, &$headers): string {
        if (is_string($body)) {
            if ($headers['Content-Transfer-Encoding'] == 'quoted-printable')
                $body = preg_replace('/^\.(.+)/m', '..$1', quoted_printable_encode($body));
            return $body;
        } elseif (isset($body['html'])) {
            if (!isset($body['text'])) {
                $body['text'] = strip_tags(preg_replace('{<(head|style|script)\b.*?</\1>}is', '', $body['html']));
            }

            $fw = Base::instance();
            $eol = "\r\n";
            $hash = bin2hex(random_bytes(16));
            $headers['Content-Type'] = 'multipart/alternative; boundary="'. $hash .'"';

            $out = '--' . $hash . $eol;
            $out .= "Content-Type: text/plain; charset=\"" . $fw->get('ENCODING') . "\"" . $eol;
            $out .= "Content-Transfer-Encoding: " . $headers['Content-Transfer-Encoding'] . $eol;
            $out .= $eol;

            if ($headers['Content-Transfer-Encoding'] == 'quoted-printable') {
                $out .= preg_replace('/^\.(.+)/m', '..$1', quoted_printable_encode($body['text'])) . $eol;
            } else {
                $out .= $body['text'] . $eol;
            }

            $out .= $eol;
            $out .= "--" . $hash . $eol;
            $out .= "Content-Type: text/html; charset=\"" . $fw->get('ENCODING') ."\"" . $eol;
            $out .= "Content-Transfer-Encoding: " . $headers['Content-Transfer-Encoding'] . $eol;
            $out .= $eol;

            if ($headers['Content-Transfer-Encoding'] == 'quoted-printable') {
                $out .= preg_replace('/^\.(.+)/m', '..$1', quoted_printable_encode($body['html'])) . $eol;
            } else {
                $out .= $body['html'] . $eol;
            }

            $out .= $eol;
            $out .= "--" . $hash . "--" . $eol;

            unset($headers['Content-Transfer-Encoding']);
            return $out;
        }
        user_error(self::E_Blank, E_USER_ERROR);
        return '';
    }

    /**
     * Adds an attachment
     * 
     * @param string $file the name of the file on the local filesystem to add
     * @param string $type the MIME content type
     * @param string $alias the name of the file as presented in the email
     * @param string $cid the Content-Id
     * @return null
     */
    function attach($file, $type = 'application/octet-stream', $alias = NULL, $cid = NULL) {
        if (!is_file($file))
            user_error(sprintf(self::E_Attach,$file),E_USER_ERROR);
        if ($alias)
            $file = [$alias, $file];
        $this->attachments[] = ['filename' => $file, 'cid' => $cid, 'type' => $type];
        return null;
    }

    /**
     * Transmit message
     * 
     * @param string|array<string, string> $message the body of the message
     * @param bool|string $log whether the response should be saved in `$this->log`
     * @param bool $mock dry run if true
     * @return bool true if the message was successfully sent
     */
    function send($message, $log = TRUE, $mock = FALSE) {
        if (($this->scheme == 'ssl') && !extension_loaded('openssl')) return FALSE;

        // Message should not be blank
        if (!$message) user_error(self::E_Blank, E_USER_ERROR);

        $fw = Base::instance();

        // Retrieve headers
        $headers=$this->headers;

        // Connect to the server
        if (!$mock) {
            $socket = &$this->socket;
            $socket = @stream_socket_client($this->host.':'.$this->port, $errno, $errstr, intval(ini_get('default_socket_timeout')), STREAM_CLIENT_CONNECT, $this->context);
            if (!$socket) {
                $fw->error(500,$errstr);
                return FALSE;
            }
            stream_set_blocking($socket,TRUE);
        }

        // Get server's initial response
        $this->dialog(NULL, $log, $mock);

        // Announce presence
        $reply = $this->dialog('EHLO ' . $fw->get('HOST'), $log, $mock);
        if (strtolower($this->scheme) == 'tls') {
            $this->dialog('STARTTLS', $log, $mock);
            if (!$mock) {
                $method = STREAM_CRYPTO_METHOD_TLS_CLIENT;
                if (defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')) {
                    $method |= STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
                    $method |= STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
                }
                stream_socket_enable_crypto($socket, TRUE, $method);
            }
            $reply = $this->dialog('EHLO ' . $fw->get('HOST'), $log, $mock);
        }

        if (preg_match('/8BITMIME/', $reply)) {
            $headers['Content-Transfer-Encoding'] = '8bit';
        } else {
            $headers['Content-Transfer-Encoding'] = 'quoted-printable';
        }

        $message = $this->encodeBody($message, $headers);

        if (preg_match('/AUTH/', $reply)) {
            // Authenticate
            if ($this->user && $this->pw) {
                $this->dialog('AUTH LOGIN', $log, $mock);
                $this->dialog(base64_encode($this->user), $log, $mock);
                $reply = $this->dialog(base64_encode($this->pw), $log, $mock);
            } elseif ($this->oauthToken) {
                $auth = base64_encode(sprintf("n,a=%s,%shost=%s%sport=%s%sauth=Bearer %s%s%s",
                    $this->user, chr(1), $this->host, chr(1), $this->port, chr(1), $this->oauthToken, chr(1), chr(1)));
                $reply = $this->dialog('AUTH OAUTHBEARER ' . $auth, $log, $mock);
            }

            if (!preg_match('/^235\s.*/', $reply)) {
                $this->dialog('QUIT', $log, $mock);
                if (!$mock && ($socket !== false)) fclose($socket); // @phpstan-ignore notIdentical.alwaysTrue
                return FALSE;
            }
        }

        if (empty($headers['Message-Id']))
            $host_name = parse_url($this->host, PHP_URL_HOST);
            $headers['Message-Id'] = '<' . bin2hex(random_bytes(16)) . '@' . (isset($host_name) ? $host_name : $this->host) . '>';
        if (empty($headers['Date']))
            $headers['Date'] = date('r');

        // Required headers
        $reqd = ['From', 'To', 'Subject'];
        foreach ($reqd as $id) {
            if (empty($headers[$id]))
                user_error(sprintf(self::E_Header,$id),E_USER_ERROR);
        }
        $eol = "\r\n";

        // Stringify headers
        foreach ($headers as $key=>&$val) {
            if (in_array($key,['From','To','Cc','Bcc'])) {
                $email = '';
                preg_match_all('/(?:".+?" |=\?.+?\?= )?(?:<.+?>|[^ ,]+)/', $val,$matches,PREG_SET_ORDER);
                foreach ($matches as $raw) {
                    $email .= ($email ? ', ' : '') . (preg_match('/<.+?>/', $raw[0]) ? $raw[0] : ('<' . $raw[0] . '>'));
                }
                $val = $email;
            }
            unset($val);
        }

        $from = isset($headers['Sender']) ? $headers['Sender'] : strstr($headers['From'],'<');
        unset($headers['Sender']);

        // Start message dialog
        $this->dialog('MAIL FROM: '.$from, $log, $mock);
        foreach ($fw->split($headers['To'] . (isset($headers['Cc']) ? (';'. $headers['Cc']) : '') . (isset($headers['Bcc']) ? (';' . $headers['Bcc']) : '')) as $dst) {
            $this->dialog('RCPT TO: ' . strstr($dst, '<'), $log, $mock);
        }
        unset($headers['Bcc']);

        $this->dialog('DATA', $log, $mock);
        if ($this->attachments) {
            // Replace Content-Type
            $type = $headers['Content-Type'];
            unset($headers['Content-Type']);
            $enc = $headers['Content-Transfer-Encoding'];
            unset($headers['Content-Transfer-Encoding']);

            $hash = bin2hex(random_bytes(16));
            // Send mail headers
            $out='Content-Type: multipart/mixed; boundary="'.$hash.'"'.$eol;
            foreach ($headers as $key=>$val)
                $out.=$key.': '. $this->encodeHeaderValue($val) .$eol;
            $out.=$eol;
            $out.='This is a multi-part message in MIME format'.$eol;
            $out.=$eol;
            $out.='--'.$hash.$eol;
            $out.='Content-Type: '.$type.$eol;

            // Only add Content-Transfer-Encoding if the first part is NOT a multipart
            if (strpos($type, 'multipart/') !== 0)
                $out.='Content-Transfer-Encoding: '.$enc.$eol;

            $out.=$eol;
            $out.=$message.$eol;
            foreach ($this->attachments as $attachment) {
                if (is_array($attachment['filename']))
                    list($alias,$file)=$attachment['filename'];
                else
                    $alias=basename($file=$attachment['filename']);
                $out.='--'.$hash.$eol;
                $out.='Content-Type: ' . $attachment['type'] . $eol;
                $out.='Content-Transfer-Encoding: base64'.$eol;
                if ($attachment['cid'])
                    $out.='Content-Id: '.$attachment['cid'].$eol;
                $out.='Content-Disposition: attachment; '.
                    'filename="'.$alias.'"'.$eol;
                $out.=$eol;
                $contents = file_get_contents($file);
                if ($contents !== false) $out.=chunk_split(base64_encode($contents)).$eol;
            }
            $out.=$eol;
            $out.='--'.$hash.'--'.$eol;
            $out.='.';
            $this->dialog($out,preg_match('/verbose/i',strval($log)),$mock);
        } else {
            // Send mail headers
            $out='';
            foreach ($headers as $key=>$val)
                $out.=$key . ': ' . $this->encodeHeaderValue($val) . $eol;
            $out.=$eol;
            $out.=$message.$eol;
            $out.='.';
            // Send message
            $this->dialog($out,preg_match('/verbose/i',strval($log)),$mock);
        }

        $this->dialog('QUIT',$log,$mock);
        if (!$mock && ($socket !== false)) fclose($socket); // @phpstan-ignore notIdentical.alwaysTrue
        return TRUE;
    }
}

?>
