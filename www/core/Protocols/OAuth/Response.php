<?php
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2014
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

namespace SimpleID\Protocols\OAuth;

use \Base;
use SimpleID\Util\ArrayWrapper;

/**
 * A class representing an OAuth authorization or token (or similar)
 * response.
*
 * This class is a subclass of {@link ArrayWrapper}.  Response parameters
 * are stored in {@link ArrayWrapper->container} and are accessed
 * using array syntax.
 */
class Response extends ArrayWrapper {
    /** Parameter for {@link $response_mode} */
    const QUERY_RESPONSE_MODE = 'query';

    /** Parameter for {@link $response_mode} */
    const FRAGMENT_RESPONSE_MODE = 'fragment';

    /** Parameter for {@link $response_mode} */
    const FORM_POST_RESPONSE_MODE = 'form_post';

    /** @var int for redirect response, the response mode.
     * This can be one of {@link QUERY_RESPONSE_MODE}
     * (the query string), {@link FRAGMENT_RESPONSE_MODE} (the fragment) or
     * {@link FORM_POST_RESPONSE_MODE} (as a page with an automaticlly submitting
     * form using the `POST` method)
     */
    protected $response_mode = self::QUERY_RESPONSE_MODE;

    /** @var string the redirect URI */
    protected $redirect_uri = null;

    /**
     * Creates an OAuth response.
     *
     * An OAuth response is created based on an OAuth request.  The
     * response will contain the same `state` and `redirect_uri`
     * parameters as the underlying request.
     * 
     * @param Request $request the request to which the response will
     * be made
     * @param array $data the initial response parameters
     */
    public function __construct($request = NULL, $data = array()) {
        parent::__construct($data);

        if ($request != NULL) {
            if (isset($request['state'])) $this->container['state'] = $request['state'];
            if (isset($request['redirect_uri'])) $this->redirect_uri = $request['redirect_uri'];
        }
    }

    /**
     * Gets the flow to be used in redirect responses.
     *
     * @return string the response mode
     */
    public function getResponseMode() {
        return $this->response_mode;
    }

    /**
     * Sets the response mode to be used in redirect responses.  This should
     * be either QUERY_RESPONSE_MODE or FRAGMENT_RESPONSE_MODE
     *
     * @param string $flow the response mode
     */
    public function setResponseMode($response_mode) {
        $this->response_mode = $response_mode;
    }

    /**
     * Sets the redirect URI.
     *
     * @param string $redirect_uri the redirect URI to set
     */
    public function setRedirectURI($redirect_uri) {
        $this->redirect_uri = $redirect_uri;
    }

    /**
     * Returns the redirect URI.
     *
     * @return string the redirect URI
     */
    public function getRedirectURI() {
        return $this->redirect_uri;
    }

    /**
     * Determines whether the current OAuth response is an error
     * response.
     *
     * A response is an error response if it contains the key `error`.
     *
     * @return bool true if the response is an error response
     */
    public function isError() {
        return isset($this->container['error']);
    }

    /**
     * Sets parameters in the current response so that it is an error response.
     *
     * Note that existing parameters set in the response are not removed.
     *
     * @param string $error the OAuth error code
     * @param string $error_description the OAuth error description
     * @param array $additional additional parameters to include
     * @return Response this object (for chaining)
     */
    public function setError($error, $error_description = NULL, $additional = array()) {
        foreach (array_keys($this->container) as $key) {
            if ($key != 'state') unset($this->container[$key]);
        }
        $this->container['error'] = $error;
        if ($error_description != null) $this->container['error_description'] = $error_description;
        $this->container = array_merge($this->container, $additional);
        return $this;
    }

    /**
     * Renders the response as a redirect or a form post.
     *
     * Redirect responses are used in the OAuth authorization endpoint.
     *
     * @param string $redirect_uri the URL to which the response is sent.
     * If null, the {@link $redirect_uri} property will be used
     * 
     */
    public function renderRedirect($redirect_uri = NULL) {
        $f3 = Base::instance();

        if ($redirect_uri == NULL) $redirect_uri = $this->redirect_uri;

        if ($this->response_mode == self::FORM_POST_RESPONSE_MODE) $this->renderFormPost($redirect_uri);

        // 1. Firstly, get the query string
        $query = str_replace(array('+', '%7E'), array('%20', '~'), http_build_query($this->container));
        
        // 2. If there is no query string, then we just return the URL
        if (!$query) return $redirect_uri;
        
        // 3. The URL may already have a query and a fragment.  If this is so, we
        //    need to slot in the new query string properly.  We disassemble and
        //    reconstruct the URL.
        $parts = parse_url($redirect_uri);
        
        $url = $parts['scheme'] . '://';
        if (isset($parts['user'])) {
            $url .= $parts['user'];
            if (isset($parts['pass'])) $url .= ':' . $parts['pass'];
            $url .= '@';
        }
        $url .= $parts['host'];
        if (isset($parts['port'])) $url .= ':' . $parts['port'];
        if (isset($parts['path'])) $url .= $parts['path'];
        
        if (($this->response_mode == self::QUERY_RESPONSE_MODE) || (strpos($url, '#') === FALSE)) {
            $url .= '?' . ((isset($parts['query'])) ? $parts['query'] . '&' : '') . $query;
            if (isset($parts['fragment'])) $url .= '#' . $parts['fragment'];
        } elseif ($this->response_mode == self::FRAGMENT_RESPONSE_MODE) {
            // In theory $parts['fragment'] should be an empty string, but the
            // current draft specification does not prohibit putting other things
            // in the fragment.
            if (isset($parts['query'])) {
                $url .= '?' . $parts['query'] . '#' . $parts['fragment'] . '&' . $query;
            } else {
                $url .= '#' . $parts['fragment'] . '&' . $query;
            }
        }

        $f3->status(303);
        header('Location: ' . $url);
    }

    /**
     * Renders the response as a JSON object.
     *
     * JSON responses are used in the OAuth token endpoint, and other endpoints.
     *
     * @param int $status the HTTP status code.  If null, the status code is `400`
     * for error responses and `200` otherwise.
     * 
     */
    public function renderJSON($status = NULL) {
        $f3 = Base::instance();

        if ($status == NULL) {
            $status = ($this->isError()) ? 400 : 200;
        }
        $f3->status($status);
        $f3->expire(0);
    
        header('Content-Type: application/json;charset=UTF-8');
        header('Pragma: no-cache');
        print json_encode($this->container);
    }

    /**
     * Renders the response as a POST request.
     *
     * @param string $url the URL to which the response is sent
     * 
     */
    public function renderFormPost($url = NULL) {
        $f3 = Base::instance();
        $tpl = new \Template();

        if ($url == NULL) $url = $this->redirect_uri;

        $f3->set('url', $url);
        $f3->set('params', $this->container);
        print $tpl->render('post.html');
    }

    /**
     * Returns the response modes supported by this class.
     *
     * @return array list of response modes
     */
    public static function getResponseModesSupported() {
        return array(self::QUERY_RESPONSE_MODE, self::FRAGMENT_RESPONSE_MODE, self::FORM_POST_RESPONSE_MODE);
    }
}

?>