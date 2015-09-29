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
 * 
 */

namespace SimpleID\Protocols\OAuth;

use Psr\Log\LogLevel;
use SimpleID\Module;
use SimpleID\ModuleManager;

/**
 * Base class for SimpleID modules providing access to resources protected
 * by OAuth.
 *
 * This class contains various convenience functions to {@link OAuthManager}
 * and its methods.
 */
class OAuthProtectedResource extends Module {

    /**
     * @var OAuthManager the OAuth manager
     */
    protected $oauth;

    /**
     * @var bool whether to detect access tokens from the request body
     */
    protected $oauth_include_request_body = false;


    public function __construct() {
        parent::__construct();
        $this->oauth = OAuthManager::instance();
    }

    /**
     * FatFree Framework event handler.
     *
     * This event handler initialises the user system.  It starts the PHP session
     * and loads data for the currently logged-in user, if any.
     *
     */
    public function beforeroute() {
        $this->oauth->initAccessToken($this->oauth_include_request_body);
    }

    /**
     * Returns the current access token.
     *
     * This is a shortcut for {@link SimpleID\Protocols\OAuth\OAuthManager::getAccessToken()}.
     *
     * @return AccessToken the access token
     */
    protected function getAccessToken() {
        return $this->oauth->getAccessToken();
    }

    /**
     * Returns the authorisation associated with the current access token.
     *
     * This is a shortcut for {@link SimpleID\Protocols\OAuth\OAuthManager::getAuthorization()}.
     *
     * @return Authorization the authorisation
     */
    protected function getAuthorization() {
        if (!$this->oauth->getAccessToken()) return null;
        return $this->oauth->getAccessToken()->getAuthorization();
    }

    /**
     * Returns the owner of the authorisation associated with the current
     * access token.
     *
     * This is a shortcut for {@link SimpleID\Protocols\OAuth\Authorization::getOwner()}.
     *
     * @return Storable the owner
     */
    protected function getTokenOwner() {
        if (!$this->oauth->getAccessToken()) return null;
        return $this->oauth->getAccessToken()->getAuthorization()->getOwner();
    }

    /**
     * Returns the client of the authorisation associated with the current
     * access token.
     *
     * This is a shortcut for {@link SimpleID\Protocols\OAuth\Authorization::getClient()}.
     *
     * @return Storable the client
     */
    protected function getTokenClient() {
        if (!$this->oauth->getAccessToken()) return null;
        return $this->oauth->getAccessToken()->getAuthorization()->getClient();
    }

    /**
     * Returns whether the current access token is authorised under the
     * specified scope.
     *
     * This is a shortcut for {@link SimpleID\Protocols\OAuth\OAuthManager::isTokenAuthorized()}.
     *
     * @param array|string $scope the scope
     * @param string &$error the error code returned if the access token
     * is not authorised
     * @return bool true if the access token is authorised
     */
    protected function isTokenAuthorized($scope, &$error = null) {
        return $this->oauth->isTokenAuthorized($scope, $error);
    }

    /**
     * Sends an OAuth unauthorised response with a WWW-Authenticate header.
     *
     * @param string $error the error code
     * @param string $error_description human readable error information
     * @param array $additional any additional data to be sent with the error
     * message
     * @param string $html the format of the error message
     * @param string $status the HTTP status to send
     */
    protected function unauthorizedError($error, $error_description = NULL, $additional = array(), $format = 'html', $status = 401) {
        $this->f3->status($status);

        if ($error) {
            $header = 'WWW-Authenticate: Bearer ';
            $header .= 'realm="' . addcslashes($this->f3->get('REALM'), '"') . '", ';
            $header .= 'error="' . addcslashes($error, '"') . '"';
            if ($error_description != NULL) $header .= ', error_description="' . addcslashes($error_description, '"') . '"';
            foreach ($additional as $param => $value) {
                $header .= ', ' . $param . '="' . addcslashes($value, '"') . '"';
            }
            
            header($header);
        }

        switch ($format) {
            case 'json':
                $result = array_merge($additional, array('error' => $error));
                if ($error_description) $result['error_description'] = $error_description;
                header('Content-Type: application/json');
                print json_encode($result);
                break;
            case 'html':
            default:
                $this->fatalError($error_description);
                break;
        }
        exit;
    }
}


?>
