<?php

namespace SimpleID\API;

/**
 * OpenID related hooks
 */
abstract class OAuthHooks {
    /**
     * Authenticates a client
     *
     * @return array|null an array containing `#client` - a 
     * {@link SimpleID\Protocols\OAuth\Client}) representing the client authenticated
     * under this method; and `#client_auth_method` - a string
     * representing the authentication method used
     */
    abstract function oAuthInitClientHook();

    /**
     * Authenticates an access token
     *
     * @return SimpleID\Protocols\OAuth\AccessToken|null
     */
    abstract function oAuthInitAccessTokenHook();

    /**
     * Returns the OAuth scopes available from this module.
     *
     * See {@link SimpleID\Protocols\Connect\ConnectModule::scopesHook()}
     * for an example of the structure of the array to be returned.
     *
     * @return array the OAuth scopes
     */
    abstract function scopesHook();

    /**
     * Resolves an OAuth authorisation request.
     *
     * Under certain OAuth-based protocols, the authorisation request
     * may contain parameters which require resolution before the request
     * can be processed further.  For example, under OpenID Connect,
     * the `request_uri` parameter will require a query to obtain the
     * request object
     *
     * Implementations can use methods in `$request` and `$response` to
     * modify the request, generate errors, etc.
     *
     * @param SimpleID\Protocols\OAuth\Request the authorisation request
     * @param SimpleID\Protocols\OAuth\Response the OAuth response
     */
    abstract function oAuthResolveAuthRequestHook($request, $response);

    /**
     * Checks an OAuth authorisation request for protocol compliance.
     *
     * Implementations can use methods in `$response` to
     * generate errors, etc.
     *
     * @param SimpleID\Protocols\OAuth\Request the authorisation request
     * @param SimpleID\Protocols\OAuth\Response the OAuth response
     */
    abstract function oAuthCheckAuthRequestHook($request, $response);

    /**
     * Processes an OAuth authorisation request to determine whether the
     * user has granted access.
     *
     * @param SimpleID\Protocols\OAuth\Request the authorisation request
     * @param SimpleID\Protocols\OAuth\Response the OAuth response
     * @return int one of CHECKID_OK, CHECKID_APPROVAL_REQUIRED, CHECKID_LOGIN_REQUIRED, CHECKID_INSUFFICIENT_TRUST
     * or CHECKID_USER_DENIED
     */
    abstract function oAuthProcessAuthRequestHook($request, $response);

    /**
     * Returns the response types available.
     *
     * @return array an array of string containing the response types
     * available
     */
    abstract function oAuthResponseTypesHook();

    /**
     * Invoked when an authorisation request has been granted.
     *
     * Under an implicit flow, both this hook and the {@link oAuthTokenHook()} will be
     * called.
     *
     * @param SimpleID\Protocols\OAuth\Authorization $Authorization the authorisation to
     * be granted
     * @param SimpleID\Protocols\OAuth\Request $request the authorisation request
     * @param SimpleID\Protocols\OAuth\Response $response the authorisation response
     * @param array $scopes the requested scope
     */
    abstract function oAuthGrantAuthHook($authorization, $request, $response, $scopes);

    /**
     * Invoked when an access token is being issued.
     *
     * This hook is called at the authorisation endpoint (under implicit flow), or
     * at the token endpoint (under authorisation code or refresh token flows).
     *
     * Under an implicit flow, both this hook and the {@link oAuthGrantAuthHook()} will be
     * called.
     *
     * @param string $grant_type the grant type
     * @param SimpleID\Protocols\OAuth\Authorization $Authorization the authorisation to
     * be granted
     * @param SimpleID\Protocols\OAuth\Request $request the authorisation request
     * @param SimpleID\Protocols\OAuth\Response $response the authorisation response
     * @param array $scopes the requested scope
     */
    abstract function oAuthTokenHook($grant_type, $authorization, $request, $response, $scopes);

    /**
     * Provides additional form items when displaying the OAuth authorisation
     * request form.
     *
     * The state of the consent form is specified in the `$form_state`
     * array.  The array has the following elements:
     *
     * - `rq` the Request object
     * - `rs` the Response object
     * 
     * @param SimpleID\Util\Forms\FormState $form_state the form state
     * @return array an array of form elements
     */
    abstract function oAuthConsentFormHook($form_state);

    /**
     * Processes the OAuth authorisation request form.
     *
     * @param SimpleID\Util\Forms\FormState $form_state the form state
     *
     */
    abstract function oAuthConsentFormSubmitHook($form_state);

}

?>
