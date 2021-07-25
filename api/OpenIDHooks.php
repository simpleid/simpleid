<?php

namespace SimpleID\API;

/**
 * OpenID related hooks
 */
abstract class OpenIDHooks {
    /**
     * Returns an array of type URIs to be included in SimpleID's XRDS document
     * (previously `hook_xrds_types`).
     *
     * For example:
     *
     * <code>
     * 
     * return array('http://specs.openid.net/extensions/ui/1.0/lang-pref', 'http://specs.openid.net/extensions/ui/1.0/mode/popup');
     * 
     * </code>
     *
     * @return array an array of URIs
     * @since 2.0
     */
    abstract function xrdsTypesHook();

    /**
     * Processes an authentication request that is <i>not</i> about an identifier
     * (previously `hook_checkid`).
     *
     * The OpenID specifications provides a mechanism for extensions to process
     * authentication requests that are not about an identifier.  Authentication requests
     * about identifiers are automatically processed by the {@link SimpleID\Protocols\OpenID\OpenIDModule::openIDCheckIdentity()}
     * function and the {@link openIDCheckIdentityHook()} hooks.
     *
     * Assertion results are coded within SimpleID as an integer between 127 ({@link CHECKID_OK})
     * and -127 ({@link CHECKID_PROTOCOL_ERROR}).  Positive values indicate a potential
     * positive assertion (subject to various types of user approval), while negative
     * values indicate a irrecoverable negative assertion.
     *
     * This hook should return one of these values.  If the extension is unable to
     * handle this particular type of authentication request, it should return NULL.
     *
     * @param SimpleID\Protocols\OpenID\Request $request the OpenID request
     * @param bool $immediate true if openid.mode is checkid_immediate
     * @return int a return value from the list of possible values returned by
     * {@link SimpleID\Protocols\OpenID\OpenIDModule::openIDCheckIdentity()} or NULL
     */
    abstract function openIDCheckExtensionHook($request, $immediate);

    /**
     * Processes an authentication request where the assertion is potentially
     * positive (previously `hook_checkid_identity`).
     *
     * Assertion results are coded within SimpleID as an integer between 127 ({@link SimpleID\Protocols\OpenID\OpenIDModule::CHECKID_OK})
     * and -127 ({@link SimpleID\Protocols\OpenID\OpenIDModule::CHECKID_PROTOCOL_ERROR}).  Positive values indicate a potential
     * positive assertion (subject to various types of user approval), while negative
     * values indicate a irrecoverable negative assertion.
     *
     * Extensions are able to examine the authentication request to modify change
     * the assertion result from positive to negative.  As SimpleID takes the
     * minimum from the results returned by this hook, extensions are
     * not able to change the assertion result from negative to positive.
     *
     * If the extension is indifferent to the result of the current authentication
     * request (e.g. it cannot understand it), it should return NULL.
     *
     * This hook is not called at all if SimpleID determines that the assertion
     * is negative.
     *
     * @param SimpleID\Protocols\OpenID\Request $request the OpenID request
     * @param string $identity the identity to be checked against
     * @param bool $immediate true if openid.mode is checkid_immediate
     * @return int a return value from the list of possible values returned by
     * {@link SimpleID\Protocols\OpenID\OpenIDModule::openIDCheckIdentity()} or NULL
     */
    abstract function openIDCheckIdentityHook($request, $identity, $immediate);

    /**
     * Modifies an OpenID response (previously `hook_response`).
     *
     * For positive assertions, this hook should assume that all user approvals
     * have been given and return a response array accordingly.  Where consent
     * is required, the response can be further modified in the
     * {@link openIDConsentFormSubmitHook()} hook.
     *
     * This hook will need to provide any aliases required.
     *
     * An example:
     *
     * <code>
     * $alias = $request->getAliasForExtension($my_uri);
     * $response['ns' . $alias] = $my_uri;
     * $response[$alias . '.field'] = 'value';
     * </code>
     *
     * @param bool $assertion true if a positive assertion is made, false otherwise
     * @param SimpleID\Protocols\OpenID\Request $request the OpenID request
     * @param SimpleID\Protocols\OpenID\Response $response the OpenID response to modify
     */
    abstract function openIDResponseHook($assertion, $request, $response);

    /**
     * Provides additional form items when displaying the relying party consent
     * form (previously `hook_consent_form`).
     *
     * The state of the consent form is specified in the `$form_state`
     * array.  The array has the following elements:
     *
     * - `rq` the Request object
     * - `rs` the Response object
     * - `code` the result code from the list of possible values returned by
     * {@link SimpleID\Protocols\OpenID\OpenIDModule::openIDCheckIdentity()}
     * - `prefs` the user preferences for this relying party
     * 
     * @param array $form_state the form state
     * @return array an array of form elements
     * @since 0.8
     */
    abstract function openIDConsentFormHook($form_state);

    /**
     * Processes the relying party consent form (previously `hook_consent`).
     *
     * This provides the extension with the opportunity to modify the OpenID response
     * or the change the user's preferences by editing `$form_state`.
     * 
     * `$form_state` contains the same element as per the
     * {@link SimpleID\Protocols\OpenID\OpenIDModule::openIDCheckIdentity()} hook, except that this is now passed by reference
     *
     * @param SimpleID\Util\Forms\FormState $form_state the form state
     *
     */
    abstract function openIDConsentFormSubmitHook($form_state);
}

?>
