<?php

/**
 * 
 * This page lists out all the hooks which are available to SimpleID extensions.
 *
 * When implementing these hooks in your extensions, you should replace the word
 * hook with the name of your extension.
 *
 * @package extensions
 */

/**
 * Returns an array of type URIs to be included in SimpleID's XRDS document.
 *
 * For example:
 *
 * <code>
 * <?php
 * return array('http://specs.openid.net/extensions/ui/1.0/lang-pref', 'http://specs.openid.net/extensions/ui/1.0/mode/popup');
 * ?>
 * </code>
 *
 * @return array an array of URIs
 * @since 0.7
 */
function hook_xrds_types() {
}

/**
 * Processes an authentication request that is <i>not</i> about an identifier.
 *
 * The OpenID specifications provides a mechanism for extensions to process
 * authentication requests that are not about an identifier.  Authentication requests
 * about identifiers are automatically processed by the {@link simpleid_checkid_identity()}
 * function and the {@link hook_checkid_identity()} hooks.
 *
 * Assertion results are coded within SimpleID as an integer between 127 ({@link CHECKID_OK})
 * and -127 ({@link CHECKID_PROTOCOL_ERROR}).  Positive values indicate a potential
 * positive assertion (subject to various types of user approval), while negative
 * values indicate a irrecoverable negative assertion.
 *
 * This hook should return one of these values.  If the extension is unable to
 * handle this particular type of authentication request, it should return NULL.
 *
 * @param array $request the OpenID request
 * @param bool $immediate true if openid.mode is checkid_immediate
 * @return int a return value from the list of possible values returned by
 * {@link simpleid_checkid_identity()} or NULL
 * @see simpleid_checkid()
 */
function hook_checkid($request, $immediate) {
}


/**
 * Processes an authentication request where the assertion is potentially
 * positive.
 *
 * Assertion results are coded within SimpleID as an integer between 127 ({@link CHECKID_OK})
 * and -127 ({@link CHECKID_PROTOCOL_ERROR}).  Positive values indicate a potential
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
 * @param array $request the OpenID request
 * @param bool $immediate true if openid.mode is checkid_immediate
 * @return int a return value from the list of possible values returned by
 * {@link simpleid_checkid_identity()} or NULL
 * @see simpleid_checkid_identity()
 */
function hook_checkid_identity($request, $immediate) {
}

/**
 * Gets fields and values to be included in the OpenID response.
 *
 * For positive assertions, this hook should assume that all user approvals
 * have been given and return a response array accordingly.  The extension has
 * the opportunity to modify the response what the user has actually approved
 * in the {@link hook_send() send hook}.
 *
 * This hook will need to provide any aliases required.
 *
 * An example:
 *
 * <code>
 * <?php
 * $alias = openid_extension_alias($my_uri);
 * return array(
 *     'openid.ns.' . $alias => $my_uri,
 *     'openid.' . $alias . '.field' => 'value'
 * );
 * ?>
 * </code>
 *
 * @param bool $assertion true if a positive assertion is made, false otherwise
 * @param array $request the OpenID request
 * @return array the fields and values to include
 */
function hook_response($assertion, $request) {
}
 
/**
 * Gets fields associated with this extension which needs to be signed
 *
 * SimpleID automatically handles signing fields required by the OpenID
 * specification, so only the fields introduced by this extension
 * needed to be returned by this function.
 *
 * The array of fields returned by this function must include any applicable
 * aliases as required.  For example
 *
 * <code>
 * <?php
 * $alias = openid_extension_alias($my_uri);
 * return array($alias . '.field1', $alias . 'field2');
 * ?>
 * </code>
 *
 * @param array $response the OpenID response to sign
 * @return array an array of fields to sign
 */
function hook_signed_fields($response) {
}

/**
 * Determines the format in which assertions are sent, when they are sent via
 * indirect communication.
 *
 * The OpenID specification version 2.0 provides for the sending of assertions
 * via indirect communication.  The original specifications provide that the
 * response should be formatted within the query string.
 *
 * Some extensions to the OpenID specification allows the assertion to be
 * formatted in some other way, e.g. via the fragment.  This hook allows
 * extensions to specify which format the assertion should be sent.
 *
 * If the extension is indifferent regarding the format, it should return
 * null
 *
 * @param string $url the URL of the RP to which the response is to be sent
 * @param array $response the assertion to be sent
 * @return int one of OPENID_RESPONSE_QUERY or OPENID_RESPONSE_FRAGMENT or NULL
 */
function hook_indirect_response($url, $response) {
}

/**
 * Provides additional form items when displaying the login form
 * 
 * @param string $destination he SimpleID location to which the user is directed
 * if login is successful
 * @param string $state the current SimpleID state, if required by the location
 * @see user_login_form()
 */
function hook_user_login_form($destination, $state) {
}


/**
 * Provides additional form items when displaying the relying party consent
 * form
 * 
 *
 * @param array $request the OpenID request
 * @param array $response the proposed OpenID response
 * @param array $rp the user's preferences saved with this relying party
 * @return string HTML code to be inserted into the verification form
 * @see simpleid_consent_form()
 * @deprecated Use {@link hook_consent_form()}
 */
function hook_rp_form($request, $response, $rp) {
}

/**
 * Provides additional form items when displaying the relying party consent
 * form
 * 
 *
 * @param array $request the OpenID request
 * @param array $response the proposed OpenID response
 * @param array $rp the user's preferences saved with this relying party
 * @return string HTML code to be inserted into the verification form
 * @see simpleid_consent_form()
 * @since 0.8
 */
function hook_consent_form($request, $response, $rp) {
}

/**
 * Processes the relying party consent form.
 *
 * This provides the extension with the opportunity to:
 *
 * - modify the OpenID response based on the user's preferences by editing
 *   $response
 * - save the user's preferences by editing $rp
 *
 * @param array $form_request the data submitted by the user in the relying
 * party verification form
 * @param array &$response pointer to the proposed OpenID response
 * @param array &$rp pointer to the user's preferences saved with this relying party
 * @deprecated Use {@link hook_consent()}
 *
 */
function hook_send($form_request, &$response, &$rp) {
}

/**
 * Processes the relying party verification form.
 *
 * This provides the extension with the opportunity to:
 *
 * - modify the OpenID response based on the user's preferences by editing
 *   $response
 * - save the user's preferences by editing $rp
 *
 * @param array $form_request the data submitted by the user in the relying
 * party verification form
 * @param array &$response pointer to the proposed OpenID response
 * @param array &$rp pointer to the user's preferences saved with this relying party
 * @since 0.8
 *
 */
function hook_consent($form_request, &$response, &$rp) {
}

/**
 * Return any additional items provided by the extension to be appended to the
 * Simpleweb route array.
 *
 * @see simpleweb.inc
 * @see simpleid_start()
 * @return array the routes array
 * @since 0.7
 */
function hook_routes() {
}

/**
 * Returns additional blocks to be displayed in the user's dashboard.
 *
 * A block is coded as an array in accordance with the specifications set
 * out in {@link page.inc}.
 *
 * This hook should return an <i>array</i> of blocks, i.e. an array of
 * arrays.
 *
 * @see page_dashboard()
 * @return array an array of blocks to add to the user's dashboard
 * @since 0.7
 */
function hook_page_dashboard() {
}

/**
 * Returns additional blocks to be displayed in the user's profile page.
 *
 * A block is coded as an array in accordance with the specifications set
 * out in {@link page.inc}.
 *
 * This hook should return an <i>array</i> of blocks, i.e. an array of
 * arrays.
 *
 * @see page_profile()
 * @return array an array of blocks to add to the user's profile page
 * @since 0.7
 */
function hook_page_profile() {
}

?>
