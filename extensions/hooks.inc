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
 * Returns the OpenID Type URI for this extension.  Mandatory for all extensions.
 *
 * @return string the Type URI for this extension
 */
function hook_ns() {
}

/**
 * Returns the default alias for this extension.  Mandatory for all extensions
 *
 * @return string the default alias
 */
function hook_default_alias() {
}
 
/**
 * Gets fields and values associated with this extension when a positive assertion response
 * is made.
 *
 * @param mixed $request the OpenID request
 * @return mixed the OpenID response
 */
function hook_id_res($request) {
}


/**
 * Gets fields associated with this extension which needs to be signed
 *
 * SimpleID automatically handles signing fields required by the OpenID
 * specification, so only the fields introduced by this extension
 * needed to be returned by this function
 *
 * @param mixed $response the OpenID response to sign
 * @return array an array of fields to sign
 */
function hook_signed_fields($response) {
}

/**
 * Provides additional form items when displaying the relying party verification
 * form
 * 
 *
 * @param mixed $request the OpenID request
 * @param array $rp the user's preferences saved with this relying party
 * @return string HTML code to be inserted into the verification form
 * @see hook_send()
 */
function hook_form($request, $rp) {
}

/**
 * Processes the relying party verification form
 */
function hook_send($response) {
}

/**
 * Provides additional form items when displaying the user page
 *
 * @global array the user
 * @return string HTML code to be inserted into the user page
 */
function hook_user_page() {
    global $user;
}




?>
