<?php

namespace SimpleID\API;

/**
 * Authentication related hooks
 */
abstract class AuthHooks {
    /**
     * Attempts to automatically login using credentials presented by the user agent
     * (previously <code>hook_user_auto_login</code>).
     *
     * This hook is called by the <code>AuthManager::initUser()</code> function.  The hook
     * should detect any credentials present in the request and return a User object
     * if credentials identifying the user is present.
     *
     * If no credentials are present, or the credentials are invalid, this hook
     * should return NULL.
     * 
     * @return User the user object, or NULL
     */
    abstract function autoAuthHook();

    /**
     * Provides additional form items when displaying the login form (previously
     * <code>hook_user_login_form</code>).
     *
     * The state of the consent form is specified in the <code>$form_state</code>
     * array.  At a minimum, the array has the following elements:
     *
     * - mode the authentication mode
     *
     * Other modules may insert additional elements into the <code>$form_state</code> array
     *
     * @param array $form_state the form state
     * @return array an array of form elements
     */
    abstract function loginFormHook(&$form_state);

    /**
     * Validates a login form.
     *
     * Implementations should use the <code>Base::get()<code> function
     * to access data submitted by the user in the form
     *
     * <code>$form_state</code> contains the same elements as per the
     * <code>loginForm</code> hook.
     *
     * @param array $form_state the form state
     * @return bool true if the form passes validation
     */
    abstract function loginFormValidateHook(&$form_state);

    /**
     * Processes a login form (previously <code>hook_user_verify_credentials</code>).
     * 
     * Typically this hook is used to verifies the set of credentials supplied by
     * the login form for a specified user.
     *
     * Implementations should use the <code>Base::get()<code> function
     * to access data submitted by the user in the form
     *
     * <code>$form_state</code> contains the same elements as per the
     * <code>loginForm</code> hook.
     *
     * This function should return one of the following:
     *
     * - null if the hook is skipping processing of the login form to another module
     * - false if the user should <strong>not</code> be logged in (because the
     *   supplied credentials do not match)
     * - an array with the following elements if the credentials match
     *       - uid the user ID
     *       - auth_level the authentication level supported by this module
     *
     * @param array $form_state the form state
     * @return array|bool|null the result of the processing
     */
    abstract function loginFormSubmitHook(&$form_state);

    /**
     * Logs in a user.
     *
     * This hook is triggered when all the authentication components are completed.
     * This hook can be used to save any authentication information.
     *
     * The state of the login form (if any) used in the process is passed via
     * the <code>$form_state</code> parameter.  It contains the same elements as per the
     * <code>loginForm</code> hook.
     *
     * @param User $user the user to be logged in
     * @param int $level the maximum authentication level achieved from the
     * authentication process
     * @param array $modules an array of fully qualified class names of the modules
     * involved in the authentication process
     * @param array $form_state the state of the login form
     * @since 2.0
     */
    abstract function loginHook($user, $level, $modules, $form_state);

    /**
     * Logs out a user.
     *
     * This hook can be used to clean up any saved information when a user
     * logs out
     *
     * @since 2.0
     */
    abstract function logoutHook();
}



?>
