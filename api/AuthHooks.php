<?php

namespace SimpleID\API;

/**
 * Authentication related hooks
 */
abstract class AuthHooks {
    /**
     * Attempts to automatically login using credentials presented by the user agent
     * (previously `hook_user_auto_login`).
     *
     * This hook is called by the {@link SimpleID\Auth\AuthManager::initUser()} function.  The hook
     * should detect any credentials present in the request and return a User object
     * if credentials identifying the user is present.
     *
     * If no credentials are present, or the credentials are invalid, this hook
     * should return NULL.
     * 
     * @return SimpleID\Models\User the user object, or NULL
     */
    abstract function autoAuthHook();

    /**
     * Provides additional form items when displaying the login form (previously
     * `hook_user_login_form`).
     *
     * The state of the consent form is specified in the `$form_state`
     * array.  At a minimum, the array has the following elements:
     *
     * - mode the authentication mode
     *
     * Other modules may insert additional elements into the `$form_state` array
     *
     * @param array $form_state the form state
     * @return array an array of form elements
     */
    abstract function loginFormHook(&$form_state);

    /**
     * Validates a login form.
     *
     * Implementations should use the `Base::get()` function
     * to access data submitted by the user in the form
     *
     * `$form_state` contains the same elements as per the
     * {@link loginFormHook()}.
     *
     * @param array $form_state the form state
     * @return bool true if the form passes validation
     */
    abstract function loginFormValidateHook(&$form_state);

    /**
     * Processes a login form (previously `hook_user_verify_credentials`).
     * 
     * Typically this hook is used to verifies the set of credentials supplied by
     * the login form for a specified user.
     *
     * Implementations should use the `Base::get()` function
     * to access data submitted by the user in the form
     *
     * `$form_state` contains the same elements as per the
     * {@link loginFormHook()} hook.
     *
     * This function should return one of the following:
     *
     * - null if the hook is skipping processing of the login form to another module
     * - false if the user should <strong>not` be logged in (because the
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
     * Processes a login form where the user has cancelled login.
     *
     * `$form_state` contains the same elements as per the
     * {@link loginFormHook()} hook.
     *
     * This function should return one of the following:
     *
     * - null if the hook is skipping processing to another module
     * - true if the hook has processed the hook
     *
     * @param array $form_state the form state
     * @return bool|null the result of the processing
     */
    abstract function loginFormCancelled($form_state);

    /**
     * Logs in a user.
     *
     * This hook is triggered when all the authentication components are completed.
     * This hook can be used to save any authentication information.
     *
     * The state of the login form (if any) used in the process is passed via
     * the `$form_state` parameter.  It contains the same elements as per the
     * {@link loginFormHook()} hook.
     *
     * @param SimpleID\Models\User $user the user to be logged in
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

    /**
     * Returns an array of data paths from the User object that should
     * be hidden from view.
     *
     * Data paths should be in a format that is parsable by
     * {@link SimpleID\Util\ArrayWrapper::pathSet()}
     *
     * @return array of data paths.
     */
    abstract function secretUserDataPathsHook();

    /**
     * Returns an authentication context class reference
     * the authentication scheme module implemented in relation
     * to the current user.
     *
     * @return string the authentication context class reference
     */
    abstract function acrHook();
}



?>
