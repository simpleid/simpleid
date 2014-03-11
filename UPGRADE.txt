Upgrading SimpleID
==================

Introduction
------------

SimpleID is currently in heavy development, with the software changing rapidly.
As a result, it is very important to upgrade SimpleID when a new version is
released.

General information on upgrading can be found at
<http://simpleid.koinic.net/documentation/getting-started/upgrading>.

This document sets out the additional steps which may need to be performed to
upgrade to a specific version of SimpleID.

Upgrading to SimpleID 0.9
-------------------------

1. System requirements

The system requirements for SimpleID have changed.  The most important
changes are:

    (a) PHP

        From version 0.9, the minimum version of PHP is 5.3.0.  PHP 4 is no
        longer supported.

    (b) HTTPS support

        From version 0.9, HTTPS support is mandatory.  The evolving security
        environment means that it is no longer safe to accept logins from
        unencrypted connections.

        If you run your own server, there are now many inexpensive certificate 
        authorities from which to get certificates.  Self-signed certificates
        are also acceptable (although not recommended).

        If you are using a shared server from a web hosting provider, check
        with them regarding SSL capabilities.  Many offer a shared SSL
        certificate to the server at no extra cost.

For further information on the revised system requirements, see the SimpleID
web site at http://simpleid.koinic.net/node/58

2. Enhanced password security

Version 0.9 now supports storing passwords with hashing algorithms other than
MD5 and with a salt.  You may wish to update your identity file to take
advantage of this new feature.

3. File extensions

SimpleID PHP code files no longer use the .inc file extension.  Instead only
the .php file extension is used.  This prevents misconfigured web servers to
return SimpleID source code.

You will need to perform the following manually:

    (a) Rename config.inc to config.php

    (b) Rename any custom extensions in the extensions directory from
        .extension.inc to .extension.php

    (c) Delete all old .inc files from the SimpleID web directory.

4. upgrade.php

You will need to run the upgrade script to complete the upgrade.  To run the
script, use your web browser to go to

http://www.exmaple.com/simpleid/upgrade.php

where http://www.exmaple.com/simpleid/ is the URL of your SimpleID server
(where you have moved the www directory).  You will need to be logged in as
an administrator to proceed with the script.

Upgrading to SimpleID 0.8
-------------------------

SimpleID 0.8 does not require any additional steps as part of the upgrade
process.

However, you will still need to run the upgrade script to complete the
upgrade.  To run the script, use your web browser to go to

http://www.exmaple.com/simpleid/upgrade.php

where http://www.exmaple.com/simpleid/ is the URL of your SimpleID server
(where you have moved the www directory).  You will need to be logged in as
an administrator to proceed with the script.


Upgrading to SimpleID 0.7
-------------------------

1. New storage framework

SimpleID introduced a new storage framework.  The new framework allows SimpleID
to store additional information about your identity.

As a result, you will need to be aware that there is a new configuration option
called SIMPLEID_STORE_DIR, which specifies the directory where this information
will be stored.  This directory must exist and be readable and writable by the
web server.

If you are upgrading from SimpleID 0.6, this setting will default to the
directory specified by SIMPLEID_CACHE_DIR in your config.inc.  However, it is
a good idea to place this in a separate directory.  To do this, add the
following line to your config.inc:

define('SIMPLEID_STORE_DIR', '<your directory here>');

2. Administrators

SimpleID 0.7 introduced the concept of administrators.  Administrators
have access to certain functions which regular users cannot.  To make a user
an administrator, edit the user's identity file to include the following line:

administrator=1

3. User Interface Extension

SimpleID 0.7 introduced support for the draft OpenID User Interface Extension.
It is enabled by default for new installations of SimpleID, however if you
are upgrading you may need to enable it manually.  To do so, edit
your config.inc to change the SIMPLEID_EXTENSIONS configuration option to
include ui.  For example:

define('SIMPLEID_EXTENSIONS', 'sreg,ui');

4. Upgrade script

SimpleID introduced a new upgrade script.  This means that whenever you
upgrade you will also need to run the script.  To run the script, use your
web browser to go to

http://www.exmaple.com/simpleid/upgrade.php

where http://www.exmaple.com/simpleid/ is the URL of your SimpleID server
(where you have moved the www directory).  You will need to be logged in as
an administrator to proceed with the script.


Upgrading to SimpleID 0.6
-------------------------

SimpleID version 0.6 introduced a new log in system.  The new system allows
you to log in to SimpleID without sending your password in plain text.  Your
password is used to create a cryptographic digest, which is then sent to
the SimpleID server and verified.

As a result, you need to be aware of two things:

1.  You browser must have JavaScript switched on in order to use the new
    log in system.  If JavaScript is not switched on, SimpleID reverts to the
    "legacy" log in system used in previous versions, subject to the important
    point below.
    
2.  By default, SimpleID version 0.6 will not accept logins under the legacy
    system.  You can override this by putting the following line in your
    config.inc:
    
    define('SIMPLEID_ALLOW_LEGACY_LOGIN', true);
    
    It is STRONGLY RECOMMENDED that you DO NOT switch the legacy login system
    on, as it is substantially less secure than the new login system.  Use this
    ONLY if your browser does not support JavaScript.
    

