<?php

set_include_path(implode(PATH_SEPARATOR, array(
    dirname(__FILE__) . '/../www/',
    dirname(__FILE__) . '/',
    get_include_path(),
)));

require 'bootstrap.inc.php';

?>