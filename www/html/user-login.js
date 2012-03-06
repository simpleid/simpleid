$(document).ready(function() {
    if (!$('.login-security').is('.allow-autocomplete')) $('#edit-pass').attr('autocomplete', 'off');
    
    if ($('#edit-name').is('.form-text')) $('#edit-name').focus();
});

