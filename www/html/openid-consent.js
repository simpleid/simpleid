$(document).ready(function() {
    $('.return-to-suspect').click(function() {
        if ($(this).attr('checked') == false) return true;
        
        return confirm(l.openid_suspect);
    });
});
