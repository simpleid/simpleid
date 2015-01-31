$(document).ready(function() {
    $('input#edit-cancel').click(function() {
        window.close();
        return false;
    });
    $(document).keydown(function(e) {
        if (e.which == 27) { // Close the window if user presses Esc
            window.close();
            return false;
        }
    });
});
