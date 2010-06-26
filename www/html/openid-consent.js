$(document).ready(function() {
    $('.return-to-suspect').click(function() {
        if ($(this).attr('checked') == false) return true;
        
        return confirm('This web site has not confirmed its identity and might be fraudulent.\n\nAre you sure you wish to automatically send your information to this site for any future requests?');
    });
});
