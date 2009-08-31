var discovery_refresh = function() {
    var code = '';
    
    if ($('#discovery-openid1')[0].checked) {
        code += $('#discovery-templates .openid1').html() + '\n';
        if ($('#discovery-local-id')[0].checked) code += $('.openid1-local-id').html() + '\n';
    }
    if ($('#discovery-openid2')[0].checked) {
        code += $('#discovery-templates .openid2').html() + '\n';
        if ($('#discovery-local-id')[0].checked) code += $('.openid2-local-id').html() + '\n';
    }
    
    if (code == '') code = '<em>You need to set at least one of OpenID 1.x or OpenID 2 to generate the code.</em>';
    
    $('#discovery-link-tags').html(code);
}

$(document).ready(function() {
    $('.discovery-checkbox').click(discovery_refresh);
    discovery_refresh();
});
