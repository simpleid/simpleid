<?php 
/*
 * SimpleID
 *
 * Copyright (C) Kelvin Mo 2009
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 * 
 * $Id$
 */

/**
 * Functions for displaying various pages in SimpleID.
 *
 * @package simpleid
 * @filesource
 * @since 0.7
 */
 
/**
 * Displays the dashboard page.
 */
function page_dashboard() {
    global $user;
    global $xtpl;
    
    if ($user == NULL) {
        user_login_form('');
        return;
    }
    
    user_header();
    page_nav();
    
    $blocks = _page_welcome_block();
    
    $blocks = array_merge($blocks, extension_invoke_all('page_dashboard'));
    $blocks = array_map('page_render_block', $blocks);
    $xtpl->assign('blocks', implode($blocks));
    $xtpl->parse('main.blocks');
    
    $xtpl->assign('title', 'Dashboard');
    $xtpl->parse('main');
    $xtpl->out('main');

}

/**
 * Displays the profile page.
 */
function page_profile() {
    global $user;
    global $xtpl;
    
    if ($user == NULL) {
        user_login_form('my/profile');
        return;
    }
    
    user_header();
    page_nav();
    
    $blocks = _page_discovery_block();

    $blocks = array_merge($blocks, extension_invoke_all('page_profile'));
    $blocks = array_map('page_render_block', $blocks); 
    $xtpl->assign('blocks', implode($blocks));
    $xtpl->parse('main.blocks');
    
    $xtpl->assign('javascript', '<script src="' . get_base_path() . 'html/page-profile.js" type="text/javascript"></script>');
    $xtpl->assign('title', 'My Profile');
    $xtpl->parse('main');
    $xtpl->out('main');
}

/**
 * Returns the user's home page.
 */
function page_sites() {
    global $user;
    global $xtpl;
    
    if ($user == NULL) {
        user_login_form('my/sites');
        return;
    }
    
    user_header();
    page_nav();
    
    $rps = isset($user['rp']) ? $user['rp'] : array();
    
    if ($rps) {
        foreach ($rps as $realm => $rp) {
            $xtpl->assign('realm', htmlspecialchars($rp['realm'], ENT_QUOTES, 'UTF-8'));
            $xtpl->assign('last_time', htmlspecialchars($rp['last_time'], ENT_QUOTES, 'UTF-8'));
            $xtpl->assign('last_time_formatted', htmlspecialchars(strftime(SIMPLEID_DATE_TIME_FORMAT, $rp['last_time']), ENT_QUOTES, 'UTF-8'));
            $xtpl->assign('auto_release', (isset($rp['auto_release']) && $rp['auto_release']) ? 'checked="checked"' : '');
            $xtpl->parse('main.sites.realm');
        }
    }
    
    if (!$rps || (count($rps) == 0)) {
        $xtpl->assign('disabled', 'disabled="disabled"');
    }
    
    $xtpl->assign('token', get_form_token('autorelease'));
        
    $xtpl->parse('main.sites');
    
    $xtpl->assign('title', 'My Sites');
    $xtpl->parse('main');
    $xtpl->out('main');
}

/**
 * Set up the navigation section in the header
 */
function page_nav() {
    global $user;
    global $xtpl;
    
    $xtpl->assign('nav_base', trim(simpleid_url(' ', '', true)));
    
    if ($user != NULL) {
        if (isset($user['administrator']) && ($user['administrator'] == 1)) $xtpl->parse('main.nav.nav_admin');
        
    }
    $xtpl->parse('main.nav');
}

/**
 * Renders a particular block.
 *
 * @param array $block the block to render
 * @return string the HTML of the rendered block
 */
function page_render_block($block) {
    static $xtpl_block;
    
    if (!$xtpl_block) $xtpl_block = new XTemplate('html/block.xtpl');
    
    $xtpl_block->reset('block');
    $xtpl_block->assign('id', $block['id']);
    $xtpl_block->assign('title', $block['title']);
    $xtpl_block->assign('content', $block['content']);
    
    if (isset($block['links'])) {
        $xtpl_block->assign('links', $block['links']);
        $xtpl_block->parse('block.links');
    }
    
    $xtpl_block->parse('block');
    return $xtpl_block->text('block');
}

/**
 * Returns the welcome block.
 *
 * @return array the welcome block
 */
function _page_welcome_block() {
    global $user;
    
    return array(array(
        'id' => 'welcome',
        'title' => 'Welcome',
        'content' => 'You are logged in as <strong>' . htmlspecialchars($user['uid'], ENT_QUOTES, 'UTF-8') . '</strong> (<strong>' . htmlspecialchars($user['identity'], ENT_QUOTES, 'UTF-8') . '</strong>).'
    ));
}

function _page_discovery_block() {
    global $user;
    
    $html = "<h3>&lt;link&gt; tags</h3>";
    
    $html .= "<div><label><input type=\"checkbox\" name=\"openid1\" value=\"1\" id=\"discovery-openid1\" class=\"discovery-checkbox\" />OpenID 1.x</label>";
    $html .= "<label><input type=\"checkbox\" name=\"openid2\" value=\"1\" id=\"discovery-openid2\" class=\"discovery-checkbox\" />OpenID 2.0</label>";
    $html .= "<label><input type=\"checkbox\" name=\"local-id\" value=\"1\" id=\"discovery-local-id\" class=\"discovery-checkbox\" />Claim a different identifier</label></div>";
    $html .= "<pre id=\"discovery-link-tags\">";
    $html .= "</pre>";
    $html .= "<ul id=\"discovery-templates\"><li class=\"openid1\">&lt;link rel=&quot;openid.server&quot; href=&quot;" . htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8') . "&quot; /&gt;</li>\n";
    $html .= "<li class=\"openid2\">&lt;link rel=&quot;openid2.provider&quot; href=&quot;" . htmlspecialchars(simpleid_url(), ENT_QUOTES, 'UTF-8') ."&quot; /&gt;</li>\n";
    $html .= "<li class=\"openid1-local-id\">&lt;link rel=&quot;openid.delegate&quot; href=&quot;" . htmlspecialchars($user['identity'], ENT_QUOTES, 'UTF-8') . "&quot; /&gt;</li>\n";
    $html .= "<li class=\"openid2-local-id\">&lt;link rel=&quot;openid2.local_id&quot; href=&quot;" . htmlspecialchars($user['identity'], ENT_QUOTES, 'UTF-8') ."&quot; /&gt;</li></ul>\n";

    $html .= "<h3>YADIS</h3>";
    $html .= "<ol><li>Write your own or <a href=\"" . htmlspecialchars(simpleid_url('xrds/'. $user['uid'], '', true), ENT_QUOTES, 'UTF-8') . "\">download</a> your YADIS document</li>";
    $html .= "<li><div>Add HTTP headers or &lt;meta&gt; tag, e.g.:<div><pre>&lt;meta http-equiv=&quot;X-XRDS-Location&quot; content=&quot;" . htmlspecialchars(simpleid_url('xrds/'. $user['uid']), ENT_QUOTES, 'UTF-8') . "&quot; /></pre>";
    $html .= "</li></ol>";
    
    return array(array(
        'id' => 'discovery',
        'title' => 'Claim your Identifier',
        'content' => $html,
        'links' => '<a href="http://simpleid.sourceforge.net/documentation/getting-started/setting-identity/claim-your-identifier">More information</a>'
    ));
}
?>
