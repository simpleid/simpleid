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
    
    $blocks = array();

    $blocks = array_merge($blocks, extension_invoke_all('page_profile'));
    $blocks = array_map('page_render_block', $blocks); 
    $xtpl->assign('blocks', implode($blocks));
    $xtpl->parse('main.blocks');
    
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
            $xtpl->assign('last_time', htmlspecialchars(strftime(SIMPLEID_DATE_TIME_FORMAT, $rp['last_time']), ENT_QUOTES, 'UTF-8'));
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
        'content' => 'You are logged in as <strong>' . htmlspecialchars($user['uid']) . '</strong> (<strong>' . htmlspecialchars($user['identity']) . '</strong>).'
    ));
}
?>
