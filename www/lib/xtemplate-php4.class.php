<?php

// When developing uncomment the line below, re-comment before making public
//error_reporting(E_ALL);

/**
 * XTemplate PHP templating engine
 *
 * @package XTemplate
 * @author Barnabas Debreceni [cranx@users.sourceforge.net]
 * @copyright Barnabas Debreceni 2000-2001
 * @author Jeremy Coates [cocomp@users.sourceforge.net]
 * @copyright Jeremy Coates 2002-2007
 * @see license.txt LGPL / BSD license
 * @since PHP 4.?
 * @link $HeadURL: https://xtpl.svn.sourceforge.net/svnroot/xtpl/branches/php4/xtemplate.class.php $
 * @version $Id: xtemplate.class.php 76 2008-11-01 09:45:12Z kmo $
 *
 *
 * XTemplate class - http://www.phpxtemplate.org/ (x)html / xml generation with templates - fast & easy
 * Latest stable & Subversion versions available @ http://sourceforge.net/projects/xtpl/
 * License: LGPL / BSD - see license.txt
 * Changelog: see changelog.txt
 */
class XTemplate {

	/**
	 * Properties
	 */

	/**
	 * Raw contents of the template file
	 *
	 * @access public
	 * @var string
	 */
	var $filecontents = '';

	/**
	 * Unparsed blocks
	 *
	 * @access public
	 * @var array
	 */
	var $blocks = array();

	/**
	 * Parsed blocks
	 *
	 * @var unknown_type
	 */
	var $parsed_blocks = array();

	/**
	 * Preparsed blocks (for file includes)
	 *
	 * @access public
	 * @var array
	 */
	var $preparsed_blocks = array();

	/**
	 * Block parsing order for recursive parsing
	 * (Sometimes reverse :)
	 *
	 * @access public
	 * @var array
	 */
	var $block_parse_order = array();

	/**
	 * Store sub-block names
	 * (For fast resetting)
	 *
	 * @access public
	 * @var array
	 */
	var $sub_blocks = array();

	/**
	 * Variables array
	 *
	 * @access public
	 * @var array
	 */
	var $vars = array();

	/**
	 * File variables array
	 *
	 * @access public
	 * @var array
	 */
	var $filevars = array();

	/**
	 * Filevars' parent block
	 *
	 * @access public
	 * @var array
	 */
	var $filevar_parent = array();

	/**
	 * File caching during duration of script
	 * e.g. files only cached to speed {FILE "filename"} repeats
	 *
	 * @access public
	 * @var array
	 */
	var $filecache = array();

	/**
	 * Location of template files
	 *
	 * @access public
	 * @var string
	 */
	var $tpldir = '';

	/**
	 * Filenames lookup table
	 *
	 * @access public
	 * @var null
	 */
	var $files = null;

	/**
	 * Template filename
	 *
	 * @access public
	 * @var string
	 */
	var $filename = '';

	// moved to setup method so uses the tag_start & end_delims
	/**
	 * RegEx for file includes
	 *
	 * "/\{FILE\s*\"([^\"]+)\"\s*\}/m";
	 *
	 * @access public
	 * @var string
	 */
	var $file_delim = '';

	/**
	 * RegEx for file include variable
	 *
	 * "/\{FILE\s*\{([A-Za-z0-9\._]+?)\}\s*\}/m";
	 *
	 * @access public
	 * @var string
	 */
	var $filevar_delim = '';

	/**
	 * RegEx for file includes with newlines
	 *
	 * "/^\s*\{FILE\s*\{([A-Za-z0-9\._]+?)\}\s*\}\s*\n/m";
	 *
	 * @access public
	 * @var string
	 */
	var $filevar_delim_nl = '';

	/**
	 * Template block start delimiter
	 *
	 * @access public
	 * @var string
	 */
	var $block_start_delim = '<!-- ';

	/**
	 * Template block end delimiter
	 *
	 * @access public
	 * @var string
	 */
	var $block_end_delim = '-->';

	/**
	 * Template block start word
	 *
	 * @access public
	 * @var string
	 */
	var $block_start_word = 'BEGIN:';

	/**
	 * Template block end word
	 *
	 * The last 3 properties and this make the delimiters look like:
	 * @example <!-- BEGIN: block_name -->
	 * if you use the default syntax.
	 *
	 * @access public
	 * @var string
	 */
	var $block_end_word = 'END:';

	/**
	 * Template tag start delimiter
	 *
	 * This makes the delimiters look like:
	 * @example {tagname}
	 * if you use the default syntax.
	 *
	 * @access public
	 * @var string
	 */
	var $tag_start_delim = '{';

	/**
	 * Template tag end delimiter
	 *
	 * This makes the delimiters look like:
	 * @example {tagname}
	 * if you use the default syntax.
	 *
	 * @access public
	 * @var string
	 */
	var $tag_end_delim = '}';
	/* this makes the delimiters look like: {tagname} if you use my syntax. */

	/**
	 * Regular expression element for comments within tags and blocks
	 *
	 * @example {tagname#My Comment}
	 * @example {tagname #My Comment}
	 * @example <!-- BEGIN: blockname#My Comment -->
	 * @example <!-- BEGIN: blockname #My Comment -->
	 *
	 * @access public
	 * @var string
	 */
	var $comment_preg = '( ?#.*?)?';

	/**
	 * Default main template block name
	 *
	 * @access public
	 * @var string
	 */
	var $mainblock = 'main';

	/**
	 * Script output type
	 *
	 * @access public
	 * @var string
	 */
	var $output_type = 'HTML';

	/**
	 * Debug mode
	 *
	 * @access public
	 * @var boolean
	 */
	var $debug = false;

	/**
	 * Null string for unassigned vars
	 *
	 * @access protected
	 * @var array
	 */
	var $_null_string = array('' => '');

	/**
	 * Null string for unassigned blocks
	 *
	 * @access protected
	 * @var array
	 */
	var $_null_block = array('' => '');

	/**
	 * Errors
	 *
	 * @access protected
	 * @var string
	 */
	var $_error = '';

	/**
	 * Auto-reset sub blocks
	 *
	 * @access protected
	 * @var boolean
	 */
	var $_autoreset = true;

	/**
	 * Set to FALSE to generate errors if a non-existant blocks is referenced
	 *
	 * @author NW
	 * @since 2002/10/17
	 * @access protected
	 * @var boolean
	 */
	var $_ignore_missing_blocks = true;

	/**
     * Constructor - Instantiate the object
     *
     * @param string $file Template file to work on
     * @param string $tpldir Location of template files (useful for keeping files outside web server root)
     * @param array $files Filenames lookup
     * @param string $mainblock Name of main block in the template
     * @param boolean $autosetup If true, run setup() as part of constuctor
     * @return XTemplate
     */
	function XTemplate ($file, $tpldir = '', $files = null, $mainblock = 'main', $autosetup = true) {

		$this->restart($file, $tpldir, $files, $mainblock, $autosetup, $this->tag_start_delim, $this->tag_end_delim);
	}


	/***************************************************************************/
	/***[ public stuff ]********************************************************/
	/***************************************************************************/

	/**
	 * Restart the class - allows one instantiation with several files processed by restarting
	 * e.g. $xtpl = new XTemplate('file1.xtpl');
	 * $xtpl->parse('main');
	 * $xtpl->out('main');
	 * $xtpl->restart('file2.xtpl');
	 * $xtpl->parse('main');
	 * $xtpl->out('main');
	 * (Added in response to sf:641407 feature request)
	 *
	 * @param string $file Template file to work on
	 * @param string $tpldir Location of template files
	 * @param array $files Filenames lookup
	 * @param string $mainblock Name of main block in the template
	 * @param boolean $autosetup If true, run setup() as part of restarting
	 * @param string $tag_start {
	 * @param string $tag_end }
	 */
	function restart ($file, $tpldir = '', $files = null, $mainblock = 'main', $autosetup = true, $tag_start = '{', $tag_end = '}') {

		$this->filename = $file;

		// From SF Feature request 1202027
		// Kenneth Kalmer
		$this->tpldir = $tpldir;
		if (defined('XTPL_DIR') && empty($this->tpldir)) {
			$this->tpldir = XTPL_DIR;
		}

		if (is_array($files)) {
			$this->files = $files;
		}

		$this->mainblock = $mainblock;

		$this->tag_start_delim = $tag_start;
		$this->tag_end_delim = $tag_end;

		// Start with fresh file contents
		$this->filecontents = '';

		// Reset the template arrays
		$this->blocks = array();
		$this->parsed_blocks = array();
		$this->preparsed_blocks = array();
		$this->block_parse_order = array();
		$this->sub_blocks = array();
		$this->vars = array();
		$this->filevars = array();
		$this->filevar_parent = array();
		$this->filecache = array();

		if ($autosetup) {
			$this->setup();
		}
	}

	/**
     * setup - the elements that were previously in the constructor
     *
     * @access public
     * @param boolean $add_outer If true is passed when called, it adds an outer main block to the file
     */
	function setup ($add_outer = false) {

		$this->tag_start_delim = preg_quote($this->tag_start_delim);
		$this->tag_end_delim = preg_quote($this->tag_end_delim);

		// Setup the file delimiters

		// regexp for file includes
		$this->file_delim = "/" . $this->tag_start_delim . "FILE\s*\"([^\"]+)\"" . $this->comment_preg . $this->tag_end_delim . "/m";

		// regexp for file includes
		$this->filevar_delim = "/" . $this->tag_start_delim . "FILE\s*" . $this->tag_start_delim . "([A-Za-z0-9\._]+?)" . $this->comment_preg . $this->tag_end_delim . $this->comment_preg . $this->tag_end_delim . "/m";

		// regexp for file includes w/ newlines
		$this->filevar_delim_nl = "/^\s*" . $this->tag_start_delim . "FILE\s*" . $this->tag_start_delim . "([A-Za-z0-9\._]+?)" . $this->comment_preg . $this->tag_end_delim . $this->comment_preg . $this->tag_end_delim . "\s*\n/m";

		if (empty($this->filecontents)) {
			// read in template file
			$this->filecontents = $this->_r_getfile($this->filename);
		}

		if ($add_outer) {
			$this->_add_outer_block();
		}

		// preprocess some stuff
		$this->blocks = $this->_maketree($this->filecontents, '');
		$this->filevar_parent = $this->_store_filevar_parents($this->blocks);
		$this->scan_globals();
	}

	/**
     * assign a variable
     *
     * @example Simplest case:
     * @example $xtpl->assign('name', 'value');
     * @example {name} in template
     *
     * @example Array assign:
     * @example $xtpl->assign(array('name' => 'value', 'name2' => 'value2'));
     * @example {name} {name2} in template
     *
     * @example Value as array assign:
     * @example $xtpl->assign('name', array('key' => 'value', 'key2' => 'value2'));
     * @example {name.key} {name.key2} in template
     *
     * @example Reset array:
     * @example $xtpl->assign('name', array('key' => 'value', 'key2' => 'value2'));
     * @example // Other code then:
     * @example $xtpl->assign('name', array('key3' => 'value3'), false);
     * @example {name.key} {name.key2} {name.key3} in template
     *
     * @access public
     * @param string $name Variable to assign $val to
     * @param string / array $val Value to assign to $name
	 * @param boolean $reset_array Reset the variable array if $val is an array
     */
	function assign ($name, $val = '', $reset_array = true) {

		if (is_array($name)) {

			foreach ($name as $k => $v) {

				$this->vars[$k] = $v;
			}
		} elseif (is_array($val)) {

			// Clear the existing values
    		if ($reset_array) {
    			$this->vars[$name] = array();
    		}

        	foreach ($val as $k => $v) {

        		$this->vars[$name][$k] = $v;
        	}

		} else {

			$this->vars[$name] = $val;
		}
	}

	/**
     * assign a file variable
     *
     * @access public
     * @param string $name Variable to assign $val to
     * @param string / array $val Values to assign to $name
     */
	function assign_file ($name, $val = '') {

		if (is_array($name)) {

			foreach ($name as $k => $v) {

				$this->_assign_file_sub($k, $v);
			}
		} else {

			$this->_assign_file_sub($name, $val);
		}
	}

	/**
     * parse a block
     *
     * @access public
     * @param string $bname Block name to parse
     */
	function parse ($bname) {

		if (isset($this->preparsed_blocks[$bname])) {

			$copy = $this->preparsed_blocks[$bname];

		} elseif (isset($this->blocks[$bname])) {

			$copy = $this->blocks[$bname];

		} elseif ($this->_ignore_missing_blocks) {
			// ------------------------------------------------------
			// NW : 17 Oct 2002. Added default of ignore_missing_blocks
			//      to allow for generalised processing where some
			//      blocks may be removed from the HTML without the
			//      processing code needing to be altered.
			// ------------------------------------------------------
			// JRC: 3/1/2003 added set error to ignore missing functionality
			$this->_set_error("parse: blockname [$bname] does not exist");
			return;

		} else {

			$this->_set_error("parse: blockname [$bname] does not exist");
		}

		/* from there we should have no more {FILE } directives */
		if (!isset($copy)) {
			die('Block: ' . $bname);
		}

		$copy = preg_replace($this->filevar_delim_nl, '', $copy);

		$var_array = array();

		/* find & replace variables+blocks */
		preg_match_all("|" . $this->tag_start_delim . "([A-Za-z0-9\._]+?" . $this->comment_preg . ")" . $this->tag_end_delim. "|", $copy, $var_array);

		$var_array = $var_array[1];

		foreach ($var_array as $k => $v) {

			// Are there any comments in the tags {tag#a comment for documenting the template}
			$any_comments = explode('#', $v);
			$v = rtrim($any_comments[0]);

			if (sizeof($any_comments) > 1) {

				$comments = $any_comments[1];
			} else {

				$comments = '';
			}

			$sub = explode('.', $v);

			if ($sub[0] == '_BLOCK_') {

				unset($sub[0]);

				$bname2 = implode('.', $sub);

				// trinary operator eliminates assign error in E_ALL reporting
				$var = isset($this->parsed_blocks[$bname2]) ? $this->parsed_blocks[$bname2] : null;
				$nul = (!isset($this->_null_block[$bname2])) ? $this->_null_block[''] : $this->_null_block[$bname2];

				if ($var === '') {

					if ($nul == '') {
						// -----------------------------------------------------------
						// Removed requirement for blocks to be at the start of string
						// -----------------------------------------------------------
						//                      $copy=preg_replace("/^\s*\{".$v."\}\s*\n*/m","",$copy);
						// Now blocks don't need to be at the beginning of a line,
						//$copy=preg_replace("/\s*" . $this->tag_start_delim . $v . $this->tag_end_delim . "\s*\n*/m","",$copy);
						$copy = preg_replace("|" . $this->tag_start_delim . $v . $this->tag_end_delim . "|m", '', $copy);

					} else {

						$copy = preg_replace("|" . $this->tag_start_delim . $v . $this->tag_end_delim . "|m", "$nul", $copy);
					}
				} else {

					//$var = trim($var);
					switch (true) {
						case preg_match('/^\n/', $var) && preg_match('/\n$/', $var):
							$var = substr($var, 1, -1);
							break;

						case preg_match('/^\n/', $var):
							$var = substr($var, 1);
							break;

						case preg_match('/\n$/', $var):
							$var = substr($var, 0, -1);
							break;
					}

					// SF Bug no. 810773 - thanks anonymous
					$var = str_replace('\\', '\\\\', $var);
					// Ensure dollars in strings are not evaluated reported by SadGeezer 31/3/04
					$var = str_replace('$', '\\$', $var);
					// Replaced str_replaces with preg_quote
					//$var = preg_quote($var);
					$var = str_replace('\\|', '|', $var);
					$copy = preg_replace("|" . $this->tag_start_delim . $v . $this->tag_end_delim . "|m", "$var", $copy);

					if (preg_match('/^\n/', $copy) && preg_match('/\n$/', $copy)) {
						$copy = substr($copy, 1, -1);
					}
				}
			} else {

				$var = $this->vars;

				foreach ($sub as $v1) {

					// NW 4 Oct 2002 - Added isset and is_array check to avoid NOTICE messages
					// JC 17 Oct 2002 - Changed EMPTY to stlen=0
					//                if (empty($var[$v1])) { // this line would think that zeros(0) were empty - which is not true
					if (!isset($var[$v1]) || (!is_array($var[$v1]) && strlen($var[$v1]) == 0)) {

						// Check for constant, when variable not assigned
						if (defined($v1)) {

							$var[$v1] = constant($v1);

						} else {

							$var[$v1] = null;
						}
					}

					$var = $var[$v1];
				}

				$nul = (!isset($this->_null_string[$v])) ? ($this->_null_string[""]) : ($this->_null_string[$v]);
				$var = (!isset($var)) ? $nul : $var;

				if ($var === '') {
					// -----------------------------------------------------------
					// Removed requriement for blocks to be at the start of string
					// -----------------------------------------------------------
					//                    $copy=preg_replace("|^\s*\{".$v." ?#?".$comments."\}\s*\n|m","",$copy);
					$copy = preg_replace("|" . $this->tag_start_delim . $v . "( ?#" . $comments . ")?" . $this->tag_end_delim . "|m", '', $copy);
				}

				$var = trim($var);
				// SF Bug no. 810773 - thanks anonymous
				$var = str_replace('\\', '\\\\', $var);
				// Ensure dollars in strings are not evaluated reported by SadGeezer 31/3/04
				$var = str_replace('$', '\\$', $var);
				// Replace str_replaces with preg_quote
				//$var = preg_quote($var);
				$var = str_replace('\\|', '|', $var);
				$copy = preg_replace("|" . $this->tag_start_delim . $v . "( ?#" . $comments . ")?" . $this->tag_end_delim . "|m", "$var", $copy);

				if (preg_match('/^\n/', $copy) && preg_match('/\n$/', $copy)) {
					$copy = substr($copy, 1);
				}
			}
		}

		if (isset($this->parsed_blocks[$bname])) {
			$this->parsed_blocks[$bname] .= $copy;
		} else {
			$this->parsed_blocks[$bname] = $copy;
		}

		/* reset sub-blocks */
		if ($this->_autoreset && (!empty($this->sub_blocks[$bname]))) {

			reset($this->sub_blocks[$bname]);

			foreach ($this->sub_blocks[$bname] as $k => $v) {
				$this->reset($v);
			}
		}
	}

	/**
     * returns the parsed text for a block, including all sub-blocks.
     *
     * @access public
     * @param string $bname Block name to parse
     */
	function rparse ($bname) {

		if (!empty($this->sub_blocks[$bname])) {

			reset($this->sub_blocks[$bname]);

			foreach ($this->sub_blocks[$bname] as $k => $v) {

				if (!empty($v)) {
					$this->rparse($v);
				}
			}
		}

		$this->parse($bname);
	}

	/**
     * inserts a loop ( call assign & parse )
     *
     * @access public
     * @param string $bname Block name to assign
     * @param string $var Variable to assign values to
     * @param string / array $value Value to assign to $var
    */
	function insert_loop ($bname, $var, $value = '') {

		$this->assign($var, $value);
		$this->parse($bname);
	}

	/**
     * parses a block for every set of data in the values array
     *
     * @access public
     * @param string $bname Block name to loop
     * @param string $var Variable to assign values to
     * @param array $values Values to assign to $var
    */
	function array_loop ($bname, $var, &$values) {

		if (is_array($values)) {

			foreach($values as $v) {

				$this->insert_loop($bname, $var, $v);
			}
		}
	}

	/**
     * returns the parsed text for a block
     *
     * @access public
     * @param string $bname Block name to return
     * @return string
     */
	function text ($bname = '') {

		$text = '';

		if ($this->debug && $this->output_type == 'HTML') {
			// JC 20/11/02 echo the template filename if in development as
			// html comment
			$text .= '<!-- XTemplate: ' . realpath($this->filename) . " -->\n";
		}

		$bname = !empty($bname) ? $bname : $this->mainblock;

		$text .= isset($this->parsed_blocks[$bname]) ? $this->parsed_blocks[$bname] : $this->get_error();

		return $text;
	}

	/**
     * prints the parsed text
     *
     * @access public
     * @param string $bname Block name to echo out
     */
	function out ($bname) {

		$out = $this->text($bname);
		//        $length=strlen($out);
		//header("Content-Length: ".$length); // TODO: Comment this back in later

		echo $out;
	}

	/**
     * prints the parsed text to a specified file
     *
     * @access public
     * @param string $bname Block name to write out
     * @param string $fname File name to write to
     */
	function out_file ($bname, $fname) {

		if (!empty($bname) && !empty($fname) && is_writeable($fname)) {

			$fp = fopen($fname, 'w');
			fwrite($fp, $this->text($bname));
			fclose($fp);
		}
	}

	/**
     * resets the parsed text
     *
     * @access public
     * @param string $bname Block to reset
     */
	function reset ($bname) {

		$this->parsed_blocks[$bname] = '';
	}

	/**
     * returns true if block was parsed, false if not
     *
     * @access public
     * @param string $bname Block name to test
     * @return boolean
     */
	function parsed ($bname) {

		return (!empty($this->parsed_blocks[$bname]));
	}

	/**
     * sets the string to replace in case the var was not assigned
     *
     * @access public
     * @param string $str Display string for null block
     * @param string $varname Variable name to apply $str to
     */
	function set_null_string($str, $varname = '') {

		$this->_null_string[$varname] = $str;
	}

	/**
	 * Backwards compatibility only
	 *
	 * @param string $str
	 * @param string $varname
	 * @deprecated Change to set_null_string to keep in with rest of naming convention
	 */
	function SetNullString ($str, $varname = '') {
		$this->set_null_string($str, $varname);
	}

	/**
     * sets the string to replace in case the block was not parsed
     *
     * @access public
     * @param string $str Display string for null block
     * @param string $bname Block name to apply $str to
     */
	function set_null_block ($str, $bname = '') {

		$this->_null_block[$bname] = $str;
	}

	/**
	 * Backwards compatibility only
	 *
	 * @param string $str
	 * @param string $bname
	 * @deprecated Change to set_null_block to keep in with rest of naming convention
	 */
	function SetNullBlock ($str, $bname = '') {
		$this->set_null_block($str, $bname);
	}

	/**
     * sets AUTORESET to 1. (default is 1)
     * if set to 1, parse() automatically resets the parsed blocks' sub blocks
     * (for multiple level blocks)
     *
     * @access public
     */
	function set_autoreset () {

		$this->_autoreset = true;
	}

	/**
     * sets AUTORESET to 0. (default is 1)
     * if set to 1, parse() automatically resets the parsed blocks' sub blocks
     * (for multiple level blocks)
     *
     * @access public
     */
	function clear_autoreset () {

		$this->_autoreset = false;
	}

	/**
     * scans global variables and assigns to PHP array
     *
     * @access public
     */
	function scan_globals () {

		reset($GLOBALS);

		foreach ($GLOBALS as $k => $v) {
			$GLOB[$k] = $v;
		}

		/**
		 * Access global variables as:
		 * @example {PHP._SERVER.HTTP_HOST}
		 * in your template!
		 */
		$this->assign('PHP', $GLOB);
	}

	/**
     * gets error condition / string
     *
     * @access public
     * @return boolean / string
     */
	function get_error () {

		// JRC: 3/1/2003 Added ouptut wrapper and detection of output type for error message output
		$retval = false;

		if ($this->_error != '') {

			switch ($this->output_type) {
				case 'HTML':
				case 'html':
					$retval = '<b>[XTemplate]</b><ul>' . nl2br(str_replace('* ', '<li>', str_replace(" *\n", "</li>\n", $this->_error))) . '</ul>';
					break;

				default:
					$retval = '[XTemplate] ' . str_replace(' *\n', "\n", $this->_error);
					break;
			}
		}

		return $retval;
	}

	/***************************************************************************/
	/***[ private stuff ]*******************************************************/
	/***************************************************************************/

	/**
     * generates the array containing to-be-parsed stuff:
     * $blocks["main"],$blocks["main.table"],$blocks["main.table.row"], etc.
     * also builds the reverse parse order.
     *
     * @access public - aiming for private
     * @param string $con content to be processed
     * @param string $parentblock name of the parent block in the block hierarchy
     */
	function _maketree ($con, $parentblock='') {

		$blocks = array();

		$con2 = explode($this->block_start_delim, $con);

		if (!empty($parentblock)) {

			$block_names = explode('.', $parentblock);
			$level = sizeof($block_names);

		} else {

			$block_names = array();
			$level = 0;
		}

		// JRC 06/04/2005 Added block comments (on BEGIN or END) <!-- BEGIN: block_name#Comments placed here -->
		//$patt = "($this->block_start_word|$this->block_end_word)\s*(\w+)\s*$this->block_end_delim(.*)";
		$patt = "(" . $this->block_start_word . "|" . $this->block_end_word . ")\s*(\w+)" . $this->comment_preg . "\s*" . $this->block_end_delim . "(.*)";

		foreach($con2 as $k => $v) {

			$res = array();

			if (preg_match_all("/$patt/ims", $v, $res, PREG_SET_ORDER)) {
				// $res[0][1] = BEGIN or END
				// $res[0][2] = block name
				// $res[0][3] = comment
				// $res[0][4] = kinda content
				$block_word	= $res[0][1];
				$block_name	= $res[0][2];
				$comment	= $res[0][3];
				$content	= $res[0][4];

				if (strtoupper($block_word) == $this->block_start_word) {

					$parent_name = implode('.', $block_names);

					// add one level - array("main","table","row")
					$block_names[++$level] = $block_name;

					// make block name (main.table.row)
					$cur_block_name=implode('.', $block_names);

					// build block parsing order (reverse)
					$this->block_parse_order[] = $cur_block_name;

					//add contents. trinary operator eliminates assign error in E_ALL reporting
					$blocks[$cur_block_name] = isset($blocks[$cur_block_name]) ? $blocks[$cur_block_name] . $content : $content;

					// add {_BLOCK_.blockname} string to parent block
					$blocks[$parent_name] .= str_replace('\\', '', $this->tag_start_delim) . '_BLOCK_.' . $cur_block_name . str_replace('\\', '', $this->tag_end_delim);

					// store sub block names for autoresetting and recursive parsing
					$this->sub_blocks[$parent_name][] = $cur_block_name;

					// store sub block names for autoresetting
					$this->sub_blocks[$cur_block_name][] = '';

				} else if (strtoupper($block_word) == $this->block_end_word) {

					unset($block_names[$level--]);

					$parent_name = implode('.', $block_names);

					// add rest of block to parent block
					$blocks[$parent_name] .= $content;
				}
			} else {

				// no block delimiters found
				// Saves doing multiple implodes - less overhead
				$tmp = implode('.', $block_names);

				if ($k) {
					$blocks[$tmp] .= $this->block_start_delim;
				}

				// trinary operator eliminates assign error in E_ALL reporting
				$blocks[$tmp] = isset($blocks[$tmp]) ? $blocks[$tmp] . $v : $v;
			}
		}

		return $blocks;
	}

	/**
     * Sub processing for assign_file method
     *
     * @access private
     * @param string $name
     * @param string $val
     */
	function _assign_file_sub ($name, $val) {

		if (isset($this->filevar_parent[$name])) {

			if ($val != '') {

				$val = $this->_r_getfile($val);

				foreach($this->filevar_parent[$name] as $parent) {

					if (isset($this->preparsed_blocks[$parent]) && !isset($this->filevars[$name])) {

						$copy = $this->preparsed_blocks[$parent];

					} elseif (isset($this->blocks[$parent])) {

						$copy = $this->blocks[$parent];
					}

					$res = array();

					preg_match_all($this->filevar_delim, $copy, $res, PREG_SET_ORDER);

					if (is_array($res) && isset($res[0])) {

						// Changed as per solution in SF bug ID #1261828
						foreach ($res as $v) {

							// Changed as per solution in SF bug ID #1261828
							if ($v[1] == $name) {

								// Changed as per solution in SF bug ID #1261828
								$copy = preg_replace("/" . preg_quote($v[0]) . "/", "$val", $copy);
								$this->preparsed_blocks = array_merge($this->preparsed_blocks, $this->_maketree($copy, $parent));
								$this->filevar_parent = array_merge($this->filevar_parent, $this->_store_filevar_parents($this->preparsed_blocks));
							}
						}
					}
				}
			}
		}

		$this->filevars[$name] = $val;
	}

	/**
     * store container block's name for file variables
     *
     * @access public - aiming for private
     * @param array $blocks
     * @return array
     */
	function _store_filevar_parents ($blocks){

		$parents = array();

		foreach ($blocks as $bname => $con) {

			$res = array();

			preg_match_all($this->filevar_delim, $con, $res);

			foreach ($res[1] as $k => $v) {

				$parents[$v][] = $bname;
			}
		}
		return $parents;
	}

	/**
     * Set the error string
     *
     * @access private
     * @param string $str
     */
	function _set_error ($str)    {

		// JRC: 3/1/2003 Made to append the error messages
		$this->_error .= '* ' . $str . " *\n";
		// JRC: 3/1/2003 Removed trigger error, use this externally if you want it eg. trigger_error($xtpl->get_error())
		//trigger_error($this->get_error());
	}

	/**
     * returns the contents of a file
     *
     * @access protected
     * @param string $file
     * @return string
     */
	function _getfile ($file) {

		if (!isset($file)) {
			// JC 19/12/02 added $file to error message
			$this->_set_error('!isset file name!' . $file);

			return '';
		}

		// check if filename is mapped to other filename
		if (isset($this->files)) {

			if (isset($this->files[$file])) {

				$file = $this->files[$file];
			}
		}

		// prepend template dir
		if (!empty($this->tpldir)) {

			/**
			 * Support hierarchy of file locations to search
			 *
			 * @example Supply array of filepaths when instantiating
			 * 			First path supplied that has the named file is prioritised
			 * 			$xtpl = new XTemplate('myfile.xtpl', array('.','/mypath', '/mypath2'));
			 * @since 29/05/2007
			 */
			if (is_array($this->tpldir)) {

				foreach ($this->tpldir as $dir) {

					if (is_readable($dir . DIRECTORY_SEPARATOR . $file)) {
						$file = $dir . DIRECTORY_SEPARATOR . $file;
						break;
					}
				}
			} else {

				$file = $this->tpldir. DIRECTORY_SEPARATOR . $file;
			}
		}

		$file_text = '';

		if (isset($this->filecache[$file])) {

			$file_text .= $this->filecache[$file];

			if ($this->debug) {
				$file_text = '<!-- XTemplate debug cached: ' . realpath($file) . ' -->' . "\n" . $file_text;
			}

		} else {

			if (is_file($file) && is_readable($file)) {

				if (filesize($file)) {

					if (!($fh = fopen($file, 'r'))) {

						$this->_set_error('Cannot open file: ' . realpath($file));
						return '';
					}

					$file_text .= fread($fh,filesize($file));
					fclose($fh);

				}

				if ($this->debug) {
					$file_text = '<!-- XTemplate debug: ' . realpath($file) . ' -->' . "\n" . $file_text;
				}

			} elseif (str_replace('.', '', phpversion()) >= '430' && $file_text = @file_get_contents($file, true)) {
				// Enable use of include path by using file_get_contents
				// Implemented at suggestion of SF Feature Request ID #1529478 michaelgroh
				if ($file_text === false) {
					$this->_set_error("[" . realpath($file) . "] ($file) does not exist");
					$file_text = "<b>__XTemplate fatal error: file [$file] does not exist in the include path__</b>";
				} elseif ($this->debug) {
					$file_text = '<!-- XTemplate debug: ' . realpath($file) . ' (via include path) -->' . "\n" . $file_text;
				}
			} elseif (!is_file($file)) {

				// NW 17 Oct 2002 : Added realpath around the file name to identify where the code is searching.
				$this->_set_error("[" . realpath($file) . "] ($file) does not exist");
				$file_text .= "<b>__XTemplate fatal error: file [$file] does not exist__</b>";

			} elseif (!is_readable($file)) {

				$this->_set_error("[" . realpath($file) . "] ($file) is not readable");
				$file_text .= "<b>__XTemplate fatal error: file [$file] is not readable__</b>";
			}

			$this->filecache[$file] = $file_text;
		}

		return $file_text;
	}

	/**
     * recursively gets the content of a file with {FILE "filename.tpl"} directives
     *
     * @access public - aiming for private
     * @param string $file
     * @return string
     */
	function _r_getfile ($file) {

		$text = $this->_getfile($file);

		$res = array();

		while (preg_match($this->file_delim,$text,$res)) {

			$text2 = $this->_getfile($res[1]);
			$text = preg_replace("'".preg_quote($res[0])."'",$text2,$text);
		}

		return $text;
	}


	/**
     * add an outer block delimiter set useful for rtfs etc - keeps them editable in word
     *
     * @access private
     */
	function _add_outer_block () {

		$before = $this->block_start_delim . $this->block_start_word . ' ' . $this->mainblock . ' ' . $this->block_end_delim;
		$after = $this->block_start_delim . $this->block_end_word . ' ' . $this->mainblock . ' ' . $this->block_end_delim;

		$this->filecontents = $before . "\n" . $this->filecontents . "\n" . $after;
	}

	/**
     * Debug function - var_dump wrapped in '<pre></pre>' tags
     *
     * @access private
     * @param multiple var_dumps all the supplied arguments
     */
	function _pre_var_dump ($args) {

		if ($this->debug) {
			echo '<pre>';
			var_dump(func_get_args());
			echo '</pre>';
		}
	}
} /* end of XTemplate class. */

?>