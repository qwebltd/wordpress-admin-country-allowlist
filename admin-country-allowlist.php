<?php
/*
Plugin Name:  Admin Country Allowlist
Plugin URI:   https://github.com/qwebltd/wordpress-admin-country-allowlist
Description:  By far the simplest country allowlist plugin available. Locks admin panel and XMLRPC access to a given list of allowed countries using QWeb's IP to country lookup API.
Version:      1.4.0
Author:       QWeb Ltd
Author URI:   https://www.qweb.co.uk
License:      MIT
License URI:  https://opensource.org/license/mit/
Text Domain:  admin-country-allowlist
*/

	// Prevent direct access
	if(!defined( 'ABSPATH' ))
		exit;

	// Function to return the visitors IP
	function qweb_aca_get_visitor_ip() {
		// If using Cloudflare
		if(isset($_SERVER['HTTP_CF_CONNECTING_IP']) && rest_is_ip_address(sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP'])))
			return sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP']);

		// If behind a firewall
		if(isset($_SERVER['HTTP_X_SUCURI_CLIENTIP']) && rest_is_ip_address(sanitize_text_field($_SERVER['HTTP_X_SUCURI_CLIENTIP'])))
			return sanitize_text_field($_SERVER['HTTP_X_SUCURI_CLIENTIP']);
		elseif(isset($_SERVER['HTTP_INCAP_CLIENT_IP']) && rest_is_ip_address(sanitize_text_field($_SERVER['HTTP_INCAP_CLIENT_IP'])))
			return sanitize_text_field($_SERVER['HTTP_INCAP_CLIENT_IP']);

		// Other headers can be forged by proxy servers, so we ignore them and just check REMOTE_ADDR at this point
		if(isset($_SERVER['REMOTE_ADDR']) && rest_is_ip_address(sanitize_text_field($_SERVER['REMOTE_ADDR'])))
			return sanitize_text_field($_SERVER['REMOTE_ADDR']);

		return false;
	}

	// Function to return the cache folder path. Giving this its own function just makes it easier to change
	function qweb_aca_cache_folder() {
		return wp_upload_dir()['basedir'].DIRECTORY_SEPARATOR.'qweb-aca-cache';
	}

	// Function to communicate with the API endpoint
	function qweb_aca_ip_lookup($accessKey, $ip) {
		$response = wp_remote_retrieve_body(wp_remote_get('https://apis.qweb.co.uk/ip-lookup/'.$accessKey.'/'.$ip.'.json'));

		if($response !== '')
			return json_decode($response);
		else
			return 'There was an error communicating with the lookup service. If this problem persists, your server might be blocked or having network issues. Contact your web host for support.';
	}

	// Function to look up the country of the visitors IP and check that it's in the allow list
	function qweb_aca_ip_check() {
		// We only want to proceed if an access key and at least one allowed country has been entered
		$accessKey = trim(get_option('qweb_aca_access_key'));
		$allowedCountries = get_option('qweb_aca_allowed_countries');

		if($accessKey != '' && is_array($allowedCountries) && !empty($allowedCountries)) {
			$ip = qweb_aca_get_visitor_ip();

			// To prevent getting accidentally locked out of Wordpress due to a bad server config, if we can't determine the visitor IP, just allow access
			if($ip !== false) {
				// The API works with IPv4 and IPv6 addresses, and further validates them, so we don't need to do any more logic here. the rest_is_ip_address() calls are enough

				// Cache the results in static files for performance
				$cacheDirectory = qweb_aca_cache_folder();

				if(!is_dir($cacheDirectory))
					mkdir($cacheDirectory, 0755);

				$cacheFile = $cacheDirectory.DIRECTORY_SEPARATOR.preg_replace('/[^0-9a-f]/', '_', $ip).'.json';

				// If we've already checked this IP and the cache is less than a week old, just use it
				if(is_file($cacheFile) && filemtime($cacheFile) >= time() - 604800)
					$data = json_decode(file_get_contents($cacheFile));
				else {
					// Otherwise, use the QWeb API to get its information
					$data = qweb_aca_ip_lookup($accessKey, $ip);

					// And cache the result
					if(isset($data->answer) && $data->answer == 'success')
						file_put_contents($cacheFile, json_encode($data));
				}

				if(isset($data)) {
					if(isset($data->answer)) {
						if($data->answer == 'success') {
							// If we've received a successful response, we must be within the quota allowance so remove any previously set 'reached' flag
							if(get_transient('qweb_aca_quota_reached') !== false)
								delete_transient('qweb_aca_quota_reached');

							// Check that the returned country code is in our allowlist and, if allow_known_proxies is false, check that the IP isn't a known proxy
							if(($data->is_proxy == 'yes' && !get_option('qweb_aca_allow_known_proxies')) || !in_array($data->country, $allowedCountries)) {
								// Access isn't allowed
								header('HTTP/1.0 403 Forbidden');
								exit;
							}
						} else {
							// We don't want to bombard inboxes when an access quota is reached, so:
							$quotaReached = stripos($data->answer, 'this limit has already been reached') !== false;

							if(!$quotaReached || ($quotaReached && get_transient('qweb_aca_quota_reached') === false)) {
								if($quotaReached) {
									set_transient('qweb_aca_quota_reached', true);
									$data->answer .= ' Blocking is now paused until you fall back within your quota.';
								}

								wp_mail(get_bloginfo('admin_email'), get_bloginfo('name').' - '.__('IP to country lookup failed!', 'admin-country-allowlist'), sprintf(
									__('The following response was received from the lookup API when attempting to verify the country of IP %1$s: %2$s', 'admin-country-allowlist'),
									esc_html($ip),
									esc_html($data->answer)
								));
							}
						}
					} else {
						wp_mail(get_bloginfo('admin_email'), get_bloginfo('name').' - '.__('IP to country lookup failed!', 'admin-country-allowlist'), sprintf(
							__('The following error was generated when attempting to verify the country of IP %1$s: %2$s', 'admin-country-allowlist'),
							esc_html($ip),
							esc_html($data)
						));
					}
				}
			}
		}

		return true;
	}

	// Function to create necessary folders/options and do basic sanity checks on activation
	function qweb_aca_activation() {
		// Create the cache folder
		$cacheDirectory = qweb_aca_cache_folder();

		if(!is_dir($cacheDirectory))
			mkdir($cacheDirectory, 0755);

		// Create the options
		add_option('qweb_aca_access_key', '');
		add_option('qweb_aca_allowed_countries', array());
		add_option('qweb_aca_allow_known_proxies', false);
		add_option('qweb_aca_block_xmlrpc_access', false);

		// Schedule the cache cleaning cron
		if(!wp_next_scheduled('qweb_aca_clear_old_cache_event'))
			wp_schedule_event(time(), 'daily', 'qweb_aca_clear_old_cache_event');

		return true;
	}

	function qweb_aca_deactivation() {
		// We keep the cache and options in place until uninstallation, but we don't want to keep the cron running if the plugin is deactivated
		wp_unschedule_event(wp_next_scheduled('qweb_aca_clear_old_cache_event'), 'qweb_aca_clear_old_cache_event');
	}

	// Function to clean up on uninstallation
	function qweb_aca_uninstallation() {
		// Unschedule the cache cleaning cron. We do this first, to make sure it doesn't run again after deleting the folder
		wp_unschedule_event(wp_next_scheduled('qweb_aca_clear_old_cache_event'), 'qweb_aca_clear_old_cache_event');

		// Delete the cache folder
		$cacheDirectory = qweb_aca_cache_folder();

		if(is_dir($cacheDirectory)) {
			// Folders must be empty before deletion
			foreach (array_diff(scandir($cacheDirectory), array('.','..')) as $file) {
				unlink($cacheDirectory.DIRECTORY_SEPARATOR.$file);
			}

			rmdir($cacheDirectory);
		}

		// Delete the options
		delete_option('qweb_aca_access_key');
		delete_option('qweb_aca_allowed_countries');
		delete_option('qweb_aca_allow_known_proxies');
		delete_option('qweb_aca_block_xmlrpc_access');

		// Remove htaccess entries
		if(extract_from_markers(get_home_path().'.htaccess', 'QWeb Admin Country Allowlist XMLRPC Blocking'))
			insert_with_markers(get_home_path().'.htaccess', 'QWeb Admin Country Allowlist XMLRPC Blocking', '');

		return true;
	}

	// Function to return an array of recognised country codes.
	function qweb_aca_country_codes() {
		return array('AD','AE','AF','AG','AI','AL','AM','AO','AR','AT','AU','AW','AX','AZ','BA','BB','BD','BE','BF','BG','BH','BI','BJ','BL','BM','BN','BO','BQ','BR','BS','BT','BV','BW','BY','BZ','CA','CC','CD','CF','CG','CH','CI','CK','CL','CM','CN','CO','CR','CU','CV','CW','CX','CY','CZ','DE','DJ','DK','DM','DO','DZ','EC','EE','EG','ER','ES','ET','FI','FJ','FK','FM','FO','FR','GA','GB','GD','GE','GF','GG','GH','GI','GL','GM','GN','GP','GQ','GR','GS','GT','GU','GW','GY','HK','HM','HN','HR','HT','HU','ID','IE','IL','IM','IN','IO','IQ','IR','IS','IT','JE','JM','JO','JP','KE','KG','KH','KI','KM','KN','KP','KR','KW','KY','KZ','LA','LB','LC','LI','LK','LR','LS','LT','LU','LV','LY','MA','MC','MD','ME','MF','MG','MH','MK','ML','MM','MN','MO','MP','MQ','MR','MS','MT','MU','MV','MW','MX','MY','MZ','NA','NC','NE','NF','NG','NI','NL','NO','NP','NR','NU','NZ','OM','PA','PE','PF','PG','PH','PK','PL','PM','PN','PR','PS','PT','PW','PY','QA','RE','RO','RS','RU','RW','SA','SB','SC','SD','SE','SG','SH','SI','SK','SL','SM','SN','SO','SR','SS','ST','SV','SX','SY','SZ','TC','TD','TF','TG','TH','TJ','TK','TL','TM','TN','TO','TR','TT','TV','TW','TZ','UA','UG','UM','US','UY','UZ','VA','VC','VE','VG','VI','VN','VU','WF','WS','XK','YE','YT','ZA','ZM','ZW');
	}

	// Function to generate the settings page
	function qweb_aca_settings_page() {
		// Check user capabilities
		if(!current_user_can('manage_options')) {
			return;
		}
?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
		<p><?php echo __('Use these settings to restrict access to your Wordpress administration panel, and the XMLRPC mechanism. You should allow access to only the countries where you know legitimate administrators need to log in from, so that for most of the world, your administration panel is inaccessible and malicious bots will have a much harder time finding security holes to exploit.', 'admin-country-allowlist'); ?></p>
		<p><?php echo __('Generate an access key for the IP Lookup API via the <a href="https://apis.qweb.co.uk/console" target="_blank">QWeb API Console</a> and enter it here. <strong>Access keys are FREE!</strong>', 'admin-country-allowlist'); ?></p>
<?php
		// show error/update messages
		settings_errors( 'qweb_aca_messages' );
?>
		<form action="options.php" method="post">
<?php
		// Output the nonce fields for the registered settings
		settings_fields('qweb_aca_options');

		// Output the actual fields
		do_settings_sections(__FILE__);

		// Output a save button
		submit_button( __('Save Settings', 'admin-country-allowlist'));
?>
		</form>
		<h2><?php echo __('Statistics', 'admin-country-allowlist'); ?></h2>
		<p><?php echo __('You can see how many IP lookups are being processed via the <a href="https://apis.qweb.co.uk/console" target="_blank">QWeb API Console</a>. Simply log in, locate your access key from the list, and tap the <strong>Usage report</strong> icon.', 'admin-country-allowlist'); ?></p>
		<p><?php echo __('Requests to the lookup service are only made once per unique IP, and only if that IP is attempting admin access. This plugin then caches the response for a week, so legitimate administrators and the occasional attacks tend not to invoke many lookups. For most websites, you should only need a free access key and likely won\'t come close to the requests quota. If the usage graphs suggest otherwise, or you receive an email notification from this plugin because you\'re reaching the quota, then you can upgrade to a paid tier at any time by purchasing a subscription or switching an existing subscription to another tier.', 'admin-country-allowlist'); ?></p>
		<p><a class="button" href="https://apis.qweb.co.uk/console"><?php echo __('QWeb API Console', 'admin-country-allowlist'); ?></a></p>
<?php
		// Output content below the settings form, once activated and in use.
		if(trim(get_option('qweb_aca_access_key')) != '') {
?>
		<h2><?php echo __('Like this plugin?', 'admin-country-allowlist'); ?></h2>
		<p><?php echo __('Please <a href="https://wordpress.org/support/plugin/admin-country-allowlist/reviews/#new-post" target="_blank">leave a review</a> to help other website owners know what you think of this plugin.', 'admin-country-allowlist'); ?></p>
		<p><a class="button" href="https://wordpress.org/support/plugin/admin-country-allowlist/reviews/#new-post"><?php echo __('Review', 'admin-country-allowlist'); ?></a></p>
<?php
		}
?>
	</div>
<?php
	}

	// Function to register settings
	function qweb_aca_register_settings() {
		// Register fields and sanitising functions so that Wordpress creates the relevant database entries for them
		register_setting( 'qweb_aca_options', 'qweb_aca_access_key', array('type' => 'string', 'description' => 'Your access key provided by the QWeb API portal', 'sanitize_callback' => function($input) {
			// Sanitise the field input

			// Use the QWeb API to get this visitors IP information using the entered key, because then we know if the key is valid, plus we can make sure the country is in the allowed list.
			// This purposefully doesn't use the cache mechanic because we need to know that the access key is valid
			$accessKey = trim((string)$input);

			if($accessKey != '') {
				$data = qweb_aca_ip_lookup($accessKey, qweb_aca_get_visitor_ip());

				if($data->answer == 'success') {
					// Make sure $data->country is an allowed country
					$allowedCountries = get_option('qweb_aca_allowed_countries');
					if(in_array($data->country, qweb_aca_country_codes()) && !in_array($data->country, $allowedCountries)) {
						// Add this country in to the allow list. This triggers our sanitise function the same as if the settings page was used, so we can leave that to convert to a sorted array
						array_push($allowedCountries, $data->country);
						update_option('qweb_aca_allowed_countries', implode(',', $allowedCountries));
					}
				} else
					add_settings_error('qweb_aca_access_key', 'qweb_aca_access_key_error', sprintf(
						__('The following response was received from the lookup API when attempting to verify the country of IP %1$s: %2$s', 'admin-country-allowlist'),
						esc_html($ip),
						esc_html($data->answer)
					), 'error');
			} else
				add_settings_error('qweb_aca_access_key', 'qweb_aca_access_key_error', __('You must enter a valid access key', 'admin-country-allowlist'), 'error');

			// Output sanitised value for Wordpress to save
			return $accessKey;
		}));

		register_setting( 'qweb_aca_options', 'qweb_aca_allowed_countries', array('type' => 'string', 'description' => 'Comma separated list of ISO 3166-1 alpha-2 country codes to allow', 'sanitize_callback' => function($input) {
			// Sanitise the field input

			// Turn the submitted string into an array of codes, iterate to verify each, and build a new array of those we accept
			$sanitisedCodes = array();

			foreach(explode(',', $input) as $iKey => $iVal) {
				$code = strtoupper(trim($iVal));
				if(in_array($code, qweb_aca_country_codes()))
					array_push($sanitisedCodes, $code);
			}

			// If we have an access key, make sure this visitors country is in the allow list
			$accessKey = trim(get_option('qweb_aca_access_key'));

			if($accessKey != '') {
				$data = qweb_aca_ip_lookup($accessKey, qweb_aca_get_visitor_ip());

				if($data->answer == 'success') {
					if(in_array($data->country, qweb_aca_country_codes()) && !in_array($data->country, $sanitisedCodes))
						array_push($sanitisedCodes, $data->country);
				}
			}

			// Alphabetical sorting
			sort($sanitisedCodes);

			// Output sanitised value for Wordpress to save
			// It doesn't matter if the array is empty at this point, it'll just trigger the qweb_aca_empty_countries_list notice if that happens
			return $sanitisedCodes;
		}));

		register_setting( 'qweb_aca_options', 'qweb_aca_allow_known_proxies', array('type' => 'boolean', 'description' => 'Should access be granted to known proxy IPs in these countries?', 'sanitize_callback' => function($input) {
			// Sanitise the field input

			// Output sanitised value for Wordpress to save
			// We basically only care if the submitted value is a yes. Anything else and we can just consider it a no.
			return ($input == 'yes');
		}));

		register_setting( 'qweb_aca_options', 'qweb_aca_block_xmlrpc_access', array('type' => 'boolean', 'description' => 'Should access to XMLRPC be blocked completely?', 'sanitize_callback' => function($input) {
			// Sanitise the field input

			// If the submitted value is a yes, try to write a htaccess entry. Anything else and we can just consider it a no.
			if($input == 'yes') {
				if(!insert_with_markers(get_home_path().'.htaccess', 'QWeb Admin Country Allowlist XMLRPC Blocking', array(
					'<Files xmlrpc.php>',
					'	Order Deny,Allow',
					'	Deny from all',
					'</Files>',
				))) {
					add_settings_error('qweb_aca_block_xmlrpc_access', 'qweb_aca_block_xmlrpc_access_error', __('Failed to update your .htaccess file with XMLRPC access blocking lines. Please ensure this file is accessible with read:write permissions', 'admin-country-allowlist'), 'error');

					return get_option('qweb_aca_block_xmlrpc_access'); // Revert to the original setting
				}
			} else {
				// Remove htaccess entries
				if(extract_from_markers(get_home_path().'.htaccess', 'QWeb Admin Country Allowlist XMLRPC Blocking')) {
					if(!insert_with_markers(get_home_path().'.htaccess', 'QWeb Admin Country Allowlist XMLRPC Blocking', '')) {
						add_settings_error('qweb_aca_block_xmlrpc_access', 'qweb_aca_block_xmlrpc_access_error', __('Failed to remove the XMLRPC access blocking lines from your .htaccess file. Please ensure this file is accessible with read:write permissions', 'admin-country-allowlist'), 'error');

						return get_option('qweb_aca_block_xmlrpc_access'); // Revert to the original setting
					}
				}
			}

			// If we get this far, then everything worked and we can store the submitted value as intended.
			return ($input == 'yes');
		}));

		// Add a section to drop fields into
		add_settings_section('qweb_aca_options_general', 'Options', function() {}, __FILE__);

		// Create the fields
		add_settings_field('qweb_aca_access_key', 'Access key', function() {
			echo '
				<input name="qweb_aca_access_key" type="text" id="qweb_aca_access_key" value="'.esc_attr(get_option('qweb_aca_access_key')).'" class="regular-text" />
				<p class="description">'.__('Your access key provided by the <a href="https://apis.qweb.co.uk/console" target="_blank">QWeb API Console</a>.', 'admin-country-allowlist').'</p>';
		}, __FILE__, 'qweb_aca_options_general');

		add_settings_field( 'qweb_aca_allowed_countries', 'Allowed countries', function() {
			// TODO need a fancy mechanic to make populating this field easier, while keeping it a text input for copy + paste population
			echo '
				<input name="qweb_aca_allowed_countries" type="text" id="qweb_aca_allowed_countries" value="'.esc_attr(implode(',', get_option('qweb_aca_allowed_countries'))).'" class="regular-text" />
				<p class="description">'.__('Comma separated list of <a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Officially_assigned_code_elements" target="_blank">ISO 3166-1 alpha-2 country codes</a> you allow admin panel access to.', 'admin-country-allowlist').'</p>';
		}, __FILE__, 'qweb_aca_options_general');

		add_settings_field( 'qweb_aca_allow_known_proxies', 'Allow known proxies?', function() {
			$currentValue = get_option('qweb_aca_allow_known_proxies');

			echo '
				<select name="qweb_aca_allow_known_proxies" id="qweb_aca_allow_known_proxies">
					<option value="yes"'.($currentValue ? ' selected="selected"' : '').'>'.__('Allow', 'admin-country-allowlist').'</option>
					<option value="no"'.(!$currentValue ? ' selected="selected"' : '').'>'.__('Disallow', 'admin-country-allowlist').'</option>
				</select>
				<p class="description">'.__('If an IP is from an allowed country, but we know it to be a proxy server, should we still allow access?', 'admin-country-allowlist').'</p>';
		}, __FILE__, 'qweb_aca_options_general');

		add_settings_field( 'qweb_aca_block_xmlrpc_access', 'Block XMLRPC access?', function() {
			$currentValue = get_option('qweb_aca_block_xmlrpc_access');

			echo '
				<select name="qweb_aca_block_xmlrpc_access" id="qweb_aca_block_xmlrpc_access">
					<option value="yes"'.($currentValue ? ' selected="selected"' : '').'>'.__('Block access completely', 'admin-country-allowlist').'</option>
					<option value="no"'.(!$currentValue ? ' selected="selected"' : '').'>'.__('Allow access to authorised countries only', 'admin-country-allowlist').'</option>
				</select>
				<p class="description">'.__('If you\'re certain that nothing needs access to the Wordpress XMLRPC mechanism, then blocking access completely will save from having to perform API lookups for these requests, which can dramatically reduce the number of API requests that this website needs to invoke and help keep you within your API usage quota.', 'admin-country-allowlist').'</p>
				<p class="description"><strong>'.__('If you don\'t know what XMLRPC is, then you can almost certainly block access completely.', 'admin-country-allowlist').'</strong></p>';
		}, __FILE__, 'qweb_aca_options_general');
	}

	// Function to add a settings link to the plugin in the plugins list
	function qweb_aca_list_settings_link($links) {
		// Filters the links in the plugin item of the plugins list, to include a settings link too
		array_push($links, '<a href="'.admin_url( 'options-general.php?page='.plugin_basename(__FILE__)).'">'.__('Settings', 'admin-country-allowlist').'</a>');
		return $links;
	}

	// Function to clear old cache files
	function qweb_aca_clear_old_cache() {
		$cacheDirectory = qweb_aca_cache_folder();

		// Only continue if this is a valid directory
		if(is_dir($cacheDirectory)) {
			// Delete cache older than 1 week
			$maxAge = time() - 604800;

			foreach (array_diff(scandir($cacheDirectory), array('.','..')) as $file) {
				if(filemtime($cacheDirectory.DIRECTORY_SEPARATOR.$file) < $maxAge)
					unlink($cacheDirectory.DIRECTORY_SEPARATOR.$file);
			}
		}
	}

	// Function to add a new item to the settings menu
	function qweb_aca_create_menu() {
		add_options_page('Admin Country Allowlist', 'Admin Country Allowlist', 'administrator', __FILE__, 'qweb_aca_settings_page');
	}

	// Add settings link to the plugins list page
	add_filter('plugin_action_links_'.plugin_basename(__FILE__), 'qweb_aca_list_settings_link');

	// Add settings link to the menu
	add_action('admin_menu', 'qweb_aca_create_menu');

	// Register the settings
	add_action('admin_init', 'qweb_aca_register_settings');

	// Plugin activation, deactivation, and uninstallation hooks
	register_activation_hook(__FILE__, 'qweb_aca_activation');
	register_deactivation_hook(__FILE__, 'qweb_aca_deactivation');
	register_uninstall_hook(__FILE__, 'qweb_aca_uninstallation');

	// Cron event to delete old cache every week. This is scheduled during activation
	add_action('qweb_aca_clear_old_cache_event', 'qweb_aca_clear_old_cache');

	// admin-ajax.php requests cause is_admin() to return true, but front end plugins also use it so we shouldn't block
	if(strpos($_SERVER['REQUEST_URI'], 'admin-ajax.php') === false) {
		if(is_admin()) {
			// Basic sanity checks and error outputs if logged in to the admin panel

			// Check cache directory exists
			$qwebAcaCacheDirectory = qweb_aca_cache_folder();

			if(!is_dir($qwebAcaCacheDirectory) && !mkdir($qwebAcaCacheDirectory, 0755)) {
				function qweb_aca_cache_folder_missing() {
					printf(
						'<div class="%1$s"><h2>'.__('Admin Country Allowlist', 'admin-country-allowlist').'</h2><p>%2$s %3$s</p></div>',
						esc_attr('notice notice-error'),
						esc_html__('Failed to automatically create the lookups cache folder. Please create the following folder, and ensure it\'s accessible with read:write permissions:', 'admin-country-allowlist'),
						esc_html($qwebAcaCacheDirectory)
					);
				}

				add_action('admin_notices', 'qweb_aca_cache_folder_missing');
			} elseif(!is_writable($qwebAcaCacheDirectory)) {
				function qweb_aca_cache_folder_not_writable() {
					printf(
						'<div class="%1$s"><h2>'.__('Admin Country Allowlist', 'admin-country-allowlist').'</h2><p>%2$s %3$s</p></div>',
						esc_attr('notice notice-error'),
						esc_html__('The following folder isn\'t currently accessible with read:write permissions:', 'admin-country-allowlist'),
						esc_html($qwebAcaCacheDirectory)
					);
				}

				add_action('admin_notices', 'qweb_aca_cache_folder_not_writable');
			}

			// Check an access key is saved
			if(trim(get_option('qweb_aca_access_key')) == '') {
				function qweb_aca_access_key_missing() {
					printf(
						'<div class="%1$s"><h2>'.__('Admin Country Allowlist', 'admin-country-allowlist').'</h2><p>%2$s</p><p><a class="button" href="'.admin_url( 'options-general.php?page='.plugin_basename(__FILE__)).'">%3$s</a></p></div>',
						esc_attr('notice notice-error'),
						esc_html__('You need to obtain an API access key before this plugin can secure your website. Refer to the settings page for details.', 'admin-country-allowlist'),
						esc_html__('Settings', 'admin-country-allowlist')
					);
				}

				add_action('admin_notices', 'qweb_aca_access_key_missing');
			} else {
				// Check at least one country is allowed
				if(!array(get_option('qweb_aca_allowed_countries')) || empty(get_option('qweb_aca_allowed_countries'))) {
					function qweb_aca_empty_countries_list() {
						printf(
							'<div class="%1$s"><h2>'.__('Admin Country Allowlist', 'admin-country-allowlist').'</h2><p>%2$s</p></div>',
							esc_attr('notice notice-error'),
							esc_html__('You need to allow at least one country before this plugin can secure your website.', 'admin-country-allowlist')
						);
					}

					add_action('admin_notices', 'qweb_aca_empty_countries_list');
				}
			}
		}

		// Hook in to the init routine of all admin pages and scripts
		add_filter('admin_init', 'qweb_aca_ip_check');

		// Determine if this is a request for an admin page that doesn't trigger admin_init (because we're not yet logged in, for example), or for the XMLRPC mechanic which is basically an admin endpoint
		if((stripos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false && ($GLOBALS['pagenow'] === 'wp-login.php' || $_SERVER['PHP_SELF'] === '/wp-login.php') && stripos($_SERVER['REQUEST_URI'], 'redirect_to='.admin_url()) !== false) || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST))
			add_action('init', 'qweb_aca_ip_check');
	}