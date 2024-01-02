# Wordpress Admin Country Allowlist Plugin
By far the simplest country allowlist plugin available for Wordpress. Locks admin panel and XMLRPC access to a given list of allowed countries using [QWeb's IP to country lookup API](https://apis.qweb.co.uk/ip-lookup/).

This is free open source software (FOSS), which you're welcome to either use as-is, or fork and further develop under the very permissive terms of the [MIT license](LICENSE).

Out of the box, this is most likely the simplest, most efficient plugin for restricting access to your Wordpress admin panel to an allowlist of specific countries. Simply install and activate the plugin, obtain an access key via the QWeb Ltd API console, and enter your access key in the plugin settings. The plugin will automatically determine your own country and add this to the allowlist, and you can add other countries to the list as you like.

Countries are entered as comma separated [ISO 3166-1 alpha-2 country codes](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Officially_assigned_code_elements) in a single field, making it super easy to copy & paste the same list across multiple websites.

This plugin also restricts access to the Wordpress XMLRPC mechanism, using the same country allowlist.

You can optionally choose to allow or disallow access through known public proxy servers, even if they're located in an allowed country.

The plugin creates a cache of IP information and automatically clears cache files older than one week. This reduces the number of lookup requests and keeps your website responsive, without creating an unnecessarily large cache.

As a single 17kb file, this is an exceptionally lightweight plugin. Built to be efficient, and using QWeb's incredibly responsive [IP lookup API]((https://apis.qweb.co.uk/ip-lookup/)), the Admin Country Allowlist plugin should be a part of your standard security kit for any Wordpress websites that you manage.

This plugin relies on [QWeb's IP to country lookup API](https://apis.qweb.co.uk/ip-lookup/) for IP to country lookups, and will not function without an active API key from this service. QWeb does provide a FREE tier for this API service, suitable for most websites. Please refer to the [QWeb Ltd API Terms of Use](https://apis.qweb.co.uk/console/eula) and [QWeb Ltd Privacy Policy](https://www.qweb.co.uk/privacy-policy).

# Installation
- Install from the Wordpress plugin repository, or [download the admin-country-allowlist.zip](admin-country-allowlist.zip) file and upload via your Wordpress admin dashboard.
- Activate the Admin Country Allowlist plugin.
- Log in to the [QWeb Ltd API console](https://apis.qweb.co.uk/console/), generate an API key for the IP Lookup API, and copy this key into the plugin's settings page.
- Optionally, add additional countries to the allowlist as comma separated [ISO 3166-1 alpha-2 country codes](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Officially_assigned_code_elements).
- Optionally choose to allow or disallow known proxy servers, even when they're located within the allowed countries.

# Uninstallation
Simply deactivate and uninstall via the Wordpress dashboard. This plugin will self-clean on uninstallation, leaving no old cache files behind.

# Problems
If you have any problems at all, [contact us for assistance](https://www.qweb.co.uk). We're always happy to help.
