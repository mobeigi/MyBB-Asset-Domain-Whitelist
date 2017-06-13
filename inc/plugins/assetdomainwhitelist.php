<?php 
// Disallow direct access to this file for security reasons
if(!defined("IN_MYBB"))
  die("Direct initialization of this file is not allowed.<br /><br />Please make sure IN_MYBB is defined.");

// Hooks
$plugins->add_hook('usercp_editsig_start', 'assetdomainwhitelist_validate_signature');
$plugins->add_hook('datahandler_post_validate_post', 'assetdomainwhitelist_validate_all');
$plugins->add_hook('datahandler_post_validate_thread', 'assetdomainwhitelist_validate_all');
$plugins->add_hook('datahandler_pm_validate', 'assetdomainwhitelist_validate_all');

// Plugin info
function assetdomainwhitelist_info()
{
  return array(
    "name"            => "Asset Domain Whitelist",
    "description"    => "Whitelist asset sources in posts, threads, private messages and user signatures.",
    "website"        => "https://mohammadg.com/",
    "author"        => "Mohammad Ghasembeigi",
    "authorsite"    => "https://mohammadg.com/",
    "version"        => "1.0.0",
    "codename"             => "assetdomainwhitelist",
    "compatibility" => "18*"
  );
}

function assetdomainwhitelist_activate()
{
  global $db;
  // settings
  
  $settings_group = $db->insert_query('settinggroups', [
    'name'        => 'assetdomainwhitelist',
    'title'       => 'Asset Domain Whitelist',
    'description' => 'Settings for Asset Domain Whitelist.',
  ]);
  
  $db->insert_query('settinggroups', $settings_group);
  
  $gid = (int) $db->insert_id();
  $disporder = 1;
  
  $setting = [
    'name'        => 'assetdomainwhitelist_domain_whitelist',
    'title'       => 'Domain Whitelist',
    'description' => 'Comma separated list of domains that images will be processed through.',
    'optionscode' => 'text',
    'value'       => 'i.imgur.com',
    'disporder' => $disporder++,
    'gid' => $gid
  ];
  
  $db->insert_query('settings', $setting);
  
  rebuild_settings();
}

function assetdomainwhitelist_deactivate()
{
  global $db;

  $result = $db->simple_select('settinggroups', 'gid', "name = 'assetdomainwhitelist'");
  $gid = (int) $db->fetch_field($result, "gid");

  if ($gid > 0)
    $db->delete_query('settings', "gid = '{$gid}'");

  $db->delete_query('settinggroups', "gid = '{$gid}'");

  rebuild_settings();
}

function assetdomainwhitelist_validate_signature()
{
  global $mybb, $error;
  
  $ret = assetdomainwhitelist_process_input($mybb->input['signature']);
  if (!empty($ret))
    $error = inline_error($ret);
}

function assetdomainwhitelist_validate_all(&$data)
{
  $ret = assetdomainwhitelist_process_input($data->data['message']);
  
  if (!empty($ret))
    $data->set_error($ret);
}

function assetdomainwhitelist_process_input($input)
{
  global $mybb;
  
  $domainWhitelist = explode(',', $mybb->settings['assetdomainwhitelist_domain_whitelist']);
  
  preg_match_all("/\[img(.*?)\](.*?)\[\/img\]/i", $input, $matches, PREG_SET_ORDER);
  
  foreach ($matches as $img) {
    if (!filter_var($img[2], FILTER_VALIDATE_URL)) {
      $ret = "Invalid URL provided inside [img] tags.";
      break;
    }
    
    $parsedUrl = parse_url($img[2]);

    if ($parsedUrl) {
      $urlHost = $parsedUrl['host'];
      $domainMatched = false;
      
      foreach ($domainWhitelist as &$domain) {
        if (fnmatch($domain, $urlHost)) {
          $domainMatched = true;
          break;
        }
      }
      
      if (!$domainMatched) {
        $ret = "Untrusted image source inside [img] tags.";
        break;
      }
    }
  }
  
  return $ret;
}

?>