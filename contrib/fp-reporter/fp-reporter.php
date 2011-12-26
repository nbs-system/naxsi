<?
/*
 * Fp-reporter, false positive reporter PHP script for Naxsi
 * Copyright (C) 2011, Thibault 'bui' Koechlin, Didier Conchaudron
 * 
 * Version 0.1
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Original lib fropm ReCAPTCHA
require_once('recaptchalib.php');
$public_key="YourReCAPTCHAPublicKeyHere";
$private_key="YourReCAPTCHAPrivateKeyHere";

// You might customize your own error message here
define ("CUSTOM_ERROR_PAGE", "<h1>Request Denied !</h1></br>".
	"Your request has been denied, but please don't panick.</br>".
	"If you are not a hacker, please fill the CAPTCHA bellow, </br>".
	"So that administrators can have a look at this error.</br>".
	"Thanks !</br>");
define ("CORE_RULES_FILE", "/etc/nginx/naxsi_core.rules");
define ("MAIL_DST", "foo@bar.com");
define ("MAIL_SUBJECT", "[NAXSI] A request has been from on your site.");

session_start();

if (isset($_SERVER["HTTP_NAXSI_SIG"]))
  {
    echo "<html><body>".CUSTOM_ERROR_PAGE."<form method=\"post\" action=\"/RequestDenied/forbidden.php\">";
    echo recaptcha_get_html($public_key);
    echo "<input type=\"submit\" /></form></body></html>";
    parse_str($_SERVER["HTTP_NAXSI_SIG"], $nsig);
    $include_body = 0;
    $msg = "";
    $msg .= "The request emited from ".$nsig["ip"]." IP address has been blocked.\n";
    $msg .= "While access page :\n";
    $msg .= $_SERVER["HTTP_ORIG_URL"]."\n";
    $msg .= "With arguments :\n";
    $msg .= $_SERVER["HTTP_ORIG_ARGS"]."\n";
    $msg .= "This request has been blocked for the following reasons :\n";
    

    for ($i = 0; ; $i++)
      {
	if (isset($nsig["id".$i]))
	  {
	    if ($nsig["zone".$i] == "BODY")
	      $include_body = 1;
	    $pattern = get_forbidden_pattern($nsig["id".$i]);
	    if (isset($nsig["var_name".$i]) && strlen($nsig["var_name".$i]) > 0)
	      {
		$rulematch = "The forbidden caracter '".$pattern."' has been detected on '".$nsig["var_name".$i]."' variable";
		$rulematch .= " in zone '".$nsig["zone".$i]."'\n";
		$msg .= $rulematch;
	      }
	    else
	      {
		$rulematch = "The forbidden caracter '".$pattern."' has been detected within '".$nsig["zone".$i]."' zone\n";
		$msg .= $rulematch;
	      }
	  }
	else
	  break;
      }

    if ($include_body == 1)
      {
	ob_start();
	print_r($_POST);
	$output = ob_get_clean();
	$msg .= "------- BODY DUMP ------\n".$output."\n-------------\n";
      }
    
    $msg .= "-------- ORIG NAXSI SIG --------\n".$_SERVER['HTTP_NAXSI_SIG']."\n--------\n";
    $_SESSION["msg"] = $msg;
  }
else
    {
      $resp = recaptcha_check_answer ($private_key,
				      $_SERVER["REMOTE_ADDR"],
				      $_POST["recaptcha_challenge_field"],
				      $_POST["recaptcha_response_field"]);
      
      if (!$resp->is_valid) {
	die ("The reCAPTCHA wasn't entered correctly. Go back and try it again." .
	     "(reCAPTCHA said: " . $resp->error . ")");
      } else {
	echo "Hey, here is your message :<pre>".$_SESSION["msg"]."</pre>";
	destroy_session();
      }
    }
  function get_forbidden_pattern($sig_id)
  {
    if (!file_exists(CORE_RULES_FILE))
      die ("Cannot open ".CORE_RULES_FILE);
    $fd = fopen(CORE_RULES_FILE, "r");
    while(($line = fgets($fd)))
      {
	if (($idx = strpos($line, "id:")))
	  {
	    $rid = intval(substr($line, $idx+3));
	    if ($rid == $sig_id)
	      {
		return (extract_pattern_from_line($line));
		break;
	      }
	  }
      }
    fclose($fd);
  }

  function extract_pattern_from_line($line)
  {
    if (($rid = strpos($line, "rx:")))
      $len = 3;
    else if (($rid = strpos($line, "str:")))
      $len = 4;
    else
      return ("unable to extract pattern");
    $tok_id = strpos(substr($line, $rid+$len), '"');
    return (substr($line, $rid+$len, $tok_id));
  }

  ?>
