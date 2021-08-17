<?php

function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

function checkIgnore($title,$mail){
	global $ignore_data_array;
	

}
	
function extractObs($obs){	

	global $ignore_data_array;
	global $debug;
	global $log_file;

	$ips = array();
	$domains = array();
	$emails = array();
	$hashs = array();
	$urls = array();
	
	if (is_array($ignore_data_array['domain']) !==true)
		$ignore_data_array['domain'] = array();

	if (is_array($ignore_data_array['ip']) !== true)
		$ignore_data_array['ip'] = array();

	if (is_array($ignore_data_array['url']) !== true)
                $ignore_data_array['url'] = array();

	if(preg_match_all("/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}/", $obs, $ip_matches_raw)) {		
		$ip_matches = array_unique($ip_matches_raw['0'],SORT_STRING);		
		foreach($ip_matches as $ip){			
			if (!in_array($ip,$ignore_data_array['ip']))
				$ips[] = array("dataType" => "ip", "data" => $ip,"message" => "IP Observable");
		}
	} 

	if(preg_match_all('/([a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-zA-Z-]{2,3})["\s\/;:>]+|([a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-zA-Z-]{2,3})["\s\/;:>]+|([a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-zA-Z-]{2,3})["\s\/;:>]+|([a-z0-9A-Z-]+\.[a-z0-9A-Z-]+\.[a-zA-Z-]{2,3})["\s\/;:>]+|([a-z0-9A-Z-]+\.[a-zA-Z-]{2,3})["\s\/;:>]+/', $obs, $domain_matches_raw)) {
		//print_r($domain_matches_raw);
		//die();
		if ($debug > 1)
		        file_put_contents($log_file,"-------------------------\nOutput preg domain => \nOut: ".print_r($domain_matches_raw,1),FILE_APPEND);
		$domain_matches = array_unique(array_merge($domain_matches_raw['1'],$domain_matches_raw['2'],$domain_matches_raw['3'],$domain_matches_raw['4'],$domain_matches_raw['5']),SORT_STRING);
		foreach($domain_matches as $domain){
			if ((trim($domain) != "")&&(check_tld($domain))&&(in_array($domain,$ignore_data_array['domain'])!==true)){
				if (substr($domain,0,4) == "www.")
					$domains[] = array("dataType" => "domain","data" => str_replace("www.","",$domain),"message" => "Domain Observable");
				else	
					$domains[] = array("dataType" => "domain","data" => $domain,"message" => "Domain Observable");
			} else {
				if ($debug > 1)
					file_put_contents($log_file,"-------------------------\nOutput extract => \nDomain: ".$domain." => scartato!\nIgnore array:".print_r($ignore_data_array['domain'],1)."\nRet ignore:".in_array($domain,$ignore_data_array['domain']),FILE_APPEND);
			}
		}
	}


	if(preg_match_all("/([A-Fa-f0-9]{64})/", $obs, $sha256_matches_raw)) {		
		$sha256_matches = array_unique($sha256_matches_raw['1'],SORT_STRING);
		foreach($sha256_matches as $sha256)	{
			if (trim($sha256) != "")
				$hashs[] = array("dataType" => "hash","data" => $sha256,"message" => "HASH256 Observable");
		}
	}
	
	// Todo
	if(preg_match_all('/(https:\/\/[a-zA-Z0-9.-]+\/?[^<>\s\"]+)|(hxxps:\/\/[a-zA-Z0-9.-]+\/?[^<>\s\"]+)|(hxxp:\/\/[a-zA-Z0-9.-]+\/?[^<>\s\"]+)|(http:\/\/[a-zA-Z0-9.-]+\/?[^<>\s\"]+)|(www.[a-zA-Z0-9.-]+\/?[^<>\s\"]+)/', $obs, $url_matches_raw)) {
		$url_matches = array_unique($url_matches_raw['1'],SORT_STRING);
		foreach($url_matches as $url){
			if ((in_array($url,$ignore_data_array['url'])!==true)||(!is_array($ignore_data_array['url'])))
				$urls[] = array("dataType" => "url","data" => $url,"message" => "Url Observable");
		}
	}

	if(preg_match_all('/([_a-z0-9-.]+@[_a-z0-9-]+\.[a-z]{2,3})[<>;":\s]|([_a-z0-9-.]+@[_a-z0-9-]+\.[_a-z0-9-]+\.[a-z]{2,3})[<>;"\s:]|([_a-z0-9-.]+@[_a-z0-9-]+\[\.\][a-z]{2,3})[<>;":\s]/', $obs, $email_matches_raw)) {
		//print_r($email_matches_raw);
		//die();
		$email_matches = array_unique($email_matches_raw['1'],SORT_STRING);
		foreach($email_matches as $email){
			if ((trim($email) != "")&&(!in_array($email,$ignore_data_array['mail'])))
			 $emails[] = array("dataType" => "mail","data" => $email,"message" => "Email Observable");
		 }
	} 

	//return $ips;
	return array_merge($ips,$domains,$emails,$hashs,$urls);
	//print_r($ips);
	//print_r($emails);
}

function check_tld($url) {
	global $debug;
	global $log_file;

  $parsed_url = parse_url($url);
  if ($debug > 1)
	file_put_contents($log_file,"-------------------------\nOutput checktld => \nURL: ".$url." parsing: ".print_r($parsed_url,1),FILE_APPEND);
	
  if ( $parsed_url === FALSE ) return false;
  $ret_preg = preg_match('/\.(aero|asia|biz|cat|com|coop|info|int|jobs|mobi|museum|name|net|org|post|pro|tel|travel|mlcee|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|bq|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw)$/i', $parsed_url['path']);
  if ($debug > 1)
        file_put_contents($log_file,"-------------------------\nOutput checktld => \nURL: ".$url." parsing: ".print_r($parsed_url,1)." out: ".print_r($ret_preg,1),FILE_APPEND);

  return $ret_preg;
}

function attachToCase($caseId,$caseData){
	global $url;
	//$url = "https://thehive.backloop.biz/api/case/".$caseId."/artifact";
	$data = array(			
		"attachment" => array("filename" => $caseData['attach_filename'], "contents" => $caseData['attach_content']),			
	);

	$postdata = json_encode($data);
	//if ($debug)
	//	print_r($postdata);

	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: data","Authorization: Bearer EBCo0T3sHs62787PiTPCMf3v/0lsOVx+"));
	$result = curl_exec($ch);
	$curl_error = curl_error($ch);
	curl_close($ch);
	
	$out['result'] = $result;
	$out['error'] = $curl_error;
	
	return $out;

}
	
function shareCase($caseId){
	
	global $authkey;
	global $base_url;
	
	// {"shares":[{"organisationName":"Backloop","profile":"org-admin","tasks":"all","observables":"all"}]}
	$url = $base_url."/api/case/".$caseId."/shares";
	$data = array("shares" => array("0" => array(
		"organisationName" => "Backloop",
		"profile" => "org-admin",
		"tasks"=> "all",
		"observables" => "all"	,
	)));
	
	//print_r($data);

	$postdata = json_encode($data);
	if ($debug)
		print_r($postdata);

	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json","Authorization: Bearer ".$authkey));
	$result = curl_exec($ch);
	$curl_error = curl_error($ch);
	curl_close($ch);
	
	$out['result'] = $result;
	$out['error'] = $curl_error;
	
	echo print_r($out);
	return $out;

}
	
	
function updateCase($caseId, $data){
	
	global $authkey;
	global $base_url;
	
	// {"shares":[{"organisationName":"Backloop","profile":"org-admin","tasks":"all","observables":"all"}]}
	$url = $base_url."/api/case/".$caseId;
		
	//print_r($data);

	$postdata = json_encode($data);
	if ($debug)
		print_r($postdata);

	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	//curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
	curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json","Authorization: Bearer ".$authkey));
	$result = curl_exec($ch);
	$curl_error = curl_error($ch);
	curl_close($ch);
	
	$out['result'] = $result;
	$out['error'] = $curl_error;
	
	return $out;

}
	
function getCase($caseId){

global $authkey;
global $base_url;

// {"shares":[{"organisationName":"Backloop","profile":"org-admin","tasks":"all","observables":"all"}]}
$url = $base_url."/api/case/".$caseId;
	
//print_r($data);

//$postdata = json_encode($data);
//if ($debug)
//	print_r($postdata);

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
//curl_setopt($ch, CURLOPT_POST, 1);
//curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
//curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_HTTPHEADER, array("Authorization: Bearer ".$authkey));
$result = curl_exec($ch);
$curl_error = curl_error($ch);
curl_close($ch);

$out['result'] = $result;
$out['error'] = $curl_error;

return $out;

}

function obsToCase($caseId,$obs){

global $authkey;
global $base_url;

if ($obs['dataType'] != "files"){
	$url = $base_url."/api/case/".$caseId."/artifact";
	$data = array(
		"data" => $obs['data'],
		"dataType" => $obs['dataType'],
		"message"=> $obs['message'],
		"tlp" => 0,
		"ioc" => true,
	);
	
	//print_r($data);

	$postdata = json_encode($data);
	if ($debug)
		print_r($postdata);

	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json","Authorization: Bearer ".$authkey));
	$result = curl_exec($ch);
	$curl_error = curl_error($ch);
	curl_close($ch);
	
	$out['result'] = $result;
	$out['error'] = $curl_error;
} else {
	$url = $base_url."/api/case/".$caseId."/artifact";
	$data = array(
		//"data" => $obs['data'],
		"dataType" => $obs['dataType'],
		"message"=> $obs['message'],
		"tlp" => 0,
		"ioc" => true,
	);

//print_r($data);

$postdata = $obs['data'];
if ($debug)
	print_r($postdata);

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: multipart/form-data","Content-Length: " . strlen($obs['data']),"Authorization: Bearer ".$authkey));
$result = curl_exec($ch);
$curl_error = curl_error($ch);
curl_close($ch);

$out['result'] = $result;
$out['error'] = $_curl_error;	
}
return $out;

}

function searchCase($query){
		
global $debug;
		global $authkey;
		global $base_url;
		$url = $base_url."/api/case/_search";
		$data = array(
			"query" => array("tags" => $query['tags']),
			//"query" => array("In" => array("tags" => "message_id:".$query['tags']['1'])),
			"range" => "all"
		);
//if ($debug)                
		//	echo print_r($data);

		$postdata = json_encode($data); 
		//print_r($postdata);

$ch = curl_init($url);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json","Authorization: Bearer ".$authkey));
		$result = curl_exec($ch);
		$curl_error = curl_error($ch);
		curl_close($ch);
		
		$out['result'] = $result;
		$out['error'] = $curl_error;
						
		return $out;

}

function createCase($caseData){
	
	global $authkey;
	global $base_url;
	global $customer;
	global $debug;
	
	$url = $base_url."/api/case";
	
	/*
	if ($caseData['dynpart'] != ""){
		$tags = array("message_id:".$caseData['messageId'], "dynpart:".$caseData['dynpart']);
	} else {	
		$tags = array("message_id:".$caseData['messageId']);
		if (is_array($caseData['template_tag'])){
			foreach($caseData['template_tag'] as $ttag){
				$tags[] = $ttag;
			}
		}
	}
	*/
	
	$tags = array("message_id:".$caseData['messageId']);
	if ($caseData['dynpart'] != ""){
		$tags[] = $caseData['dynpart'];
	}
	if (is_array($caseData['template_tag'])){
		foreach($caseData['template_tag'] as $ttag){
			$tags[] = $ttag;
		}
	}
		
	$data = array(
		"title" => $caseData['title'],
		"description" => $caseData['description'],
		"type"=>"external",
		"status" => $caseData['status'],
		"source" => "mail",
		"sourceRef" => date("d-m-Y H:i:s"),
		//"caseTemplate" => $caseData['template'],
		"template" => $caseData['template'],
		"customFields" => array("template" => $caseData['template'],"customer" => $customer, "mail-from" => $caseData['mail_from']),
		//"attachment" => array("filename" => $caseData['attach_filename'], "contents" => $caseData['attach_filename'].";message/rfc822;".$caseData['attach_content']),
		//"tags" => array("customer:".$customer, "message_id:".$caseData['messageId'], "user_email:".$caseData['mail_from']),
		"tags" => $tags,
		//"artifacts" => array(
		//	array(
		//		"dataType" => "file", 
		//		"data" => $caseData['attach_filename'].";message/rfc822;".$caseData['attach_content'],
		//		"message" => "Username from alert"
		//	),
		//),
		//"artifacts" => $caseData['artifacts'],
		
		//"artifacts" => $total_obs
	);
	
	//print_r($data);

	$postdata = json_encode($data);
	if ($debug > 1)
		echo print_r($data,1);

	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json","Authorization: Bearer ".$authkey));
	$result = curl_exec($ch);
	$curl_error = curl_error($ch);
	curl_close($ch);
	
	$out['result'] = $result;
	$out['error'] = $curl_error;
			
	return $out;

}

function main($mailfields){
	
	global $debug;
	global $converter;
	global $log_file;
	// MAIN

	$caseData['title'] = $mailfields['subject'];
	$markdown = "";
	if ($mailfields['body'] != "")
		$markdown = $converter->convert($mailfields['body']);
	$caseData['description'] = "User: ".$mailfields['from']." wrote:\n".$markdown;
	$caseData['raw_body'] = $mailfields['body'];
	$caseData['raw_content'] = $mailfields['raw_content'];
	if ($debug > 1)
		file_put_contents($log_file,"-------------------------\nOutput extract => \nSubj: ".$caseData['title']." raw:".strlen($caseData['raw_body'])." body:".strlen($caseData['description']),FILE_APPEND);
	//$obs_array = extractObs(str_replace(array("[.]"),array("."),$caseData['raw_body']));	
	$obs_array = extractObs(str_replace(array("[.]"),array("."),$caseData['raw_content']));		
	$caseData['messageId'] = $mailfields['message_id'];
	if ($mailfields['references'] != "")
		$caseData['references'] = explode(" ",$mailfields['references']);
	else
		$caseData['references'] = "";
	$query = array();
	$case_id = 0;
	$template_data_dyn = checkTemplate($caseData['title'],$caseData['raw_content']);
	echo print_r($template_data_dyn,1);
	//print_r($caseData['references']);
	$query['tags'] = "message_id:".$caseData['messageId'];
		$res_search = searchCase($query);
		$res_search_json = json_decode($res_search['result']);
		if (is_numeric($res_search_json['0']->caseId)){
			$case_id = $res_search_json['0']->caseId;
			echo "Trovato case_id: ".$case_id." esco";
			if ($debug > 1)
				file_put_contents($log_file,"-------------------------\nOutput case: \nSubj: ".$caseData['title']." => Trovato case_id: ".$case_id." esco",FILE_APPEND);
			exit();
		}
			
	if ($template_data_dyn['dynparts']['dynpart'] != ""){
		$query['tags'] = "dynpart:".$template_data_dyn['dynparts']['dynpart'];
		$res_search = searchCase($query);
		$res_search_json = json_decode($res_search['result']);
		if (is_numeric($res_search_json['0']->caseId)){
				$case_id = $res_search_json['0']->caseId;
				echo "Trovato case_id: ".$case_id." con dynpart: ".$template_data_dyn['dynparts']['dynpart'];
				if ($debug > 1)
						file_put_contents($log_file,"-------------------------\nOutput case: \nSubj: ".$caseData['title']." => Trovato case_id: ".$case_id,FILE_APPEND);
				$orig_case = getCase($case_id);
				$orig_case_data = json_decode($orig_case['result']);
				if ($debug)
						file_put_contents($log_file,"-------------------------\nOutput case: \nSubj: ".$caseData['title']." Ref: ".$reference." => Trovato reference case_id: ".$case_id."\n",FILE_APPEND);
				$new_tags = $orig_case_data->tags;
				$new_tags[] = "message_id:".$caseData['messageId'];
				$new_data = array("description" => $caseData['description']."\n--------------------\n".$orig_case_data->description,"tags" => $new_tags);
				//if ($debug)
				//      file_put_contents($log_file,"-------------------------\nOutput new data for case: \nSubj: ".$caseData['title']." => ".print_r($new_data,1)."\n",FILE_APPEND);
				$res_update = updateCase($case_id,$new_data);
				if ($res_update['error'] != ""){
						echo $res_update['error'];
						if ($debug)
							 file_put_contents($log_file,"-------------------------\nOutput updateCase ".$case_id.": \n\n".print_r($res_update,1)."\n INPUT DATA\n".print_r($new_data),FILE_APPEND);
						die();
				}
		} else {
			echo "Non trovo ".$template_data_dyn['dynparts']['dynpart']." nei case";	
		}
	}

	foreach($caseData['references'] as $reference){
		$query = array();
		$query['tags'] = "message_id:".$reference;
		$res_search = searchCase($query);
		$res_search_json = json_decode($res_search['result']);
		if ((is_array($res_search_json))&&(is_numeric($res_search_json['0']->caseId))){
			$case_id = $res_search_json['0']->caseId;
			echo "Trovato case_id: ".$case_id." nei references";
			$orig_case = getCase($case_id);
			$orig_case_data = json_decode($orig_case['result']);
			if ($debug)
				file_put_contents($log_file,"-------------------------\nOutput case: \nSubj: ".$caseData['title']." Ref: ".$reference." => Trovato reference case_id: ".$case_id."\n",FILE_APPEND);
			$new_tags = $orig_case_data->tags;
			$new_tags[] = "message_id:".$caseData['messageId'];
			$new_data = array("description" => $caseData['description']."\n--------------------\n".$orig_case_data->description,"tags" => $new_tags);
			//if ($debug)
			//	file_put_contents($log_file,"-------------------------\nOutput new data for case: \nSubj: ".$caseData['title']." => ".print_r($new_data,1)."\n",FILE_APPEND);
			$res_update = updateCase($case_id,$new_data);
			if ($res_update['error'] != ""){
							echo $res_update['error'];
							if ($debug)
								 file_put_contents($log_file,"-------------------------\nOutput updateCase ".$case_id.": \n\n".print_r($res_update,1)."\n INPUT DATA\n".print_r($new_data),FILE_APPEND);
							die();
					}
			
		}
		//print_r($res_search_json);
		//echo "Case ID: ".$case_id;
	}


	// sistemi casi con "Enrico <my@email.com>"
	if (preg_match_all("/\\<(.*?)\\>/", $mailfields['from'], $matches))
		$caseData['mail_from'] = $matches[1][0];
	else       
		$caseData['mail_from'] = $mailfields['from'];
		
		
	//$caseData['attach_content'] = $mail['attachment'][0]['Content'];
	//$caseData['attach_name'] = $mail['attachment'][0]['AttachName'];
	//$caseData['attach_filename'] = $mail['attachment'][0]['AttachFilename'];
	$caseData['artifacts'] = $obs_array;
	if ($case_id == 0){
		if ((1==0)&&(in_array($caseData['mail_from'],$ignore_data_array['mail']))){
			if ($debug)
				echo "Ignored mail address (from)";
		} else {
			$template_data = checkTemplate($caseData['title'],$caseData['raw_content'],$caseData['mail_from']);
			//if ($debug)
			//	file_put_contents($log_file,"-------------------------\nOutput templateData: \n\n".print_r($template_data,1),FILE_APPEND);
						
			$caseData['template'] = $template_data['template'];
			$caseData['template_tag'] = $template_data['tags'];
			if ($template_data['dynparts']['dynpart'] != "")
				$caseData['dynpart'] = "dynpart:".$template_data['dynparts']['dynpart'];
			else	
				$caseData['dynpart'] = "";
				
			if ($template_data['ignore'] != 1){
			echo "Nuovo case";	
			$res_raw = createCase($caseData);
			if ($res_raw['error'] != ""){
				echo "Error: ".$res_raw['error'];
				if ($debug)
							 file_put_contents($log_file,"-------------------------\nOutput createCase: \n\n".print_r($res_raw,1)."\n INPUT DATA\n".print_r($caseData),FILE_APPEND);
				die();
			} else {
				$res_json = json_decode($res_raw['result'],true);
				if ($debug)
					file_put_contents($log_file,"-------------------------\nOutput createCase: \n\n".print_r($res_raw,1),FILE_APPEND);
				sleep(1);
				//$res_share = shareCase($res_json['caseId']);
			}
			$rand = generateRandomString();
			mkdir("mail/".$rand);
			$ret_write = file_put_contents("mail/".$rand."/".$rand.".raw",$mailfields['raw_content']);
			exec("python3 emlparser.py -p mail/".$rand."/ -o mail/".$rand."/",$ret_cmd,$ret_cmd_val);
			if ($debug)
				file_put_contents($log_file,"-------------------------\nOutput parsing: \n\n".print_r($ret_cmd,1)."Ret val: ".$ret_cmd_val." Ret write:".$ret_write,FILE_APPEND);
			
				
			//echo print_r($res_json,1);
			//print_r($res_json);
			//echo "ID: ".$res_json['caseId'];
			//$out2 = attachToCase($res_json['caseId'],$caseData);
			//print_r($res_raw);
			$mail_attach = "";
			for($i=1;$i<count($ret_cmd);$i++){
				//Todo check mimetypes
				if (($ret_cmd[$i] != "")&&((substr($ret_cmd[$i],-4)==".eml")||($ret_cmd[$i] == "part-000"))&&($res_json['caseId'] != "")){
					$ret_cmd_attach = array();
					sleep(1);
					echo "RFC822 Attach found: ".$ret_cmd[$i];
					$mail_attach = $ret_cmd[$i];
					$cmd_attach = "sudo python3 attach_file.py ".$res_json['caseId']." \"mail/".$rand."/".$ret_cmd[$i]."\" CaseAttachment";
					exec($cmd_attach,$ret_cmd_attach,$ret_cmd_val_attach);
					if ($debug)
						file_put_contents($log_file,"-------------------------\nOutput attachment: \n\n".$cmd_attach."\n".print_r($ret_cmd_attach,1)."Ret val: ".$ret_cmd_val_attach,FILE_APPEND);	
				} else {
					file_put_contents($log_file,"|".substr($ret_cmd[$i],-4)."|".$ret_cmd[$i],FILE_APPEND);
				}
			}
			// extract SPF from artifact
			if (($mail_attach != "")&&(file_exists("mail/".$rand."/".$mail_attach))){
			$spf_tag = array();
			$artifact_raw = file_get_contents("mail/".$rand."/".$mail_attach);
			//echo print_r($res_json,1);
			if (preg_match_all("/Received-SPF:\s([A-Za-z0-9]+)\s/",$artifact_raw,$extract_results)){
				//echo print_r($extract_results,1);
				//$spf_tag[] = end($extract_results['0']);
				$new_tags = $res_json['tags'];
				$new_tags[] = end($extract_results['0']);
				$res_update = updateCase($res_json['caseId'],array("tags" => $new_tags));
						 if ($res_update['error'] != ""){
							 echo $res_update['error'];
								if ($debug)
									 file_put_contents($log_file,"-------------------------\nOutput updateCase ".$case_id.": \n\n".print_r($res_update,1)."\n INPUT DATA\n".print_r($new_data),FILE_APPEND);
								 die();
						}	
				if ($debug)
								file_put_contents($log_file,"-------------------------\nOutput extract:\n".print_r($extract_results,1),FILE_APPEND);
			}
			} else {
				echo "File: "."mail/".$rand."/".$mail_attach." non esiste!";
			}
			// add sender as OBS
			$res_obs = obsToCase($res_json['caseId'],array("data" => $caseData['mail_from'],"dataType" => "mail", "message"=> "sender mail"));

			foreach($obs_array as $obs){
				$res_obs = obsToCase($res_json['caseId'],$obs);
				//print_r($res_obs);
				usleep(1000);						
			}
			//$res_share = shareCase($res_json['caseId']);
			//print_r($res_share);
			// test file upload
			// "$fileName;$contentType;$b64File"
			//$attach_obs = array(
			//	"dataType" => "file", 
			//	"data" => $caseData['attach_name'].";message/rfc822;".base64_encode(file_get_contents($caseData['attach_filename'])),
			//	"message" => "Username from alert",
			//	//"filename" => $caseData['attach_name'],
			//);
			//$res_obs = obsToCase($res_json['caseId'],$attach_obs);
			//print_r($res_obs);
			if ($caseData['attach_filename'] != "")
				system("python3 attach_file.py ".$res_json['caseId']." ".$caseData['attach_filename']." CaseAttachment");
				//echo httpPostDataFile("http://voip.backloop.biz:9000/api/case/".$res_json['caseId']."/artifact", $attach_obs, array($caseData['attach_filename']));
				
			if ($template_data['start_closed'] == 1){
				$ret_update = updateCase($res_json['caseId'], array("status" => "Resolved","resolutionStatus" => "TruePositive", "impactStatus" => "NoImpact", "summary" => "auto close"));
				if ($debug){
					file_put_contents($log_file,"-------------------------\nOutput updateCase: \n\n".print_r($ret_update,1),FILE_APPEND);
					//print_r($ret_update);
				}
				
			}
			$res_share = shareCase($res_json['caseId']);
				}	
		}
	} else {
		//case_id found UPDATE CASE TODO
	}



	
}


function checkMail($imap_url,$username,$password){
	$mailbox = new Mailbox($imap_url, $username, $password);
	//$mailbox->getAttachmentsIgnore = true;
    try {
        $mail_ids = $mailbox->searchMailbox('UNSEEN',true);
    } catch (ConnectionException $ex) {
        die('IMAP connection failed: '.$ex->getMessage());
    } catch (Exception $ex) {
        die('An error occured: '.$ex->getMessage());
    }

	$maildata = array();
	$i=0;
    foreach ($mail_ids as $mail_id) {
        echo "+------ P A R S I N G ------+\n";

        $email = $mailbox->getMail(
            $mail_id, // ID of the email, you want to get
            false // Do NOT mark emails as seen (optional)
        );
		//print_r($email);
		//die();
		$maildata[$i]['fromAddress'] = $email->fromAddress;	
		$maildata[$i]['fromName'] = $email->fromName;
		$maildata[$i]['to'] = $email->toString;
		$maildata[$i]['subject'] = $email->subject;
		$maildata[$i]['messageId'] = $email->messageId;
		if ($email->headers->references != "")
			$maildata[$i]['references'] = explode(" ",$email->headers->references);
		else	
			$maildata[$i]['references'] = "";
		$maildata[$i]['rawbody'] = $mailbox->getRawMail($mail_id);
		$maildata[$i]['attachment'] = array();
		//die("Ref: ".$maildata[$i]['references']);
		/*
        echo 'from-name: '.(string) (isset($email->fromName) ? $email->fromName : $email->fromAddress)."\n";
        echo 'from-email: '.(string) $email->fromAddress."\n";
        echo 'to: '.(string) $email->toString."\n";
        echo 'subject: '.(string) $email->subject."\n";
        echo 'message_id: '.(string) $email->messageId."\n";
		*/	
		
        echo 'mail has attachments? ';
        if ($email->hasAttachments()) {
            echo "Yes\n";
        } else {
            echo "No\n";
        }

        if (!empty($email->getAttachments())) {
            echo \count($email->getAttachments())." attachements\n";
        }

        // Save attachments one by one
        if (!$mailbox->getAttachmentsIgnore()) {
            $attachments = $email->getAttachments();

			$y=0;
            foreach ($attachments as $attachment) {
                echo '--> Saving '.(string) $attachment->name.'...';

				//print_r($attachment);
                // Set individually filePath for each single attachment
                // In this case, every file will get the current Unix timestamp
                $attachment->setFilePath(__DIR__.'/files/'.\time());

                if ($attachment->saveToDisk()) {
                    echo "OK, saved!\n";
                    //echo $attachment->getContents();
                    $tmp_attach = array("emlOrigin" => $attachment->emlOrigin, "Content" => base64_encode($attachment->getContents()), "FileInfo" => $attachment->fileInfo, "mime" => $attachment->mime, "AttachName" => $attachment->name, "AttachFilename" => __DIR__.'/files/'.\time());
                    $maildata[$i]['attachment'][] = $tmp_attach;
                } else {
                    echo "ERROR, could not save!\n";
                }
                $y++;
            }
        }
	
		//print_r($email);
		//echo $email->textHtml;
		//echo $email->textPlain;
		
        if ($email->textHtml) {
            //echo "Message HTML:\n".$email->textHtml;
            $maildata[$i]['TextHtml'] = $email->textHtml;
            $maildata[$i]['TextPlain'] = $email->textPlain;
        } else {
            //echo "Message Plain:\n".$email->textPlain;
            $maildata[$i]['TextPlain'] = $email->textPlain;
        }
	
        if (!empty($email->autoSubmitted)) {
            // Mark email as "read" / "seen"
            $mailbox->markMailAsRead($mail_id);
            echo "+------ IGNORING: Auto-Reply ------+\n";
        }

        if (!empty($email_content->precedence)) {
            // Mark email as "read" / "seen"
            $mailbox->markMailAsRead($mail_id);
            echo "+------ IGNORING: Non-Delivery Report/Receipt ------+\n";
        }
        $i++;
    }


	//print_r($maildata);

    $mailbox->disconnect();
    
    return $maildata;
}


function httpPostDataFile($url, $post_data = null, $files = null) {
	$boundary = md5(microtime());
	$options = array(
    		// use key 'http' even if you send the request to https://...
		'http' => array(
			'header'  => "Authorization: Bearer EBCo0T3sHs62787PiTPCMf3v/0lsOVx+\r\nContent-Type: multipart/form-data; boundary=" . $boundary . "\r\n",
			'method'  => 'POST',
		),
	);
	if(is_array($post_data)) foreach($post_data as $name => $data) {
		$options['http']['content'] .= '--' . $boundary . '
Content-Disposition: form-data; name="' . $name . '"
' . $data . '
';
	}
	if(is_array($files)) foreach($files as $field => $file) {
		$options['http']['content'] .= '--' . $boundary . '
Content-Disposition: form-data; name="' . $field . '"; filename="' . basename($file['name']) . '"
Content-Type: ' . !isset($file['content_type']) ? 'plain/text' : $file['content_type'] . '
Content-Transfer-Encoding: base64
' . chunk_split(base64_encode(!isset($file['data']) ? file_get_contents($file['file']) : $file['data'])) . '
';
	}
	if(is_array($post_data) && count($post_data) || is_array($files) && count($files)) {
		$options['http']['content'] .= '--' . $boundary . '--
';
	}
	$context = stream_context_create($options);
	return file_get_contents($url, false, $context);
}

function checkTemplate($subject,$body,$from=null){
	
	global $templateSelector;
	
	$ret = array();
	
	foreach($templateSelector as $key=>$template){
		
		$ret['start_closed'] = 0;
		foreach($template as $obskey=>$templateObs){			
			
			if (($obskey == "start_closed") && ($templateObs == "1")){
				$ret['start_closed'] = 1;
				continue;				
			}
		
			if (($obskey == "ignore") && ($templateObs == "1")){
                                $ret['ignore'] = 1;
                                continue;                               
                        }

			if ($templateObs['field'] == "body"){				
				if (strpos($body, $templateObs['value']) !== false){
					$ret['template'] = $key;
					if (is_array($templateObs['dynparts']) === true){
						foreach($templateObs['dynparts'] as $key=>$dynpart){
							if(preg_match_all("/".$dynpart."/", $body, $dynpart_raw)) {   
								if ($key == "dynpart")           
									$ret['dynparts']['dynpart'] = $dynpart_raw['1']['0']; 
								else	          								
									$ret['tags'][] = $key.":".$dynpart_raw['1']['0'];
							}
						}
					}
					if ($templateObs['tag'] != "")
						$ret['tags'][] = $templateObs['tag'];

					if ($templateObs['stopserver'] != "false")
						return $ret;
				}
			} else if ($templateObs['field'] == "subject"){
				//echo "Confronto: ".$subject." con: ".$templateObs['value'];
				if (strpos($subject, $templateObs['value']) !== false){
					$ret['template'] = $key;
					if (is_array($templateObs['dynparts']) === true){
						foreach($templateObs['dynparts'] as $key=>$dynpart){
							if(preg_match_all("/".$dynpart."/", $subject, $dynpart_raw)) {   
								if ($key == "dynpart")           
									$ret['dynparts']['dynpart'] = $dynpart_raw['1']['0']; 
								else	          								
									$ret['tags'][] = $key.":".$dynpart_raw['1']['0'];
							}
						}
					}
					return $ret;
				}
			} else if ($templateObs['field'] == "from"){
				if (($from != null)&&($from == $templateObs['value'])){
					$ret['ignore'] = 1;
					return $ret;
				}
			} 
			
			
		}
		
	}
	
}

?>
