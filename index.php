<?php
require 'vendor/autoload.php';
require 'functions.php';
require 'config.php';


use League\HTMLToMarkdown\HtmlConverter;

$converter = new HtmlConverter(array('strip_tags' => true));

if (file_exists($db_file)){
	$raw_ignore_data = file_get_contents($db_file);
	$ignore_data_array = json_decode($raw_ignore_data,true);

} else {

}



// MAIN

if ($mode == "POST"){
	
	echo "Subject: ".$_POST['subject'];
	//echo "Message type: ".$_POST['message_type'];
	//echo print_r($mail);
	$mailfields['subject'] = $_POST['subject'];
	$markdown = "";
	if ($_POST['body'] != "")
		$markdown = $converter->convert($_POST['body']);
	$mailfields['body'] = "User: ".$_POST['from']." wrote:\n".$markdown;
	$mailfields['raw_content'] = $_POST['body'];
	$mailfields['from'] = $_POST['from'];
	$mailfields['message_id'] = $_POST['message_id'];
	$tmp_type = explode(";",$_POST['message_type']);
	$mailfields['message_type'] = $tmp_type['0'];
	$mailfields['references'] = $_POST['references'];

	//echo print_r($mailfields);
	//die();
	echo main($mailfields);
	
} else if ($mode == "IMAP"){
	echo "Controllo mail";
	$maildata = checkMail($imap_url,$imap_username,$imap_password);

	if (count($maildata) > 0){
		
		foreach($maildata as $mail){
			echo "Subject: ".$mail['subject'];
			//echo print_r($mail);
			$mailfields['subject'] = $mail['subject'];
			$mailfields['body'] = ($mail['TextPlain']==""?$mail['TextHtml']:$mail['TextPlain']);
			$mailfields['from'] = $mail['fromAddress'];
			$mailfields['message_id'] = $mail['messageId'];
			$mailfields['references'] = $mail['references'];
			$mailfields['raw_content'] = $mail['rawbody'];

			//echo print_r($mailfields);
			//die();
			echo main($mailfields);

		}

	}

} else {
	echo "Mode not found!";
}

?>
