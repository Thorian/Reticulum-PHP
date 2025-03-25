<?php
require('../Reticulum.php');

$ret = new Reticulum\Reticulum();

$id = new Reticulum\Identity(false);
$id->loadFromFile("identity");


print_r($id);



die();
$ret->connect();
while(true){
	$ret->read();
	sleep(1);
	
}

die();
$ret->process_incoming(file_get_contents(1));
echo "-----------------------------------------------------------------";
$ret->process_incoming(file_get_contents(2));

