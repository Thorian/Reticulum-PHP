<?php
require('../Reticulum.php');

$ret = new Reticulum\Reticulum();

$id = new Reticulum\Identity(false);
$id->loadFromFile("identity.theo");
print_r($id);

$ret->connect();


while(true){
	$ret->read();
	sleep(1);
	
}

die();
$ret->process_incoming(file_get_contents(1));
echo "-----------------------------------------------------------------";
$ret->process_incoming(file_get_contents(2));

print_r($id);
$ret->process_incoming(file_get_contents(16));
die();
