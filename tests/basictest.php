<?php
require('../Reticulum.php');

$ret = new Reticulum\Reticulum();

$ret->connect();

$ident = new Reticulum\Identity();

print_r($ident);


while(true) {
	
	$ret->read();
}


