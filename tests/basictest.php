<?php
require('../Reticulum.php');

$ret = new Reticulum\Reticulum();

$ret->connect();

while(true) {
	
	$ret->read();
}


