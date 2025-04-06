<?php

require_once('../Reticulum.php');


$id = new Reticulum\Identity(false);
$id->loadFromFile("identity.theo");



$tcpInterface = new \Reticulum\ReticulumInterfaceTCPLocal(); // Uses default host and port
$reticulum = new \Reticulum\Reticulum();
$reticulum->addInterface($tcpInterface);
$lxmf = new \Reticulum\LXMF($id,"LXMFBot");
$reticulum->registerDestination($lxmf);
$nomad = new \Reticulum\Nomadnet($id,"NomadServer");
$reticulum->registerDestination($nomad);



while (true) {
	$reticulum->processIncomingData();
	sleep(1); 
}