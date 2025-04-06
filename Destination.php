<?php
namespace Reticulum;

class Destination {
	public $appName;
	public $identity;
	public $aspects = array();
	public $type = 0; //Always Destination type SINGLE 0x00 for now
	public $prove = 0x21; //always PROVE_NONE for now
	
	public $hashes = array();
	public $nameHashes = array();
	
	//public $in;  //0x11
	//public $out; //0x12
	
	public function __construct($identity,$name,...$aspects) {
		$this->identity = $identity;
		$this->appName = $name;
		$this->aspects = $aspects;
		$this->hashes = $this->hash();
		$this->nameHashes = $this->nameHashes();
	}
	
	
	public function getNameHashes() {
		return $this->nameHashes;
	}
	public function expandName() {
		$ret = array();
		foreach ($this->aspects as $aspect) {
			$name = $this->appName;
			if(is_array($aspect))
				foreach ($aspect as $aspecti) {
					$name .= "." . $aspecti;
				}
			else
				$name .= "." . $aspect;
			$ret[] = $name;
		}
		return $ret;
	}
	
	public function nameHashes() {
		$ret = array();
		$names = $this->expandName();
		foreach ($names as $name) {
			$ret[$name] = bin2hex(substr(hash("sha256",@utf8_encode($name),true),0,10));
		}
		return $ret;
	}
	
	
	
	public function hash() {
		$ret = array();
		$names = $this->expandName();
		foreach ($names as $name) {
			$nameHash = substr(hash("sha256",@utf8_encode($name),true),0,10);
			$ret[$name] = bin2hex(substr(hash("sha256",$nameHash.hex2bin($this->identity->hash),true),0,128/8));
		}
		return $ret;
	}
		
	public function getDestinationIdentifiers() {
		return $this->hashes;
	}
	
	public function handlePacket($packet) {
		echo "HANDLED! By ".get_class($this)."\n\r";
		print_r($packet);

	}
}

