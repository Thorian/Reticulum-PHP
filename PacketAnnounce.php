<?php
namespace Reticulum;

class PacketAnnounce extends Packet {
	
	public $publicKey;
	public $nameHash;
	public $randomHash;
	public $ratchet;
	public $signature;
	public $appData;
	public $announcedIdentity;
	
	public function __construct($header1, $header2, $hash1, $hash2, $context, $data) {
		parent:: __construct($header1, $header2, $hash1, $hash2, $context, $data);
		$keySize = 64;
		$ratchetSize = 32;
		$nameHashLen = 10;
		$sigLen       = 64;
		$randomHashLen = 10;
		$dataBinary   = hex2bin($this->Data);

		$offset = 0;

		$this->publicKey = bin2hex(substr($dataBinary, $offset, $keySize));
		$offset += $keySize;

		$this->nameHash = bin2hex(substr($dataBinary, $offset, $nameHashLen));
		$offset += $nameHashLen;

		$this->randomHash = bin2hex(substr($dataBinary, $offset, $randomHashLen));
		$offset += $randomHashLen;

		if ($this->ContextFlag) {
			$this->ratchet = bin2hex(substr($dataBinary, $offset, $ratchetSize));
			//echo strlen($this->ratchet)."NARF";
			$offset += $ratchetSize;
		} else {
			$this->ratchet = '';
		}

		$this->signature = bin2hex(substr($dataBinary, $offset, $sigLen));
		$offset += $sigLen;

		$this->appData = '';
		if ($offset < strlen($dataBinary)) {
			$this->appData = substr($dataBinary, $offset);
		}
		
				
		
		$this->announcedIdentity = new Identity(false);
		$this->announcedIdentity->loadPublicKey(hex2bin($this->publicKey));
//		$this->announcedIdentity->appData = $this->appData;
//		print_r($this);
		
	//	$lx = new LXMF($this->announcedIdentity);
		//print_r($lx->hash());
	}
	
	public function validate() {
		$signedData = hex2bin($this->DestinationHash).hex2bin($this->publicKey). hex2bin($this->nameHash) . hex2bin($this->randomHash) . hex2bin($this->ratchet) . $this->appData;
		if ($this->announcedIdentity->pub !== null && $this->announcedIdentity->validate(hex2bin($this->signature), $signedData)) {
			return true;
		}
		return false;
	}
	
	
	
}