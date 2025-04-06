<?php

namespace Reticulum;



class Packet {
    public $AccessCodes;
    public $HeaderType;
	public $ContextFlag;
    public $PropagationType;
    public $DestinationType;
    public $PacketType;
    public $Hops;
    public $TransportID;
    public $DestinationHash;
    public $Context;
    public $Data;

    public function __construct($header1, $hops, $TransportID, $DestinationHash, $context, $data) {
		$this->AccessCodes = ($header1 & 0b10000000) >> 7;  // Assumes the highest bit (8th bit) is for Access Codes
		$this->HeaderType = ($header1 & 0b01000000) >> 6;
		$this->ContextFlag = ($header1 & 0b00100000) >> 5;
		$this->PropagationType = ($header1 & 0b00010000) >> 4;
		$this->DestinationType = ($header1 & 0b00001100) >> 2;
		$this->PacketType = ($header1 & 0b00000011);
        $this->Hops = $hops;
		if($TransportID === null) $TransportID = '';
        $this->TransportID = bin2hex($TransportID);  // Assuming you might want these as hexadecimal strings
        $this->DestinationHash = bin2hex($DestinationHash);
        $this->Context = $context;
        $this->Data = bin2hex($data);    // Convert binary data to hexadecimal for readability
	}

    public static function parse($data) {
		// Ensure the data length is at least the minimum expected size
		if (strlen($data) < 18) {  // Smallest packet length
			throw new Exception("Packet data is too short to be valid.");
		}

		
		$flags = ord(substr($data,0,1));
		$hops = ord(substr($data,1,1));
				
		// Extract the second bit from the first byte to determine the packet format
		$type = ($flags & 0b01000000) >> 6;
		
		$DST_LEN = 16;
		if ($type == 1) {
            $transport_id = substr($data, 2, $DST_LEN);
            $destination_hash = substr($data, $DST_LEN + 2, $DST_LEN);
            $context = ord(substr($data, 2 * $DST_LEN + 2, 1));
            $data = substr($data, 2 * $DST_LEN + 3);
        } else {
            $transport_id = null;
            $destination_hash = substr($data, 2, $DST_LEN);
            $context = ord(substr($data, $DST_LEN + 2, 1));
            $data = substr($data, $DST_LEN + 3);
        }
		
		if (($flags & 0b00000011) == 1) {
			return new PacketAnnounce($flags,$hops,$transport_id,$destination_hash,$context,$data);
		} else {
			return new Packet($flags,$hops,$transport_id,$destination_hash,$context,$data);
		}
    }
	
	public function validate() {
		
		return false;
	}
}

