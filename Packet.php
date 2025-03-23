<?php
namespace Reticulum;

class Packet {
	
	// Packet types
    const DATA = 0x00; // Data packets
    const ANNOUNCE = 0x01; // Announces
    const LINKREQUEST = 0x02; // Link requests
    const PROOF = 0x03; // Proofs
    public static $types = [self::DATA, self::ANNOUNCE, self::LINKREQUEST, self::PROOF];

    // Header types
    const HEADER_1 = 0x00; // Normal header format
    const HEADER_2 = 0x01; // Header format used for packets in transport
    public static $header_types = [self::HEADER_1, self::HEADER_2];

    // Packet context types
    const NONE = 0x00; // Generic data packet
    const RESOURCE = 0x01; // Packet is part of a resource
    const RESOURCE_ADV = 0x02; // Packet is a resource advertisement
    const RESOURCE_REQ = 0x03; // Packet is a resource part request
    // Add all other context types here, abbreviated for brevity
    const KEEPALIVE = 0xFA; // Packet is a keepalive packet
    const LINKIDENTIFY = 0xFB; // Packet is a link peer identification proof
    const LINKCLOSE = 0xFC; // Packet is a link close message
    const LINKPROOF = 0xFD; // Packet is a link packet proof
    const LRRTT = 0xFE; // Packet is a link request round-trip time measurement
    const LRPROOF = 0xFF; // Packet is a link request proof

    // Context flag values
    const FLAG_SET = 0x01;
    const FLAG_UNSET = 0x00;
	
	protected $flags;
	protected $hops = 0;
	protected $header_type;
	public $context_flag;
	protected $context;
	protected $transport_type;
	protected $transport_id;
	protected $destination_type;
	public $destination_hash;
	public $packet_type;
	protected $packed;
	public $data;
	
	public function __construct() {
		
	}
	
	public static function fromData($data) {
		$pack = new static();
		$pack->flags = ord(substr($data,0,1));
		$pack->hops = ord(substr($data,1,1));
		
		$pack->header_type = ($pack->flags & 0b01000000) >> 6;
        $pack->context_flag = ($pack->flags & 0b00100000) >> 5;
        $pack->transport_type = ($pack->flags & 0b00010000) >> 4;
        $pack->destination_type = ($pack->flags & 0b00001100) >> 2;
        $pack->packet_type = ($pack->flags & 0b00000011);
		
		$DST_LEN = intdiv(Reticulum::TRUNCATED_HASHLENGTH,8);
		if ($pack->header_type == Packet::HEADER_2) {
            $pack->transport_id = substr($data, 2, $DST_LEN);
            $pack->destination_hash = substr($data, $DST_LEN + 2, $DST_LEN);
            $pack->context = ord(substr($data, 2 * $DST_LEN + 2, 1));
            $pack->data = substr($data, 2 * $DST_LEN + 3);
        } else {
            $pack->transport_id = null;
            $pack->destination_hash = substr($data, 2, $DST_LEN);
            $pack->context = ord(substr($data, $DST_LEN + 2, 1));
            $pack->data = substr($data, $DST_LEN + 3);
        }
		
		
		
		return $pack;
	}
}