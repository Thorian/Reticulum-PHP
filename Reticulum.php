<?php
namespace Reticulum;

require_once('Packet.php');
require_once('Identity.php');




class Reticulum {
	
	const TRUNCATED_HASHLENGTH = 128;
	const MTU = 500;
	const LINK_MTU_DISCOVERY = true;
	const MAX_QUEUED_ANNOUNCES = 16384;
	const QUEUED_ANNOUNCE_LIFE = 60*60*24;
	const MINIMUM_BITRATE = 5;
	const DEFAULT_PER_HOP_TIMEOUT = 6;
	const IFAC_SALT = "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8";
	const HEADER_MINSIZE   = 2+1+(128/8)*1;
    const HEADER_MAXSIZE   = 2+1+(128/8)*2;
    const IFAC_MIN_SIZE    = 1;
	
	private $socket;
	private $buffer;
	
	protected $router;
	
	
	public function connect(string $server='127.0.0.1',int $port=37428) {
		$this->socket = socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
		socket_connect($this->socket,$server,$port);
		socket_set_nonblock($this->socket);
	}
	
	public function read() {
		$dat=socket_read($this->socket,4096);
		if(strlen($dat)==0) return; 
		$this->buffer .= $dat;
		$flags_remaining = true;
		while($flags_remaining) {
			$frame_start = strpos($this->buffer,hex2bin('7E'));
			if ($frame_start === false) return;
			$frame_end = strpos($this->buffer,hex2bin('7E'),$frame_start+1);
			if ($frame_end === false) return;
			$frame = substr($this->buffer,$frame_start+1, $frame_end - $frame_start-1);
			$this->process_incoming($frame);
			$this->buffer = substr($this->buffer,$frame_end+1);
		}
	}
	
	public function process($packet) {
		
	}
	
	public function process_incoming($frame) {
		$packet = Packet::fromData($frame);
		if($packet->packet_type == Packet::ANNOUNCE) {
			echo "ANNOUNCE";
		} 
		echo bin2hex($frame)."\n\r";
		print_r($packet);
	}
	
	
}