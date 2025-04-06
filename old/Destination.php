<?php
namespace Reticulum;
class Destination {
    /**
     * A class used to describe endpoints in a Reticulum Network. Destination
     * instances are used both to create outgoing and incoming endpoints. The
     * destination type will decide if encryption, and what type, is used in
     * communication with the endpoint. A destination can also announce its
     * presence on the network, which will distribute necessary keys for
     * encrypted communication with it.
     *
     * @param identity An instance of RNS.Identity. Can hold only public keys for an outgoing destination, or holding private keys for an ingoing.
     * @param direction RNS.Destination.IN or RNS.Destination.OUT.
     * @param type RNS.Destination.SINGLE, RNS.Destination.GROUP or RNS.Destination.PLAIN.
     * @param app_name A string specifying the app name.
     * @param aspects Any non-zero number of string arguments.
     */

    const SINGLE = 0x00;
    const GROUP = 0x01;
    const PLAIN = 0x02;
    const LINK = 0x03;
    public static $types = [self::SINGLE, self::GROUP, self::PLAIN, self::LINK];

    const PROVE_NONE = 0x21;
    const PROVE_APP = 0x22;
    const PROVE_ALL = 0x23;
    public static $proof_strategies = [self::PROVE_NONE, self::PROVE_APP, self::PROVE_ALL];

    const ALLOW_NONE = 0x00;
    const ALLOW_ALL = 0x01;
    const ALLOW_LIST = 0x02;
    public static $request_policies = [self::ALLOW_NONE, self::ALLOW_ALL, self::ALLOW_LIST];

    const IN = 0x11;
    const OUT = 0x12;
    public static $directions = [self::IN, self::OUT];

    const PR_TAG_WINDOW = 30;

    const RATCHET_COUNT = 512;
    /**
     * The default number of generated ratchet keys a destination will retain, if it has ratchets enabled.
     */

    const RATCHET_INTERVAL = 30*60;
    /**
     * The minimum interval between rotating ratchet keys, in seconds.
     */

    // Properties
    private $identity;
    private $direction;
    private $type;
    private $appName;
    private $aspects;
	private $callbacks = array();
	private $nameHash;
	
	public $appData;
	
	public function __construct($identity, $direction, $type, $appName, ...$aspects) {
        $this->identity = $identity;
        $this->direction = $direction;
        $this->type = $type;
        $this->appName = $appName;
        $this->aspects = $aspects;
		$name = $this->expandName(null, $appName, ...$aspects);
        $fullHash = hash('sha256', $name, true); // Using true to get raw binary data
        $this->nameHash = substr($fullHash, 0, Identity::NAME_HASH_LENGTH / 8);
    }

	public function hash() {
		/**
		 * Returns a destination name in addressable hash form, for an app name and a number of aspects.
		 */
		$name = expandName(null, $this->appName, $this->aspects);
		$nameHash = substr(hash('sha256', $name, true), 0, Identity::NAME_HASH_LENGTH / 8);
		$addrHashMaterial = $nameHash;
		$addrHashMaterial .= $identity->getHash(); // Assuming the Identity object has a getHash() method
		return substr(hash('sha256', $addrHashMaterial, true), 0, Reticulum::TRUNCATED_HASHLENGTH / 8);
	}
	
	public function announce() {
		$dest = $this->hash();
		//ratchets go here but we ignore them for now
		$ratchet="";
		
		$randomHash = RNS::getRandomHash();
		$timeBytes = pack('J', time()); // 'J' is for unsigned 64-bit big endian
		$timeBytes = substr($timeBytes, -5); // Get the last 5 bytes

		$randomHash .= $timeBytes;
		
		$data = $dest.$this->identity->getPublicKey().$this->nameHash.$randomHash.$ratchet;
		
	}
	
	public function register_delivery_callback(MessageReceiver $call) {
		$this->callbacks[] = $call;
	}
	
	function expandName($identity, $appName, ...$aspects) {
		/**
		 * Returns a string containing the full human-readable name of the destination,
		 * for an app_name and a number of aspects.
		 */

		// Check input values and build name string
		if (strpos($appName, '.') !== false) {
			throw new Exception("Dots can't be used in app names");
		}

		$name = $appName;
		foreach ($aspects as $aspect) {
			if (strpos($aspect, '.') !== false) {
				throw new Exception("Dots can't be used in aspects");
			}
			$name .= "." . $aspect;
		}

		if ($identity !== null) {
			$name .= "." . $identity->getHexHash(); // Assuming the identity object has a method getHexHash()
		}

		return $name;
	}
	
	function enable_ratchets() {
		
		
	}
	
}