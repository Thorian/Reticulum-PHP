<?php
namespace Reticulum;

use MikeRow\Salt\NanoSalt;
use MikeRow\Salt\Blake2b\Blake2b;


class Identity
{
    private const CURVE = "Curve25519";
    private const KEYSIZE = 512;
    private const RATCHETSIZE = 256;
    private const RATCHET_EXPIRY = 2592000; // 30 days

    private const TOKEN_OVERHEAD = 16; // Assuming placeholder
    private const AES128_BLOCKSIZE = 16;
    private const HASHLENGTH = 256;
    private const SIGLENGTH = 512;

    private const NAME_HASH_LENGTH = 80;
    private const TRUNCATED_HASHLENGTH = 128; // Placeholder for truncated hash length

    private static $known_destinations = [];
    private static $known_ratchets = [];

    private $prv;
    private $pub;
    private $sigPrv;
    public $sigPub;
    public $hash;
    private $appData;
	
	public static function validateAnnounce($packet, $onlyValidateSignature = false) {
		try {
			if ($packet->packet_type == Packet::ANNOUNCE) {
				$keysize = Identity::KEYSIZE / 8;
				$ratchetsize = Identity::RATCHETSIZE / 8;
				$nameHashLen = Identity::NAME_HASH_LENGTH / 8;
				$sigLen = Identity::SIGLENGTH / 8;
				$destinationHash = $packet->destination_hash;
				
				$publicKey = substr($packet->data, 0, $keysize);
				
				if ($packet->context_flag) {
					$nameHash = substr($packet->data, $keysize, $nameHashLen);
					$randomHash = substr($packet->data, $keysize + $nameHashLen, 10);
					$ratchet = substr($packet->data, $keysize + $nameHashLen + 10, $ratchetsize);
					$signature = substr($packet->data, $keysize + $nameHashLen + 10 + $ratchetsize, $sigLen);
					$appData = "";
					if (strlen($packet->data) > $keysize + $nameHashLen + 10 + $sigLen + $ratchetsize) {
						$appData = substr($packet->data, $keysize + $nameHashLen + 10 + $sigLen + $ratchetsize);
					}
				} else {
					$ratchet = "";
					$nameHash = substr($packet->data, $keysize, $nameHashLen);
					$randomHash = substr($packet->data, $keysize + $nameHashLen, 10);
					$signature = substr($packet->data, $keysize + $nameHashLen + 10, $sigLen);
					$appData = "";
					if (strlen($packet->data) > $keysize + $nameHashLen + 10 + $sigLen) {
						$appData = substr($packet->data, $keysize + $nameHashLen + 10 + $sigLen);
					}
				}

				$signedData = $destinationHash . $publicKey . $nameHash . $randomHash . $ratchet . $appData;
				
				$announcedIdentity = new Identity(false);
				$announcedIdentity->loadPublicKey($publicKey);
				
				if ($announcedIdentity->pub !== null && $announcedIdentity->validate($signature, $signedData)) {
					if ($onlyValidateSignature) {
						unset($announcedIdentity);
						return true;
					}
					
					$hashMaterial = $nameHash . hex2bin($announcedIdentity->hash); // Assuming this is a method to get a hash
					$expectedHash = substr(hex2bin(hash("sha256", $hashMaterial)), 0, Identity::TRUNCATED_HASHLENGTH / 8);

					if ($destinationHash == $expectedHash) {
						echo ("This worked!!!!!!!!!!!");
						// Implement logic as needed, e.g., checking known destinations, logging, etc.
						return true;
					} else {
						echo ("Received invalid announce for ".$destinationHash.": Destination mismatch.");
						return false;
					}
				} else {
					//RNS::log("Received invalid announce for " . RNS::prettyhexrep($destinationHash) . ": Invalid signature.", RNS::LOG_DEBUG);
					unset($announcedIdentity);
					return false;
				}
			} else {
				return false;
			}
		} catch (Exception $e) {
			RNS::log("Error occurred while validating announce. The contained exception was: " . $e->getMessage(), RNS::LOG_ERROR);
			return false;
		}
	}

    public function __construct($createKeys = true)
    {
        if ($createKeys) {
            $this->createKeys();
        }
    }

    private function createKeys()
    {
        // Assuming use of PHP Sodium for crypto
        $this->prv = sodium_crypto_box_keypair();
        $this->pub = sodium_crypto_box_publickey($this->prv);
        $this->sigPrv = sodium_crypto_sign_keypair();
        $this->sigPub = sodium_crypto_sign_publickey($this->sigPrv);
        $this->updateHashes();
    }

    private function updateHashes()
    {
	    $this->hash = bin2hex(substr(hex2bin(hash('sha256',$this->getPublicKey())),0,Identity::TRUNCATED_HASHLENGTH / 8));
    }
	
	public function loadFromFile($file) {
		$this->loadPrivateKey(file_get_contents($file));
	}
	
	public function loadPrivateKey($key) {

        try {
			
            $halfKeySize = self::KEYSIZE / 8 / 2;
            $prvBytes = substr($key, 0, $halfKeySize);
            $this->prv = bin2hex($prvBytes);
            $sigPrvBytes = substr($key, $halfKeySize);
            $this->sigPrv = bin2hex($sigPrvBytes);
			$this->pub = bin2hex(sodium_crypto_box_publickey_from_secretkey(hex2bin($this->prv)));
           // $this->pubBytes = sodium_crypto_box_publickey_from_secretkey(hex2bin($this->prv));
			
			$sigKeys = sodium_crypto_sign_seed_keypair(hex2bin($this->sigPrv));
			
			$this->sigPub = bin2hex(sodium_crypto_sign_publickey($sigKeys));

            $this->updateHashes();

            return true;
        } catch (Exception $e) {
            error_log("Failed to load identity key: " . $e->getMessage());
            return false;
        }
	}
	
	public function loadPublicKey($publicKey) {
		$keyHalfLength = self::KEYSIZE / 8 / 2;
        $pubBytes = substr($publicKey, 0, $keyHalfLength);
        $sigPubBytes = substr($publicKey, $keyHalfLength);
        $this->pub = bin2hex($pubBytes);
        $this->sigPub = bin2hex($sigPubBytes);
		$this->updateHashes();

        return true;
	}

	function from_bytes_little_endian($bytes) {
		$length = strlen($bytes);
		$int = 0;
		for ($i = 0; $i < $length; $i++) {
			$int += ord($bytes[$i]) << ($i * 8);
		}
		return $int;
	}

	public function fromBytesLittleEndian($s) {
		// Unpack the string as a little-endian unsigned integer (machine dependent size)
		$unpacked = unpack('V', $s); // 'V' stands for little-endian unsigned long (always 32-bit, PHP's integer size)

		// Return the first element from the unpacked array
		return $unpacked[1];
	}
    public function getPublicKey()
    {
        return hex2bin($this->pub).hex2bin($this->sigPub);
    }

    public function getPrivateKey()
    {
        return $this->prv;
    }

    public function encrypt($plaintext, $ratchet = null)
    {
        // Example encryption method
        if ($ratchet !== null) {
            $sharedKey = sodium_crypto_scalarmult($this->prv, $ratchet);
            $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
            return sodium_crypto_secretbox($plaintext, $nonce, $sharedKey);
        } else {
            $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
            return sodium_crypto_box_seal($plaintext, $this->pub);
        }
    }

    public function decrypt($ciphertext, $nonce)
    {
        if ($this->prv !== null) {
            return sodium_crypto_secretbox_open($ciphertext, $nonce, $this->prv);
        } else {
            throw new Exception("Private key not loaded");
        }
    }

    public function sign($message)
    {
        return sodium_crypto_sign($message, $this->sigPrv);
    }

    public function validate($signature, $message)
    {
		$ret = sodium_crypto_sign_verify_detached($signature, $message, hex2bin($this->sigPub));
		return $ret;
    }

    // Additional methods would need to be implemented here...
}