<?php
namespace Reticulum;


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
    private const TRUNCATED_HASHLENGTH = 160; // Placeholder for truncated hash length

    private static $known_destinations = [];
    private static $known_ratchets = [];

    private $prv;
    private $pub;
    private $sigPrv;
    private $sigPub;
    private $hash;
    private $hexHash;
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

				print_r($announcedIdentity);
				
				if ($announcedIdentity->pub !== null && $announcedIdentity->validate($signature, $signedData)) {
					if ($onlyValidateSignature) {
						unset($announcedIdentity);
						return true;
					}

					$hashMaterial = $nameHash . $announcedIdentity->pub; // Assuming this is a method to get a hash
					$expectedHash = substr(hash("sha256", $hashMaterial), 0, Identity::SIGLENGTH / 8);

					if ($destinationHash == $expectedHash) {
						// Implement logic as needed, e.g., checking known destinations, logging, etc.
						return true;
					} else {
						RNS::log("Received invalid announce for " . RNS::prettyhexrep($destinationHash) . ": Destination mismatch.", RNS::LOG_DEBUG);
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
        $this->hash = sodium_crypto_generichash($this->getPublicKey());
        $this->hexHash = bin2hex($this->hash);
    }
	
	public function loadPublicKey($publicKey) {
		$keyHalfLength = self::KEYSIZE / 8 / 2;
        $pubBytes = substr($publicKey, 0, $keyHalfLength);
        $sigPubBytes = substr($publicKey, $keyHalfLength);
        $this->pub = $pubBytes;
        $this->sigPub = $sigPubBytes;

        $this->updateHashes();

        return true;
	}

	public function fromBytesLittleEndian($s) {
		// Unpack the string as a little-endian unsigned integer (machine dependent size)
		$unpacked = unpack('V', $s); // 'V' stands for little-endian unsigned long (always 32-bit, PHP's integer size)

		// Return the first element from the unpacked array
		return $unpacked[1];
	}
    public function getPublicKey()
    {
        return $this->pub;
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
		echo "signature: $signature \n\r";
		echo "Message $message \n\r";
		
        return sodium_crypto_sign_verify_detached($signature, $message, $this->sigPub);
    }

    // Additional methods would need to be implemented here...
}