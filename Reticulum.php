<?PHP
namespace Reticulum;
require_once('Packet.php');
require_once('PacketAnnounce.php');
require_once('Interface.php');
require_once('InterfaceTCPLocal.php');
require_once('Identity.php');
require_once('Destination.php');
require_once('LXMF.php');
require_once('Nomadnet.php');


class Reticulum {
    private $interfaces = [];
	protected $destinations = [];

    public function addInterface(ReticulumInterface $interface) {
        $this->interfaces[] = $interface;
    }

    public function removeInterface(ReticulumInterface $interface) {
        $key = array_search($interface, $this->interfaces, true);
        if ($key !== false) {
            unset($this->interfaces[$key]);
        }
    }
	
	public function registerDestination(Destination $dst) {
		$this->destinations[] = $dst;
	}
	
    public function processIncomingData() {
        foreach ($this->interfaces as $interface) {
			$frames = $interface->read();
			foreach ($frames as $frame) {
				$this->processFrame($frame);
			}
        }
    }

    private function processFrame($packet) {
		if(!$packet->validate()) return;
		$announce = get_class($packet)=="Reticulum\\PacketAnnounce"?true:false;
		
		foreach ($this->destinations as $dst) {
			foreach ($dst->getDestinationIdentifiers() as $name => $hash) {
				if($hash != $packet->DestinationHash) continue;
				print_r($packet);
				die("WOW THAT PACKET WAS FOR ME!!!");
			}
			if($announce)
				foreach ($dst->getNameHashes() as $name => $hash) {
					echo "looking for $name with $hash...\n\r";
					//$check = bin2hex(substr(hash("sha256",hex2bin($hash).hex2bin($packet->announcedIdentity->hash),true),0,128/8));
					//if($packet->DestinationHash != $check) continue;
					if($packet->nameHash != $hash) continue;
					$dst->handlePacket($packet);
				}
		}
    }
}