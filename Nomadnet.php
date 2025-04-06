<?php

namespace Reticulum;

class Nomadnet extends Destination {
		public $display_name;
	
		public function __construct(?Identity $identity=null,$display_name="") {
			parent::__construct($identity,'nomadnetwork',"node");
			$this->display_name = $display_name;
		}
}