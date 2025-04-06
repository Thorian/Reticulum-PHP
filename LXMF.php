<?php
namespace Reticulum;

class LXMF extends Destination {
		public $display_name;
		
		public function __construct(?Identity $identity=null,$display_name="") {
			parent::__construct($identity,'lxmf',"delivery","propagation");
			$this->display_name = $display_name;
		}
	
}