<?php
namespace Reticulum;

abstract class ReticulumInterface {
    abstract public function read();
    
	const MAX_HOPS = 128;
	
	protected function escapeSpecialCharacters($frame) {
        // Unescape special characters
        $frame = str_replace(chr(0x7D) . chr(0x5E), chr(0x7E), $frame);
        $frame = str_replace(chr(0x7D) . chr(0x5D), chr(0x7D), $frame);
        return $frame;
    }
}