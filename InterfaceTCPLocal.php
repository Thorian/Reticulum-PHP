<?php
namespace Reticulum;

class ReticulumInterfaceTCPLocal extends ReticulumInterface {
    private $socket;
    private $port;
    private $host;
    private $buffer = '';

    public function __construct($host = '127.0.0.1', $port = 37428) {
        $this->host = $host;
        $this->port = $port;
		$this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($this->socket === false) {
            throw new \Exception("Creation failed: " . socket_strerror(socket_last_error()));
        }
        socket_set_nonblock($this->socket);
		$this->connect();
    }

    public function connect() {
        socket_connect($this->socket, $this->host, $this->port); // Suppress errors due to non-blocking mode
        // Check for immediate connection or in progress (expected in non-blocking mode)
      /*  if (socket_last_error($this->socket) !== SOCKET_EINPROGRESS && socket_last_error($this->socket) !== SOCKET_EALREADY) {
            throw new \Exception("Connection failed: " . socket_strerror(socket_last_error($this->socket)));
        }*/
    }

    public function read() {
        $read = @socket_read($this->socket, 4096, PHP_BINARY_READ); // Read in non-blocking mode
        if ($read === false && socket_last_error($this->socket) != SOCKET_EWOULDBLOCK) {
            throw new \Exception("Read failed: " . socket_strerror(socket_last_error($this->socket)));
        }

        if (!empty($read)) {
            $this->buffer .= $read;
        }

        return $this->extractFrames();
    }

    private function extractFrames() {
        $frames = [];
        while (true) {
            $frameStart = strpos($this->buffer, hex2bin('7E'));
            if ($frameStart !== false) {
                $frameEnd = strpos($this->buffer, hex2bin('7E'), $frameStart + 1);
                if ($frameEnd !== false) {
                    $frame = substr($this->buffer, $frameStart + 1, $frameEnd - $frameStart - 1);
                    $frame = $this->escapeSpecialCharacters($frame);
                    if (strlen($frame) > 0) {
                        $frames[] = Packet::parse($frame);
                    }
                    $this->buffer = substr($this->buffer, $frameEnd + 1);
                } else {
                    // Exit the loop if no complete frame is found
                    break;
                }
            } else {
                // Exit the loop if no start delimiter is found
                break;
            }
        }
        return $frames;
    }

    public function close() {
        socket_close($this->socket);
    }
}
