<?php
ini_set('display_errors', 1);
error_reporting(E_ALL ^ E_WARNING ^ E_STRICT ^ E_NOTICE);

/**
 * Very basic websocket client.
 *
 * Supporting handshake from drafts:
 *	draft-hixie-thewebsocketprotocol-76
 *	draft-ietf-hybi-thewebsocketprotocol-00
 *      draft-ietf-hybi-thewebsocketprotocol-10
 * 
 * @author Simon Samtleben <web@lemmingzshadow.net>
 * @author Walter Stanish <stani.sh/walter>
 */

class WebSocketClient
{
	public $draft = 'hybi16';

	private $_Socket = null;
	private $_debugging = 0;
	
	public function __construct($host, $port, $path = '/')
	{
		$this->_connect($host, $port, $path);	
	}
	
	public function __destruct()
	{
		$this->_disconnect();
	}

	private function debug($str) {
	 if($this->_debugging) {
	  if($fh = fopen('WebSocketClient.log','a')) {
	   fwrite($fh,$str);
           fclose($fh);
          }
         }
	}

	# get/set function
	public function debugging($value='') {
	 if($value!='') {
	  if($value) {
	   $this->_debugging = 1;
	  }
	  else {
	   $this->_debugging = 0;
	  }
	 }
	 return $value;
	}

	# hex dump helper function
	private function hex_dump($data, $newline="\n") {
	  $output = '';
	  static $from = '';
	  static $to = '';
	
	  static $width = 16; # number of bytes per line
	
	  static $pad = '.'; # padding for non-visible characters
	
	  if ($from==='')
	  {
	    for ($i=0; $i<=0xFF; $i++)
	    {
	      $from .= chr($i);
	      $to .= ($i >= 0x20 && $i <= 0x7E) ? chr($i) : $pad;
	    }
	  }
	
	  $hex = str_split(bin2hex($data), $width*2);
	  $chars = str_split(strtr($data, $from, $to), $width);
	
	  $offset = 0;
	  foreach ($hex as $i => $line)
	  {
	    $output .= sprintf('%6X',$offset).' : '.implode(' ', str_split($line,2)) . ' [' . $chars[$i] . ']' . $newline;
	    $offset += $width;
	  }
	  return $output;
	}
	
        # get data from the socket
	public function getData()
	{
	 if(!($wsdata = fread($this->_Socket, 2000))) {
          throw new exception('Socket read failed.');
	 }
         switch($this->draft) {
          case 'hybi00':
           return trim($wsdata,"\x00\xff");
          case 'hybi10':
          case 'hybi16':
           return $this->_hybi10DecodeData($wsdata);
         }
	}

	# send data to the socket
	public function sendData($data)
	{
		switch($this->draft)
		{
			case 'hybi00':
				print "sending data ($data)\n";
				fwrite($this->_Socket, "\x00" . $data . "\xff" ) or die('Error:' . $errno . ':' . $errstr); 
				$wsData = fread($this->_Socket, 2000);
				$retData = trim($wsData,"\x00\xff");		
			break;
		
			case 'hybi10':
			case 'hybi16';
				fwrite($this->_Socket, $this->_hybi10EncodeData($data)) or die('Error:' . $errno . ':' . $errstr); 
				$wsData = fread($this->_Socket, 2000);				
				$retData = $this->_hybi10DecodeData($wsData);
			break;
		}
		
		return $retData;
	}

	private function _connect($host, $port, $path)
	{
		switch($this->draft)
		{
			case 'hybi00':
				$key1 = $this->_generateRandomString(32);
				$key2 = $this->_generateRandomString(32);
				$key3 = $this->_generateRandomString(8, false, true);		

				$header = "GET " . $path . " HTTP/1.1\r\n";
				$header.= "Host: ".$host.":".$port."\r\n";
				$header.= "Upgrade: WebSocket\r\n";
				$header.= "Connection: Upgrade\r\n";
				$header.= "Origin: null\r\n";
				$header.= "Sec-WebSocket-Key1: " . $key1 . "\r\n";
				$header.= "Sec-WebSocket-Key2: " . $key2 . "\r\n";
				$header.= "\r\n";
				$header.= $key3;
			break;
		
			case 'hybi10':
			case 'hybi16':
				$key = base64_encode($this->_generateRandomString(16, false, true));
				
				$header = "GET " . $path . " HTTP/1.1\r\n";
				$header.= "Host: ".$host.":".$port."\r\n";
				$header.= "Upgrade: websocket\r\n";
				$header.= "Connection: Upgrade\r\n";
				$header.= "Origin: null\r\n";
				$header.= "Sec-WebSocket-Key: " . $key . "\r\n";
				$header.= "Sec-WebSocket-Origin: null\r\n";
				$header.= "Sec-WebSocket-Version: 8\r\n";
				$header.= "\r\n";
			break;
		}		

		print "Connecting... ";
		$this->_Socket = fsockopen($host, $port, $errno, $errstr, 2); 
		print "OK.\n";
		print "Sending data... ";
		fwrite($this->_Socket, $header) or die('Error: ' . $errno . ':' . $errstr); 
		print "OK.\n------------sent this-----------------------\n$header\n-----------------------------------\n";
		print "Lengthening socket read timeout to 10 seconds... ";
		if(stream_set_timeout($this->_Socket, 10)) {
		 print "OK.\n";
		}
		else {
		 print "FAILED.\n";
		}
		print "Reading response... ";
		if(!($response = fread($this->_Socket, 2000))) {
			print "ERROR: No response.\n";
			return false;
		}
                print "OK.\n";
		print_r($response);

                switch($this->draft)
                {
                        case 'hybi10':
			case 'hybi16':
				print "Processing response as hybi10 with key verification.\n";
				preg_match('#Sec-WebSocket-Accept:\s(.*)$#mU', $response, $matches);
				$keyAccept = trim($matches[1]);
				$expectedResponse = base64_encode(pack('H*', sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
				print "Comparing $keyAccept to $expectedResponse!\n";
				return ($keyAccept === $expectedResponse) ? true : false;
				break;

			default:
				print "Cowardly refusing to perform key verification.\n";
				/**
				 * No key verification for draft hybi00, cause it's already deprecated.
				 */
				return true;
		}	
	}
	
	private function _disconnect()
	{
		fclose($this->_Socket);
	}

	private function _generateRandomString($length = 10, $addSpaces = true, $addNumbers = true)
	{  
		$characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"§$%&/()=[]{}';
		$useChars = array();
		// select some random chars:    
		for($i = 0; $i < $length; $i++)
		{
			$useChars[] = $characters[mt_rand(0, strlen($characters)-1)];
		}
		// add spaces and numbers:
		if($addSpaces === true)
		{
			array_push($useChars, ' ', ' ', ' ', ' ', ' ', ' ');
		}
		if($addNumbers === true)
		{
			array_push($useChars, rand(0,9), rand(0,9), rand(0,9));
		}
		shuffle($useChars);
		$randomString = trim(implode('', $useChars));
		$randomString = substr($randomString, 0, $length);
		return $randomString;
	}
	
	private function _hybi10EncodeData($data)
	{
		$frame = Array();
		$mask = array(rand(0, 255), rand(0, 255), rand(0, 255), rand(0, 255));
		$encodedData = '';
		$frame[0] = 0x81;
		$payloadLength = strlen($data);

		if($payloadLength <= 125)
		{		
			$frame[1] = $payloadLength + 128;		
		}
		else
		{
			$frame[1] = 254;  
			$frame[2] = $payloadLength >> 8;
			$frame[3] = $payloadLength & 0xFF; 
		}	
		$frame = array_merge($frame, $mask);	
		for($i = 0; $i < strlen($data); $i++)
		{		
			$frame[] = ord($data[$i]) ^ $mask[$i % 4];
		}

		for($i = 0; $i < sizeof($frame); $i++)
		{
			$encodedData .= chr($frame[$i]);
		}		
		
		return $encodedData;
	}
	
        # Frame decoding function.
        #  - See the 'Data Framing' section in the specification
        #     - All data from a client to a server is 'masked' to avoid confusing intermediaries and for security reasons
        #     - No data from a server to a client is masked
        #        - The client must close the connection upon receiving a
        #          masked frame (as per draft 16)
        #  - Frame format (as per draft 16):
        #       0                   1                   2                   3
        #       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        #      +-+-+-+-+-------+-+-------------+-------------------------------+
        #      |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
        #      |I|S|S|S|  (4)  |A|     (7)     |             (16/63)           |
        #      |N|V|V|V|       |S|             |   (if payload len==126/127)   |
        #      | |1|2|3|       |K|             |                               |
        #      +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
        #      |     Extended payload length continued, if payload len == 127  |
        #      + - - - - - - - - - - - - - - - +-------------------------------+
        #      |                               |Masking-key, if MASK set to 1  |
        #      +-------------------------------+-------------------------------+
        #      | Masking-key (continued)       |          Payload Data         |
        #      +-------------------------------- - - - - - - - - - - - - - - - +
        #      :                     Payload Data continued ...                :
        #      + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
        #      |                     Payload Data continued ...                |
        #      +---------------------------------------------------------------+
	#
	# NOTE: This implementation is partial and does not conform to the
	#       specification. Specifically, multi-frame messages,
	#       reserved flag behaviours (extensions), and control frames
	#       are not supported.
	private function _hybi10DecodeData($raw_frame) {

	 $this->debug("_hybi10DecodeData():
 - raw frame:
-------------------------
$raw_frame
-------------------------
 - hex dump:
-------------------------
" . $this->hex_dump($raw_frame) . "
-------------------------\n");

	 # For simplicity of implementation, we ignore byte one.
	 # This means:
	 #  - We do not support multi-frame messages
	 #  - Reserved flag behaviour mandated in the specification
	 #    cannot be implemented
	 #  - We cannot distinguish between control frames and data
	 #    frames.
	 $first_byte = sprintf('%08b', ord($raw_frame[0]));
	 #  - Determine FIN status
	 $flag_fin = $first_byte[0];
         $flag_rsv1 = $first_byte[1];
         $flag_rsv2 = $first_byte[2];
         $flag_rsv3 = $first_byte[3];
         $opcode = substr($first_byte,4);
	 $this->debug(" - First byte ($first_byte) in binary: " .  sprintf('%08b',ord($raw_frame[0])) . "\n");
	 $this->debug("    - FIN    = $flag_fin\n");
	 if(!$flag_fin) {
	  $this->debug("WARNING: FIN flag is not set - no support for multiframe messages in this implementation.\n");
	 }
         $this->debug("    - RSV1   = $flag_rsv1\n");
	 $this->debug("    - RSV2   = $flag_rsv2\n");
         $this->debug("    - RSV3   = $flag_rsv3\n");
	 if($flag_rsv1 || $flag_rsv2 || $flag_rsv3) {
	  $this->debug("WARNING: Unknown reserved flag set. According to the specification, we should drop the connection.\n");
	 }

	 # Determine opcode type
	 if($opcode == '0000') {
	  $opcode_type = 'Continuation';
	  $this->debug("WARNING: Multiframe messages are not supported by this implementation.\n");
	 }
	 elseif($opcode == '0001') {
	  $opcode_type = 'Text';
	 }
	 elseif($opcode = '0002') {
	  $opcode_type = 'Binary';
	 }
	 elseif($opcode == '1000') {
	  $opcode_type = 'Connection close';
	 }
	 elseif($opcode = '1001') {
	  $opcode_type = 'Ping';
	  $this->debug("WARNING: Ping functionality is not supported by this implementation.");
	 }
	 elseif($opcode = '1010') {
	  $opcode_type = 'Pong';
	 }
	 else {
	  $opcode_type = 'Unknown/Reserved';
	 }
	 $this->debug("    - Opcode = $opcode ($opcode_type)\n");

	 # Disconnect
	 if(($opcode_type == 'Connection close')) {
	  $this->_disconnect();
	  return false;
	 }

	 # Examine the second byte (mask, payload length)
	 $second_byte = sprintf('%08b', ord($raw_frame[1]));		
         $this->debug(" - Second byte ($second_byte) in binary: " .  sprintf('%08b',ord($raw_frame[1])) . "\n");

	 #  - Determine mask status
	 $frame_is_masked = $second_byte[0];
	 $this->debug("    - Masked = $frame_is_masked\n");

	 #  - Determine payload length
	 $payload_length = $frame_is_masked? ord($raw_frame[1]) & 127 : ord($raw_frame[1]);
	 $this->debug("    - Payload Length = $payload_length\n");

	 # Further processing is based upon masking state.
	 #
	 # Masked frame (client to server)
	 if($frame_is_masked) {

	  # First we determine the mask and payload offsets

	  # Default (standard payload, 7 bits)
	  $mask_offset = 2;
	  $payload_offet = 6;

	  # Extended payload (7+16 bits or +2 bytes)
	  if($payload_length === 126) {
	   $mask_offset = 4;
	   $payload_offset = 8;
	  }
	  # Really extended payload (7+64 bits or +8 bytes)
	  elseif($payload_length === 127) {
	   $mask_offset = 10;
	   $payload_offset = 14;
	  }

	  # Now we extract the mask and payload
	  $mask = substr($raw_frame, $mask_offset, 4);
	  $encoded_payload = substr($raw_frame, $payload_offset);

	  # Finally, we decode the encoded frame payload
	  for($i = 0; $i < strlen($encoded_payload); $i++) {		
	   $payload .= $encoded_payload[$i] ^ $mask[$i % 4];
	  }
	 }

	 # Unmasked frame (server to client)
	 else {
	  # Default payload offset
	  $payload_offset = 2;

	  # Extended payload (7+16 bits or +2 bytes)
	  if($payload_length === 126) { $payload_offset = 4; }
	  # Really extended payload (7+64 bits or +8 bytes)
	  elseif($payload_length === 127) { $payload_offset = 10; }

	  # Return unmasked payload
	  $payload = substr($raw_frame, $payload_offset-1, strlen($raw_frame)-$payload_offset);
	 }

	 $this->debug("Observed payload length: " . strlen($payload) .  "\n");
	 if($payload_length != strlen($payload)) {
	  $this->debug("WARNING: Observed payload length (".strlen($payload)." bytes) differs from claimed payload length ($payload_length bytes).\n");
         }

	 return $payload;

	}
}
