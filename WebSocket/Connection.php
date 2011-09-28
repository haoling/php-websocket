<?php

namespace WebSocket;

/**
 * WebSocket Connection class
 *
 * @author Andrea Giammarchi <webreflection.blogspot.com> (draft 76 handshake)
 * @author Nico Kaiser <nico@kaiser.me> (original author)
 * @author Simon Samtleben <web@lemmingzshadow.net> (draft 10 hybi10 support)
 * @author Walter Stanish <stani.sh/walter> (code integration, comments)
 */
class Connection
{
    private $server;
    private $socket;
    private $handshaked = false;
    private $application = null;
    private $draft = '';

    public function __construct($server, $socket) {
     $this->server = $server;
     $this->socket = $socket;
     $this->log('Connected');
    }
    
    # post-connection server handshake function
    private function handshake($data) {
     $this->log('Performing handshake');
     $lines = preg_split("/\r\n/", $data);

     # if the first line contains a flash policy file request
     if (count($lines) && preg_match('/<policy-file-request.*>/', $lines[0])) {
      $this->log('Flash policy file request');
      # deliver one
      $this->serveFlashPolicy();
      return false;
     }

     # otherwise... require HTTP/1.1 GET request, extract path
     if (! preg_match('/\AGET (\S+) HTTP\/1.1\z/', $lines[0], $matches)) {
      $this->log('Invalid request: ' . $lines[0]);
      socket_close($this->socket);
      return false;
     }
     $path = $matches[1];

     # validate application from supplied path
     $this->application = $this->server->getApplication(substr($path, 1)); // e.g. '/echo'
     if (! $this->application) {
      $this->log('Invalid application: ' . $path);
      socket_close($this->socket);
      return false;
     }

     # extract headers
     foreach ($lines as $line) {
      $line = chop($line);
      if (preg_match('/\A(\S+): (.*)\z/', $line, $matches)) {
       $headers[$matches[1]] = $matches[2];
      }
     }

     /**
      * Insert by Simon Samtleben <web@lemmingzshadow.net>
      * Support for handshake draft:
      * draft-ietf-hybi-thewebsocketprotocol-10
      */
     if(isset($headers['Sec-WebSocket-Version']) && $headers['Sec-WebSocket-Version'] >= 6) {
      $this->draft = 10;
      $secKey = $headers['Sec-WebSocket-Key'];
      $secAccept = base64_encode(pack('H*', sha1($secKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
      $response = "HTTP/1.1 101 Switching Protocols\r\n";
      $response.= "Upgrade: websocket\r\n";
      $response.= "Connection: Upgrade\r\n";
      $response.= "Sec-WebSocket-Accept: " . $secAccept .  "\r\n";
      $response.= "Sec-WebSocket-Protocol: " .  substr($path, 1) . "\r\n\r\n";
      socket_write($this->socket, $response, strlen($response));
      $this->handshaked = true;
      $this->log('Handshake sent');
      $this->application->onConnect($this);
      return true;
     }

     # handshake draft 75 & 76
     $key3 = '';
     preg_match("#\r\n(.*?)\$#", $data, $match) && $key3 = $match[1];
     $origin = $headers['Origin'];
     $host = $headers['Host'];
     $status = '101 Web Socket Protocol Handshake';
     if (array_key_exists('Sec-WebSocket-Key', $headers)) {
      $safes = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
      $hash = $headers['Sec-WebSocket-Key'].$safes;
      $this->log("THIS IS HASH '$hash'");
      $hash = base64_encode(sha1($hash, true));
      $def_header = array(
       'Sec-WebSocket-Accept' => $hash,
      );
     }
     else if (array_key_exists('Sec-WebSocket-Key1', $headers)) {
      // draft-76 : Requires a 'Security Digest' header to be present.
      $this->draft = 76;
      $def_header = array(
       'Sec-WebSocket-Origin' => $origin,
       'Sec-WebSocket-Location' => "ws://{$host}{$path}"
      );
      $digest = $this->securityDigest($headers['Sec-WebSocket-Key1'], $headers['Sec-WebSocket-Key2'], $key3);
     }
     else {
      // draft-75 : No 'Security Digest' header.
      $this->draft = 75;
      $def_header = array(
       'WebSocket-Origin' => $origin,
       'WebSocket-Location' => "ws://{$host}{$path}"  
      );
      $digest = '';
     }
     $header_str = '';
     foreach ($def_header as $key => $value) {
      $header_str .= $key . ': ' . $value . "\r\n";
     }

     $upgrade = "HTTP/1.1 ${status}\r\n" .
                "Upgrade: WebSocket\r\n" .
                "Connection: Upgrade\r\n" .
                "${header_str}\r\n$digest";

     socket_write($this->socket, $upgrade, strlen($upgrade));
     
     $this->handshaked = true;
     $this->log('Handshake sent');

     $this->application->onConnect($this);

     return true;
    }
    
    public function onData($data)
    {
      $this->log("THIS IS ONDATA");
        if ($this->handshaked) {
            $this->handle($data);
        } else {
            $this->handshake($data);
        }
    }
 
  # No documentation - wuh?
  #
  #  - What version was this written against?
  #  - What are the capabilities? It seems that...
  #     - unmasked data is not supported
  #     - multi-frame messages are not supported
  #       (initial frame MUST include FIN flag)
  #     - lengths over 126 are not supported
  #  - It seems to be a more limited version of 
  #    Simon Samtleben's hybi10Decode function,
  #    which also lacks documentation
  #
  # Comments below are an attempt to make sense of this
  # situation...
  private static function parseFrame($data) {
   # unpack data
   $data = array_values(unpack("C*", $data));
   # assign the first byte to $i
   $i = $data[0];
   # extract the FIN bit (last frame in message indicator)
   $fin = $i & 0x80;
   # extract opcodes
   $opcode = $i&0x0F;
   # whinge if single-frame message limitation is exceeded
   if(!$fin) throw new Exception("unsupported fin");
   # abort on unknown opcodes (required by the standard)
   if($opcode != 0x1) throw new Exception("unsupported opcode");
   # assign the second byte to $i
   $i = $data[1];
   # the first bit of the byte is the masking indicator bit
   $masked = $i&0x80;
   # the subsequent 7 bits of the byte are the payload length
   $len = $i&0x7F;
   # whinge if masked indicator is unset (server->client
   # frames may have this unset, client->server frames must
   # have this set, as of draft-15, 2011-09-17)
   if(!$masked) throw new Exception("unsupported should be masked");
   # whinge if payload length exceeds 126. this is a bug,
   # as a value of 127 should enable 64-bit lengths
   if($len>=126) throw new Exception("unsupported len");
   # get 32-bit mask value from the four subsequent bytes
   $mask = array_slice($data, 2, 4);
   $str = "";
   # apply the mask to the message frame
   for($i=0;$i<$len;$i++)
     $str .= chr($data[6+$i] ^ $mask[$i%4]);
   # return the unmasked frame value
   return array($str);
  }
 
  # antiquated frame parsing function, now deprecated
  # and apparently only of use with older versions of
  # the web sockets protocol
  private static function parseClassic($data){
   $out = array();
   foreach(explode(chr(255), $data) as $chunk) {
    if($chunk == "") break;
    if($chunk[0] != chr(0)) return false;
    $out[] = substr($chunk, 1);
   }
   return $out;
  }

  # websocket data frame handler function
  # 
  # FIXTHIS: should be modified to use the
  #          new decode function by Simon Samtleben
  #          <web@lemmingzshadow.net>
  #
  # Args:    $data   A single raw websocket frame.
  #
  # Returns: true on parsing success,
  #          false on parsing failure.
  #
  # Note:    No information is returned about the
  #          success of actual message handling.
  private function handle($data) {

    # Debugging
    $this->log("Data in is ".join(',', unpack("C*", $data)));

    # First unframe the message chunks
    #  - if the first byte is nonzero, use parseFrame()
    if($data[0] != chr(0)) {
      $chunks = $this->parseFrame($data);
    }
    #  - otherwise, use the older parseClassic()
    else {
      $chunks = $this->parseClassic($data);
    }

    # Debugging
    $this->log(print_r($chunks,1));

    # Abort on failure
    if($chunks === false) {
        $this->log('Data incorrectly framed. Dropping connection');
        socket_close($this->socket);
        return false;
    }

    # Call message handler function once per message chunk
    foreach($chunks as $chunk) {
     $this->application->onData($chunk, $this);
    }

    return true;
  }

    # decoder function
    #  Simon Samtleben <web@lemmingzshadow.net>
    private function hybi10Decode($data)
    {
     $bytes = $data;
     $dataLength = '';
     $mask = '';
     $coded_data = '';
     $decodedData = '';
     $secondByte = sprintf('%08b', ord($bytes[1]));
     $masked = ($secondByte[0] == '1') ? true : false;
     $dataLength = ($masked === true) ? ord($bytes[1]) & 127 : ord($bytes[1]);

     # masked
     if($masked === true)
     {
      if($dataLength === 126)
      {
       $mask = substr($bytes, 4, 4);
       $coded_data = substr($bytes, 8);
      }
      elseif($dataLength === 127)
      {
       $mask = substr($bytes, 10, 4);
       $coded_data = substr($bytes, 14);
      }
      else
      {
       $mask = substr($bytes, 2, 4);         
       $coded_data = substr($bytes, 6);      
      }      
      for($i = 0; $i < strlen($coded_data); $i++)
      {      
       $decodedData .= $coded_data[$i] ^ $mask[$i
% 4];
      }
     }
     # not masked
     else
     {
      if($dataLength === 126)
      {      
       $decodedData = substr($bytes, 4);
      }
      elseif($dataLength === 127)
      {      
       $decodedData = substr($bytes, 10);
      }
      else
      {
       $decodedData = substr($bytes, 2);     
      }      
     }      
     return $decodedData;
    }

    # encoder function 
    #  Simon Samtleben <web@lemmingzshadow.net>
    private function hybi10Encode($data)
    {
            $frame = Array();
            $mask = array(rand(0, 255), rand(0, 255), rand(0, 255),
rand(0, 255));
            $encodedData = '';
            $frame[0] = 0x81;
            $dataLength = strlen($data);


            if($dataLength <= 125)
            { 
                    $frame[1] = $dataLength + 128;
            }
            else
            {
                    $frame[1] = 254;
                    $frame[2] = $dataLength >> 8;
                    $frame[3] = $dataLength & 0xFF;
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
    
    # strictly speaking, this is not part of the protocol
    # and should therefore be carved out and lumped on its
    # own in a separate file (though it may remain within
    # the library's codebase)
    private function serveFlashPolicy() {
     $policy = '<?xml version="1.0"?>' . "\n";
     $policy .= '<!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">' . "\n";
     $policy .= '<cross-domain-policy>' . "\n";
     $policy .= '<allow-access-from domain="*" to-ports="*"/>' . "\n";
     $policy .= '</cross-domain-policy>' . "\n";
     socket_write($this->socket, $policy, strlen($policy));
     socket_close($this->socket);
    }
    
    # pretty iffy. the good stuff (draft specific code) is
    # from Simon Samtleben <web@lemmingzshadow.net>
    public function send($data) {

     /*
     # what is the explanation for this code?
     $this->log("Force answer");
     $data = pack("C*", 129,strlen($data)).$data;
     socket_write($this->socket,$data);
     return;
     */
      
     # drafts 75 & 76
     if($this->draft == 75 || $this->draft == 76) {
      if (! @socket_write($this->socket, chr(0) . $data .  chr(255), strlen($data) + 2)) {
       @socket_close($this->socket);
       $this->socket = false;
      }
     }

     # draft 10
     if($this->draft == 10) {
      $encodedData = $this->hybi10Encode($data);
      if(!@socket_write($this->socket, $encodedData, strlen($encodedData))) {
       @socket_close($this->socket);
       $this->socket = false;
      }
     }

    }
    
    # disconnection handler
    public function onDisconnect() {
     # debugging
     $this->log('Disconnected', 'info');

     # in the case of a server, call the application
     # disconnection handler if defined
     if ($this->application) {
      $this->application->onDisconnect($this);
     }

     # close the socket
     socket_close($this->socket);
    }

    # WebSocket draft 76 handshake digest
    #  by Andrea Giammarchi
    #  see http://webreflection.blogspot.com/2010/06/websocket-handshake-76-simplified.html
    private function securityDigest($key1, $key2, $key3) {
     return md5(pack('N', $this->keyToBytes($key1)) . pack('N', $this->keyToBytes($key2)) . $key3, true);
    }

    # WebSocket draft 76 handshake digest support function
    #  by Andrea Giammarchi
    #  see http://webreflection.blogspot.com/2010/06/websocket-handshake-76-simplified.html
    private function keyToBytes($key) {
     return preg_match_all('#[0-9]#', $key, $number) && preg_match_all('# #', $key, $space) ? implode('', $number[0]) / count($space[0]) : '';
    }

    # basic logging function
    public function log($message, $type = 'info') {
     socket_getpeername($this->socket, $addr, $port);
     $this->server->log('[client ' . $addr . ':' . $port . '] ' . $message, $type);
    }
}
