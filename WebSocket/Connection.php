<?php

namespace WebSocket;

/**
 * WebSocket Connection class
 *
 * @author Nico Kaiser <nico@kaiser.me>
 */
class Connection
{
    private $server;
    
    private $socket;

    private $handshaked = false;

    private $application = null;
    
    public function __construct($server, $socket)
    {
        $this->server = $server;
        $this->socket = $socket;

        $this->log('Connected');
    }
    
    private function handshake($data)
    {
        $this->log('Performing handshake');
        
        $lines = preg_split("/\r\n/", $data);
        if (count($lines)  && preg_match('/<policy-file-request.*>/', $lines[0])) {
            $this->log('Flash policy file request');
            $this->serveFlashPolicy();
            return false;
        }

        if (! preg_match('/\AGET (\S+) HTTP\/1.1\z/', $lines[0], $matches)) {
            $this->log('Invalid request: ' . $lines[0]);
            socket_close($this->socket);
            return false;
        }
        
        $path = $matches[1];

        foreach ($lines as $line) {
            $line = chop($line);
            if (preg_match('/\A(\S+): (.*)\z/', $line, $matches)) {
                $headers[$matches[1]] = $matches[2];
            }
        }

        $key3 = '';
        preg_match("#\r\n(.*?)\$#", $data, $match) && $key3 = $match[1];

        $origin = $headers['Origin'];
        $host = $headers['Host'];

        $this->application = $this->server->getApplication(substr($path, 1)); // e.g. '/echo'
        if (! $this->application) {
            $this->log('Invalid application: ' . $path);
            socket_close($this->socket);
            return false;
        }
        
        $status = '101 Web Socket Protocol Handshake';
            //10
        if (array_key_exists('Sec-WebSocket-Key', $headers)) {
             $safes = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
             $hash = $headers['Sec-WebSocket-Key'].$safes;
              $this->log("THIS IS HASH '$hash'");
              $hash = base64_encode(sha1($hash, true));

            $def_header = array(
                'Sec-WebSocket-Accept' => $hash,
            );

        } else if (array_key_exists('Sec-WebSocket-Key1', $headers)) {
            // draft-76
            $def_header = array(
                'Sec-WebSocket-Origin' => $origin,
                'Sec-WebSocket-Location' => "ws://{$host}{$path}"
            );
            $digest = $this->securityDigest($headers['Sec-WebSocket-Key1'], $headers['Sec-WebSocket-Key2'], $key3);
        } else {
            // draft-75
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
    
   private static function parseFrame($data) {
      $data = array_values(unpack("C*", $data));
      $i = $data[0]; $fin = $i & 0x80; $opcode = $i&0x0F;
      if(!$fin) throw new Exception("unsupported fin");
      if($opcode != 0x1) throw new Exception("unsupported opcode");
      $i = $data[1]; $masked = $i&0x80; $len = $i&0x7F;
      if(!$masked) throw new Exception("unsupported should be masked");
      if($len>=126) throw new Exception("unsupported len");
      $mask = array_slice($data, 2, 4);
      $str = "";
      for($i=0;$i<$len;$i++)
        $str .= chr($data[6+$i] ^ $mask[$i%4]);
      return array($str);
  }

  private static function parseClassic($data){
        $out = array();
        foreach(explode(chr(255), $data) as $chunk) {
          if($chunk == "") break;
          if($chunk[0] != chr(0)) return false;
          $out[] = substr($chunk, 1);
        }

        return $out;
  }

    private function handle($data)
    {
      $this->log("Data in is ".join(',', unpack("C*", $data)));

      if($data[0] != chr(0))
        $chunks = $this->parseFrame($data);
      else 
        $chunks = $this->parseClassic($data);
      $this->log(print_r($chunks,1));
      if($chunks === false) {
          $this->log('Data incorrectly framed. Dropping connection');
          socket_close($this->socket);
          return false;
      }

      foreach($chunks as $chunk)
        $this->application->onData($chunk, $this);

      return true;
    }
    
    private function serveFlashPolicy()
    {
        $policy = '<?xml version="1.0"?>' . "\n";
        $policy .= '<!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">' . "\n";
        $policy .= '<cross-domain-policy>' . "\n";
        $policy .= '<allow-access-from domain="*" to-ports="*"/>' . "\n";
        $policy .= '</cross-domain-policy>' . "\n";
        socket_write($this->socket, $policy, strlen($policy));
        socket_close($this->socket);
    }
    
    public function send($data)
    {
      $this->log("Force answer");
      $data = pack("C*", 129,strlen($data)).$data;
      socket_write($this->socket,$data);
      return;
      
        if (! @socket_write($this->socket, chr(0) . $data . chr(255), strlen($data) + 2)) {
            @socket_close($this->socket);
            $this->socket = false;
        }
    }
    
    public function onDisconnect()
    {
        $this->log('Disconnected', 'info');
        
        if ($this->application) {
            $this->application->onDisconnect($this);
        }
        socket_close($this->socket);
    }

    private function securityDigest($key1, $key2, $key3)
    {
        return md5(
            pack('N', $this->keyToBytes($key1)) .
            pack('N', $this->keyToBytes($key2)) .
            $key3, true);
    }

    /**
     * WebSocket draft 76 handshake by Andrea Giammarchi
     * see http://webreflection.blogspot.com/2010/06/websocket-handshake-76-simplified.html
     */
    private function keyToBytes($key)
    {
        return preg_match_all('#[0-9]#', $key, $number) && preg_match_all('# #', $key, $space) ?
            implode('', $number[0]) / count($space[0]) :
            '';
    }

    public function log($message, $type = 'info')
    {
        socket_getpeername($this->socket, $addr, $port);
        $this->server->log('[client ' . $addr . ':' . $port . '] ' . $message, $type);
    }
}