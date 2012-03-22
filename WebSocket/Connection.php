<?php

/**
 * WebSocket Connection class
 *
 * @author Andrea Giammarchi <webreflection.blogspot.com> (draft 76 handshake)
 * @author Nico Kaiser <nico@kaiser.me> (original author)
 * @author Simon Samtleben <web@lemmingzshadow.net> (draft 10 hybi10 support)
 * @author Walter Stanish <stani.sh/walter> (code integration, comments)
 * @author Aya Mishina <http://fei-yen.jp/maya/> (Define abstract class)
 *
 * References:
 *  - HyBi Working Group, Standards Track, Draft 16 (2011-09-27)
 *    http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-16
 *  - HyBi Working Group, Standards Track, Draft 10 (2011-07-11)
 *    http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-10
 */
class WebSocketConnection extends WebSocket
{
    protected $server;
    protected $socket;
    protected $handshaked = false;
    protected $application = null;
    protected $draft = '';

    public function __construct(WebSocketServer $server, $socket)
    {
        $this->server = $server;
        $this->socket = $socket;
        $this->log('Connected');
    }

    public function isHandshaked()
    {
        return $this->handshaked;
        }

    public function handshake($data)
    {
        $this->onDisconnect();
        throw new Exception('Use Unhandshaked class for not handshaked connection.');
    }

    public function onData($data)
    {
        $this->log("THIS IS ONDATA");
        $this->handle($data);
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
    protected static function parseFrame($data)
    {
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
    protected static function parseClassic($data)
    {
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
    protected function handle($data)
    {

        # Debugging
        $this->log("Data in is ".join(',', unpack("C*", $data)));

        # First unframe the message chunks
        #  - if the first byte is nonzero, use parseFrame()
        try {
            if($data[0] != chr(0)) {
                $chunks = $this->parseFrame($data);
            }
                #  - otherwise, use the older parseClassic()
            else {
                $chunks = $this->parseClassic($data);
            }
        }
        catch(Exception $e) {
            $this->log('Data incorrectly framed. Dropping connection');
            $this->log($e->getMessage());
            $this->onDisconnect();
            return false;
        }

        # Debugging
        $this->log(print_r($chunks,1));

        # Abort on failure
        if($chunks === false) {
            $this->log('Data incorrectly framed. Dropping connection');
            $this->onDisconnect();
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
    protected function hybi10Decode($data)
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
    protected function hybi10Encode($data)
    {
        $frame = Array();
        $mask = array(rand(0, 255), rand(0, 255), rand(0, 255),
                      rand(0, 255));
        $encodedData = '';
        $frame[0] = 0x81;
        $dataLength = strlen($data);


        if($dataLength <= 125)
        {
            $frame[1] = $dataLength + ($this->getOption('send_mask', true) ? 128 : 0);
        }
        elseif($dataLength <= 65535)
        {
            $frame[1] = 126 + ($this->getOption('send_mask', true) ? 128 : 0);
            $frame[2] = ($dataLength >> 8) & 0xFF;
            $frame[3] = $dataLength & 0xFF;
        }
        else
        {
            $frame[1] = 127 + ($this->getOption('send_mask', true) ? 128 : 0);
            $frame[2] = 0;
            $frame[3] = 0;
            $frame[4] = 0;
            $frame[5] = 0;
            $frame[6] = ($dataLength >> 24) & 0xFF;
            $frame[7] = ($dataLength >> 16) & 0xFF;
            $frame[8] = ($dataLength >> 8) & 0xFF;
            $frame[9] = $dataLength & 0xFF;
        }
        if($this->getOption('send_mask', true))
        {
            $frame = array_merge($frame, $mask);
            for($i = 0; $i < strlen($data); $i++)
            {
                $frame[] = ord($data[$i]) ^ $mask[$i % 4];
            }
        }
        else
        {
            for($i = 0; $i < strlen($data); $i++)
            {
                $frame[] = ord($data[$i]);
            }
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
    protected function serveFlashPolicy()
    {
        $policy = '<?xml version="1.0"?>' . "\n";
        $policy .= '<!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">' . "\n";
        $policy .= '<cross-domain-policy>' . "\n";
        $policy .= '<allow-access-from domain="*" to-ports="*"/>' . "\n";
        $policy .= '</cross-domain-policy>' . "\n";
        socket_write($this->socket, $policy, strlen($policy));
        $this->onDisconnect();
    }

    # pretty iffy. the good stuff (draft specific code) is
    # from Simon Samtleben <web@lemmingzshadow.net>
    public function send($data)
    {

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
    public function onDisconnect()
    {
        if(is_null($this->socket)) return;

        # debugging
        $this->log('Disconnected', 'info');

        # in the case of a server, call the application
        # disconnection handler if defined
        if ($this->application) {
            $this->application->onDisconnect($this);
        }

        # remove client from server
        if ($this->server) {
            $this->server->removeClient($this->socket);
        }

        # close the socket
        socket_close($this->socket);
        $this->socket = null;
    }

    # WebSocket draft 76 handshake digest
    #  by Andrea Giammarchi
    #  see http://webreflection.blogspot.com/2010/06/websocket-handshake-76-simplified.html
    protected function securityDigest($key1, $key2, $key3)
    {
        return md5(pack('N', $this->keyToBytes($key1)) . pack('N', $this->keyToBytes($key2)) . $key3, true);
    }

    # WebSocket draft 76 handshake digest support function
    #  by Andrea Giammarchi
    #  see http://webreflection.blogspot.com/2010/06/websocket-handshake-76-simplified.html
    protected function keyToBytes($key)
    {
        return preg_match_all('#[0-9]#', $key, $number) && preg_match_all('# #', $key, $space) ? implode('', $number[0]) / count($space[0]) : '';
    }

    # basic logging function
    public function log($message, $type = 'info')
    {
        @socket_getpeername($this->socket, $addr, $port);
        $this->server->log('[client ' . $addr . ':' . $port . '] ' . $message, $type);
    }
}
