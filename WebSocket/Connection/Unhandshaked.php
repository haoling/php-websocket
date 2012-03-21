<?php

namespace WebSocket\Connection;

use Exception;

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
class Unhandshaked extends \WebSocket\Connection
{
    # post-connection server handshake function
    public function handshake($data) {
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
            $this->onDisconnect();
            return false;
        }
        $path = $matches[1];

        # validate application from supplied path
        $this->application = $this->server->getApplication(substr($path, 1)); // e.g. '/echo'
        if (! $this->application) {
            $this->log('Invalid application: ' . $path);
            $this->onDisconnect();
            return false;
        }
        
        // switch class
        $class = $this->application->getOption('ConnectionClass', '\\WebSocket\\Connection');
        $conobj = new $class($this->server, $this->socket);
        $conobj->application = $this->application;

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
            $this->log('draft 10', 'info');
            $conobj->draft = 10;
            $secKey = $headers['Sec-WebSocket-Key'];
            $secAccept = base64_encode(pack('H*', sha1($secKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
            $response = "HTTP/1.1 101 Switching Protocols\r\n";
            $response.= "Upgrade: websocket\r\n";
            $response.= "Connection: Upgrade\r\n";
            $response.= "Sec-WebSocket-Accept: " . $secAccept .  "\r\n";
            $response.= "Sec-WebSocket-Protocol: " .  substr($path, 1) . "\r\n\r\n";
            socket_write($conobj->socket, $response, strlen($response));
            $conobj->handshaked = true;
            $conobj->log('Handshake sent');
            $conobj->application->onConnect($conobj);
            return $conobj;
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
        $conobj->log("THIS IS HASH '$hash'");
        $hash = base64_encode(sha1($hash, true));
        $def_header = array(
            'Sec-WebSocket-Accept' => $hash,
        );
        }
        else if (array_key_exists('Sec-WebSocket-Key1', $headers)) {
            // draft-76 : Requires a 'Security Digest' header to be present.
            $conobj->draft = 76;
            $this->log('draft 76', 'info');
            $def_header = array(
                'Sec-WebSocket-Origin' => $origin,
                'Sec-WebSocket-Location' => "ws://{$host}{$path}"
            );
            $digest = $conobj->securityDigest($headers['Sec-WebSocket-Key1'], $headers['Sec-WebSocket-Key2'], $key3);
        }
        else {
            // draft-75 : No 'Security Digest' header.
            $conobj->draft = 75;
            $this->log('draft 75', 'info');
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

        socket_write($conobj->socket, $upgrade, strlen($upgrade));
        
        $conobj->handshaked = true;
        $conobj->log('Handshake sent');

        $conobj->application->onConnect($conobj);

        return $conobj;
    }
}
