<?php

namespace WebSocket;

use WebSocket\Application\ApplicationInterface;

/**
 * Simple WebSockets server
 *
 * @author Nico Kaiser <nico@kaiser.me>
 * @author Aya Mishina <http://fei-yen.jp/maya/> (Can use own Connection class. To use "$application->setOption('ConnectionClass', 'MyClass');")
 */
class Server extends Socket
{
    protected $clients = array();

    protected $applications = array();

    public function __construct($host = 'localhost', $port = 8000, $max = 100)
    {
        parent::__construct($host, $port, $max);

        $this->log('Server created');
    }

    public function run()
    {
        while (true) {
            $this->loop();
        }
    }

    public function loop()
    {
        $changed_sockets = $this->allsockets;
        @socket_select($changed_sockets, $write = NULL, $exceptions = NULL, 0);

        $this->onTick();
        foreach ($changed_sockets as $socket) {
            if ($socket == $this->master) {
                if (($resource = socket_accept($this->master)) < 0) {
                    $this->log('Socket error: ' . socket_strerror(socket_last_error($resource)));
                    continue;
                } else {
                    $this->acceptClient($resource);
                }
            } else {
                $client = $this->clients[(int)$socket];
                $bytes = @socket_recv($socket, $data, 4096, 0);
                if (!$bytes) {
                    $client->onDisconnect();
                } elseif(! $client->isHandshaked()) {
                    $client = $client->handshake($data);
                    if(! $client) {
                        $this->removeClient($socket);
                    } else {
                        $this->clients[$socket] = $client;
                    }
                } else {
                    $client->onData($data);
                }
            }
        }
    }

    protected function acceptClient($socket) {
        $this->log('acceptClient: ' . $socket);
        $client = new Connection\Unhandshaked($this, $socket);
        $this->clients[(int)$socket] = $client;
        $this->allsockets[] = $socket;
    }

    public function getApplication($key)
    {
        settype($key, 'string');
        if(! isset($key[0])) return false;
        if (array_key_exists($key, $this->applications)) {
            return $this->applications[$key];
        } else {
            return false;
        }
    }

    public function registerApplication($key, ApplicationInterface $application)
    {
        $this->applications[$key] = $application;
    }

    public function removeClient($resource)
    {
        $this->log('removeClient: ' . $resource);
        if(! isset($this->clients[(int)$resource]) || ! in_array($resource, $this->allsockets)) return;
        $client = $this->clients[(int)$resource];
        unset($this->clients[(int)$resource]);
        $index = array_search($resource, $this->allsockets);
        unset($this->allsockets[$index]);
        unset($client);
    }

    public function log($message, $type = 'info')
    {
        echo date('Y-m-d H:i:s') . ' [' . ($type ? $type : 'error') . '] ' . $message . PHP_EOL;
    }

    public function onTick() {
        foreach ($this->applications as $application) {
            $application->onTick();
        }
    }

}
