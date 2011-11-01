<?php

namespace WebSocket;

use WebSocket\Application\ApplicationInterface;

/**
 * Simple WebSockets server
 *
 * @author Nico Kaiser <nico@kaiser.me>
 */
class Server extends Socket
{
    private $clients = array();

    private $applications = array();

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

        foreach ($this->applications as $application) {
            $application->onTick();
        }
        foreach ($changed_sockets as $socket) {
            if ($socket == $this->master) {
                if (($resource = socket_accept($this->master)) < 0) {
                    $this->log('Socket error: ' . socket_strerror(socket_last_error($resource)));
                    continue;
                } else {
                    $client = new Connection($this, $resource);
                    $this->clients[(int)$resource] = $client;
                    $this->allsockets[] = $resource;
                }
            } else {
                $client = $this->clients[(int)$socket];
                $bytes = @socket_recv($socket, $data, 4096, 0);
                if (!$bytes) {
                    $client->onDisconnect();
                    unset($this->clients[(int)$socket]);
                    $index = array_search($socket, $this->allsockets);
                    unset($this->allsockets[$index]);
                    unset($client);
                } else {
                    $client->onData($data);
                }
            }
        }
    }

    public function getApplication($key)
    {
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
        $client = $this->clients[$resource];
        unset($this->clients[$resource]);
        $index = array_search($resource, $this->allsockets);
        unset($this->allsockets[$index]);
        unset($client);
    }

    public function log($message, $type = 'info')
    {
        echo date('Y-m-d H:i:s') . ' [' . ($type ? $type : 'error') . '] ' . $message . PHP_EOL;
    }

}
