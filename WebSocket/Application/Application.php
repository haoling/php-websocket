<?php

namespace WebSocket\Application;

use WebSocket\Connection;

/**
 * WebSocket Server Application
 * 
 * @author Nico Kaiser <nico@kaiser.me>
 */
abstract class Application implements ApplicationInterface
{
    protected static $instances = array();
    
    /**
     * Singleton 
     */
    protected function __construct() { }

    final private function __clone() { }
    
    final public static function getInstance()
    {
        $calledClassName = get_called_class();
        if (!isset(self::$instances[$calledClassName])) {
            self::$instances[$calledClassName] = new $calledClassName();
        }

        return self::$instances[$calledClassName];
    }

    public function onConnect(Connection $connection) { }

    public function onDisconnect(Connection $connection) { }
    
    public function onTick() { }

    public function onData($data, Connection $client) { }
}