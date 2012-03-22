<?php

/**
 * WebSocket Server Application
 * 
 * @author Nico Kaiser <nico@kaiser.me>
 * @author Aya Mishina <http://fei-yen.jp/maya/> (Define abstract class)
 */
abstract class WebSocketApplication extends WebSocket implements WebSocketApplicationInterface
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

    public function onConnect(WebSocketConnection $connection) { }

    public function onDisconnect(WebSocketConnection $connection) { }
    
    public function onTick() { }

    public function onData($data, WebSocketConnection $client) { }
}