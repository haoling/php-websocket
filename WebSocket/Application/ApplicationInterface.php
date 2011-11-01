<?php
/*
 *
 */

namespace WebSocket\Application;

use \WebSocket\Connection;

/**
 * @author Richard Fullmer <richard.fullmer@opensoftdev.com>
 */ 
interface ApplicationInterface
{
    public function onConnect(Connection $connection);

    public function onDisconnect(Connection $connection);

    public function onTick();

    public function onData($data, Connection $client);
}
