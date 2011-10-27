<?php
/*
 *
 */

namespace WebSocket\Application;

/**
 * @author Richard Fullmer <richard.fullmer@opensoftdev.com>
 */ 
interface ApplicationInterface
{
    public function onConnect($connection);

    public function onDisconnect($connection);

    public function onTick();

    public function onData($data, $client);
}
