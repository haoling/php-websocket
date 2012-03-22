<?php
/*
 *
 */

/**
 * @author Richard Fullmer <richard.fullmer@opensoftdev.com>
 */ 
interface WebSocketApplicationInterface
{
    public function onConnect(WebSocketConnection $connection);

    public function onDisconnect(WebSocketConnection $connection);

    public function onTick();

    public function onData($data, WebSocketConnection $client);
}
