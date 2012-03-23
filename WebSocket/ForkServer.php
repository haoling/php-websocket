<?php

/**
 * WebSockets server use fork, 1 client with 1 process
 *
 * @author Aya Mishina <http://fei-yen.jp/maya/> (Initial Release)
 */
class WebSocketForkServer extends WebSocketServer
{
    protected $is_child = false;
    protected $ipc_socket = array();
    
    public function loop() {
        if($this->is_child) {
            //d(count($this->clients));
            if(($msg = fgets($this->ipc_socket)) != '') {
                // message from parent process
                list($opcode, $params) = explode("\0", trim($msg), 2);
                switch($opcode) {
                case 'DC':
                    parent::removeClient(trim($params));
                    if(! count($this->clients)) {
                        fclose($this->ipc_socket);
                        $this->log('exit');
                        exit;
                    }
                    break;
                }
            }
        } else {
            // Protect against Zombie children
            $pid = pcntl_wait($status, WNOHANG);
            if($pid > 0) {
                fclose($this->ipc_socket[$pid]);
                unset($this->ipc_socket[$pid]);
            }
            
            // check message from child processes
            $changed_sockets = $this->ipc_socket;
            @socket_select($changed_sockets, $write = NULL, $exceptions = NULL, 0);
            foreach ($changed_sockets as $socket) {
                $msg = fgets($socket);
                if($msg != '') {
                    list($opcode, $params) = explode("\0", trim($msg), 2);
                    switch($opcode) {
                    case 'DC':
                        $this->log('removeClient: ' . trim($params));
                        $this->removeClient(trim($params));
                        break;
                    }
                }
            }
        }
        
        return parent::loop();
    }
    
    
    protected function acceptClient($socket) {
        $this->log('acceptClient: ' . $socket);
        $client = new WebSocketUnhandshakedConnection($this, $socket);
        $this->clients[(int)$socket] = $client;

        // create sockets for IPC
        $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

        $pid = pcntl_fork();
        if($pid == -1) {
            throw new Exception('fork failure!');
        } elseif($pid == 0) {
            // child process
            $this->is_child = true;
            fclose($sockets[1]);
            socket_close($this->master);
            $this->ipc_socket = $sockets[0];
            $this->allsockets = array($socket);
            $this->clients = array((int)$socket => $client);
            
            // set ipc socket mode for non blocking
            stream_set_blocking($this->ipc_socket, 0);
        } else {
            // parent process
            fclose($sockets[0]);
            socket_close($socket);
            stream_set_blocking($sockets[1], 0);
            $this->ipc_socket[$pid] = $sockets[1];
        }
    }

    public function onTick() {
        if($this->is_child) return;
        return parent::onTick();
    }

    public function log($message, $type = 'info')
    {
        echo date('Y-m-d H:i:s') . '[pid'.($this->is_child?' ':'^').''.getmypid().']'
                . ' [' . ($type ? $type : 'error') . '] ' . $message . PHP_EOL;
    }

    public function removeClient($resource) {
        if($this->is_child) {
            //notify for parent process
            $this->sendMsgForParent('DC', array((int)$resource));
        } else {
            parent::removeClient($resource);
            $this->sendMsgForAllChilds('DC', array((int)$resource));
        }
    }
    
    protected function sendMsgForParent($opcode, array $params = array()) {
        if(! $this->is_child) return;
        fwrite($this->ipc_socket, sprintf("%s\0%s\n", $opcode, join("\0", $params)));
    }
    protected function sendMsgForAllChilds($opcode, array $params = array()) {
        if($this->is_child) return;
        foreach($this->ipc_socket as $socket) {
            @fwrite($socket, sprintf("%s\0%s\n", $opcode, join("\0", $params)));
        }
    }
}
