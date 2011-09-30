PHP WebSocket
=============

Improved version of Nico Kaiser's PHP 5.3 WebSocket server implementation.

WebSockets are a TCP-like layer on top of HTTP, defined at
http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol
The standard is still evolving and the IETF has not yet
standardized the specification.

While looking for PHP web sockets support, I found some
improved PHP WebSocket code online at Simon Samtleben's site:
 http://lemmingzshadow.net/files/2011/09/Connection.php.txt
 http://lemmingzshadow.net/files/2011/09/client.php.txt

This branch includes the client support (upgraded significantly with
bugfixes and additional features).

It also aims to integrate the client and server support with a more elegant
solution for dealing with legacy protocol versions.

An event-based callback interface may be defined.

Free to pitch in and help out.
