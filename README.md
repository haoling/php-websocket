PHP WebSocket
=============

Branch of Nico Kaiser's PHP 5.3 WebSocket server implementation.

WebSockets are a TCP-like layer on top of HTTP, defined at
http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol
The standard is still evolving and the IETF has not yet
standardized the specification.

While looking for PHP web sockets support, I found some
improved PHP WebSocket code online at Simon Samtleben's site:
 http://lemmingzshadow.net/files/2011/09/Connection.php.txt
 http://lemmingzshadow.net/files/2011/09/client.php.txt

That's been rolled in to this branch but not yet fully 
integrated.

Aims of this branch:
 * Add client support
 * Improve server support
 * Integrate the implementation of the two across disparate protocol versions
 * Remove \Annoying\OOPHP\Lameness\Making\One\Tiresome()

Known issues with the original and current codebase:
 * Single frame messages only (FIN flag must be set)
 * Decoding of unmasked data (server to client frames)
   is not supported (soon!)
 * Short messages only (no 64-bit length specification)

Feel free to pitch in and help out.
