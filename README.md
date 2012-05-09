# dht

[DHT](http://bittorrent.org/beps/bep_0005.html "BitTorrent DHT spec") implementation.

Note: This branch is forked from stbuehler's mainline. It uses 'browserify' to create bundle.js, a version which can run
inside a browser.

To do this meant taking out all references to actual sockets, so they can eventually be replaced with WebRTC PeerConnections.

## install

	npm install dht

## usage

See example.js

## status

Local hashtable not implemented (needs to handle timeout of peers); announce not tested.
