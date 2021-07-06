# HackTLS

THIS IS A WORK IN PROGRESS. IT DOES NOT WORK YET. 

Implementation of TLS v1.3 written in Hack.  
Makes use of both libsodium and OpenSSL for crypto help.  

# Protocol

This library *only* implements TLS v1.3 and not TLS v1.2. 

# Status

In Development. Not done. Do not use. Not secure yet (no certificate validation).  
You have been warned.

# Motivation

Hack now has TCP sockets built into the HSL (Hack Standard Library) which means we can now use a Hack-first approach a la `async`/`await` to implement this.  
This library wraps the plain TCP socket with a new TLS socket that returns after establishing the handshake. From the developer perspective, use this socket as you would the normal TCP one.  
