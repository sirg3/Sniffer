Sniffer
=======

Sniffer is an unoriginally-named packet sniffer with the unique ability of determining which application a packet is coming from (or going to). At the moment it is little more than a prototype to prove that the idea works.

Internals
---------

Like many packet sniffers, Sniffer is split into two applications: the GUI and the capture tool. The GUI launches the capture tool as root when needed and communicates with it via a CFMessagePort.

The capture tool uses `libpcap` to do the actual packet capturing. When `libpcap` tells the capture tool about a packet, it uses `libproc` to search through all of the running processes, trying to find a process with a socket that matches. Since multiple processes can have access to the file descriptor for a socket, we simply return the first one found. This may limit the usefulness of the tool for your needs, but works well in most cases.

To Do
-----

* remove hardcoded use of "en1" from the capture tool
* add more endpoint matching (TCP/IPv6, UDP, etc)
* remove Hex Fiend binary from the repository
* provide a decent user interface
* export capture as pcap

License
-------

Sniffer is released under the GPLv2 license.

Redistribution
--------------

Even though it is perfectly legal under the license, I urge you not to distribute binaries of Sniffer. The problem is that `libproc` is not ABI-compatible across Mac OS X releases (or even architectures of the same release). Distributing binaries could result in versions of the application that simply crash when launched on any version of the OS other than the one you built for.