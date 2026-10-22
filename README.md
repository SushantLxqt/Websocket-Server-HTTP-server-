Note : This is not made by me alone ( Some Help of Socket and Websocket scripts of others etc)

Small note that i made, for you to understand the code (Bitwise Operator is must needed and Knowledge about most Dynamic Memory Functions and strings related function and ofcourse networking as well!)

#First, it was just a TCP server now I made it work with websocked of js. I had to parse the websocketframe myself understanding how each system works.For normal people to test it out, websocket was necesaary for it to work with WebBrowser

1) What is sockaddr_in struct?
-> sockaddr_in is a System-Defined structure type of (sys/socket.h -> socket header file) that is used to store the IPv4 addresses and port Numbers.
2) What is sin_family, sin_port, sin_addr?
-> sin_family is to store the Ipv4 address that is AF_INET, sin_port is to store the port must be 16bit in this case we are using 8080, sin_addr is to store the address structure that is SOCK_STREAM for IPV4
3) What is hton()?
-> It stands for Host to Network Short (htons), it is used to convert the Basic 16 bit integer to big-endian that is understood by network. eg : hton(8080)
4) Why do we use INADDR_ANY while adding address structure in address struct?
-> We are building a server that will accept any client, on any bit that is 0.0.0.0 also use htonl(INADDR_ANY)
5) What is the use of bind()?
-> bind() is used to give the socket that we namaed 'server_fd' an actual identity like assigning the Ports and Address in the socket.
6) Why listen(server_fd, 2)?
-> We are now listening on the part '8080' and 2 that is the amount of client requests at a time.
7) Why client_a = accept(server_fd, NULL, NULL)?
-> Accept requires three arguments, first one is the socket that we passed second and third is the address (addr) and address lenth (addr len), both are optional for us, we don't want to specifiy the address for OS to store the value or the pointer, So instead wrote NULL for both.
8)What is fd_set and FD_SET(),FD_ZERO()?
-> fd_set is a struct type of the header select.h ( that is pre-installed in UNIX based operating system). FD_ZERO() is used to clear the fd(file descriptor) 0> readfds.
9) When masked and unmasked?
-> WebsocketFrame sent from Client -> Server must be masked ( web-browser does that ), WebsocketFrame sent from Server - Client must be unmasked ( We do that, as we are hosting the http server)
10)
