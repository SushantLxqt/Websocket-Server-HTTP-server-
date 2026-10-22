#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define PORT 8080
#define MAX_CLIENTS 2
#define BUFFER_SIZE 65536
#define MAX_PAYLOAD (BUFFER_SIZE - 14)
/*Separating 
// understood how bitwise operator works:
    know how to convert hexa to binary and binary to decimal and vice-versa
1) Sending Bytes all over the TCP
2) Get the PayLoad Length
3) Parse the Websocket Frame
4) Perform the Handshake
5) Send Unmasked Websocket Frame frame to a Client(N)
*/
//Parsing Time
// First step
int send_all(int fd, const unsigned char *data, size_t length){
    size_t sent = 0; // To have the information about how much data is sent already
    while(sent < length){
        ssize_t n = send(fd, data + sent, length - sent, MSG_NOSIGNAL);
        if(n < 0){
            if(errno == EINTR){
                continue;
            }
            return -1;
        }
        if (n == 0){
            return -1;
        }
        sent += (size_t)n;
        
    }
    return 0;    
}
/* 
1. Read the payload length from a WebSocket header
Returns:
0 = length successfully read
1 = more bytes needed
-1 = invalid length */
int get_payload_length(
    const unsigned char *frame, size_t available, uint64_t *payload_length, size_t *length_bytes)
{   // According to RFC-6455 protocol
    if (available < 2)
        return 1;
    unsigned char len = frame[1] & 0x7F;
    if (len < 126) {
        *payload_length = len;
        *length_bytes = 0;
        return 0;
    }
    if(len == 126){
        if(available < 4)
            return 1;
        *payload_length = ((uint64_t)frame[2] << 8) | (uint64_t)frame[3];

        // Reject non-minimal encoding.
        if (*payload_length < 126)
            return -1;

        *length_bytes = 2;
        return 0;
    }

    if (available < 10)
        return 1;

    uint64_t length = 0;

    for (int i = 0; i < 8; i++)
        length = (length << 8) | frame[2 + i];

    // RFC 6455 requires the highest bit to be zero.
    if (length & (UINT64_C(1) << 63))
        return -1;

    // Reject non-minimal encoding.
    if (length <= 65535)
        return -1;

    *payload_length = length;
    *length_bytes = 8;
    return 0;
}
// Parsing the websocket frame
int parse_websocket_frame(const unsigned char* frame,size_t available, uint8_t *opcode, const unsigned char**payload,uint64_t *payload_length){
    if(available < 2){
        return 1;
    }
    // Check if frame[0] == 128 that is 0x80 so it means the value will be 128 -> 0x80 and 128 | 0x80!=0 that is true so it will return 1
    int fin = (frame[0] & 0x80) != 0;
    if(frame[0] & 0x70)
        return -1;

    *opcode = frame[0] & 0x0F;
    //Support for text, binary, close ping and pong
    if(*opcode != 0x1 &&
        *opcode != 0x2 &&
        *opcode != 0x8 &&
        *opcode != 0x9 &&
        *opcode != 0xA){
        return -1;
    }

    if(!fin)
        return -1;

    // Browser to server frames must be me masked ( Javascript websocket does that already)
    if(!(frame[1] &0x80))
        return -1;

    size_t length_bytes =0;
    //Get Result
    int result = get_payload_length(frame,available,payload_length, &length_bytes);
    if (result!=0){
        return result;
    }

    //Control frames have maximum payload of 125bytes
    if(*opcode >=0x8 && *payload_length > 125)
        return -1;
    // Prevent oversized frames from filling memory indefinitely.
    if (*payload_length > MAX_PAYLOAD)
        return -1;

    size_t header_length = 2 + length_bytes + 4;

    if (available < header_length)
        return 1;

    size_t payload_size = (size_t)*payload_length;

    if (payload_size > SIZE_MAX - header_length)
        return -1;

    size_t total_length = header_length + payload_size;

    if (available < total_length)
        return 1;

    *payload = frame + header_length;

    return 0;

}

// Now, HTTP handshake
/* 0-> HandShake Completed, 1->Request Incomplete, -1-> invalid request or socket error*/
int websocket_handshake(int client_fd,unsigned char*buffer,size_t*buffer_length){
    buffer[*buffer_length] = '\0';
    char *end = strstr((char *)buffer, "\r\n\r\n");

    if(end == NULL){
        if(*buffer_length >= BUFFER_SIZE - 1)
            return -1;
        return 1;
    }
    size_t http_length = (size_t)(end -(char *)buffer) + 4;

    // Basic Validation of HTTP request
    if (strncmp((char *)buffer, "GET ", 4) != 0 ||
        strstr((char *)buffer, "Upgrade: websocket\r\n") == NULL ||
        strstr((char *)buffer, "Connection: Upgrade") == NULL) {
        return -1;
    }
    char *key_line = strstr(
        (char *)buffer,
        "Sec-WebSocket-Key:"
    );

    if (key_line == NULL || key_line >= end)
        return -1;

    key_line += strlen("Sec-WebSocket-Key:");

    while (*key_line == ' ' || *key_line == '\t')
        key_line++;

    char key[128];
    size_t key_length = 0;

    while (key_line[key_length] != '\r' &&
           key_line[key_length] != '\n' &&
           key_line[key_length] != '\0') {
        if (key_length >= sizeof(key) - 1)
            return -1;

        key[key_length] = key_line[key_length];
        key_length++;
    }

    key[key_length] = '\0';

    if (key_length == 0)
        return -1;

    // RFC 6455 GUID.
    const char *guid =
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    char combined[256];

    int combined_length = snprintf(
        combined,
        sizeof(combined),
        "%s%s",
        key,
        guid
    );

    if (combined_length < 0 ||
        (size_t)combined_length >= sizeof(combined)) {
        return -1;
    }
    // Using OpenSSL -SHA1 ( Not that secure still) -> cryptographic hash function
    // Sec-WebSocket-Accept = Base64(SHA1(key + GUID)).
    unsigned char digest[SHA_DIGEST_LENGTH];

    SHA1(
        (const unsigned char *)combined,
        (size_t)combined_length,
        digest
    );

    unsigned char accept_key[EVP_ENCODE_LENGTH(
        SHA_DIGEST_LENGTH
    )];

    int encoded_length = EVP_EncodeBlock(
        accept_key,
        digest,
        SHA_DIGEST_LENGTH
    );

    if (encoded_length <= 0)
        return -1;

    char response[512];

    int response_length = snprintf(
        response,
        sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %.*s\r\n"
        "\r\n",
        encoded_length,
        accept_key
    );

    if (response_length < 0 ||
        (size_t)response_length >= sizeof(response)) {
        return -1;
    }

    if (send_all(
        client_fd,
        (const unsigned char *)response,
        (size_t)response_length
    ) == -1) {
        return -1;
    }

    printf("WebSocket handshake completed!\n");

    // Remove the HTTP request, preserving any frame bytes
    // received after the HTTP headers.
    memmove(
        buffer,
        buffer + http_length,
        *buffer_length - http_length
    );

    *buffer_length -= http_length;
    buffer[*buffer_length] = '\0';

    return 0;
}

// --------------------------------------------------
// Send an unmasked WebSocket frame to a client
// --------------------------------------------------

int send_websocket_frame(
    int client_fd,
    uint8_t opcode,
    const unsigned char *payload,
    size_t payload_length
) {
    unsigned char header[10];
    size_t header_length;

    header[0] = 0x80 | (opcode & 0x0F);

    if (payload_length <= 125) {
        header[1] = (unsigned char)payload_length;
        header_length = 2;
    }
    else if (payload_length <= 65535) {
        header[1] = 126;
        header[2] = (unsigned char)(payload_length >> 8);
        header[3] = (unsigned char)payload_length;
        header_length = 4;
    }
    else {
        header[1] = 127;

        for (int i = 0; i < 8; i++) {
            header[2 + i] =
                (unsigned char)(
                    ((uint64_t)payload_length) >> (56 - 8 * i)
                );
        }

        header_length = 10;
    }

    if (send_all(client_fd, header, header_length) == -1)
        return -1;

    if (payload_length > 0 &&
        send_all(client_fd, payload, payload_length) == -1) {
        return -1;
    }

    return 0;
}

static int send_system_message(int fd, const char *message) {
    return send_websocket_frame(fd, 0x1,
        (const unsigned char *)message, strlen(message));
}

// Creating a struct to Store Everything 
struct sockaddr_in address;
// Main function
int main(void)
{
    int server_fd, client_a, client_b;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;

    setsockopt(
        server_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &reuse,
        sizeof(reuse)
    );

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(
        server_fd,
        (struct sockaddr *)&address,
        sizeof(address)
    ) == -1) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) == -1) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("WebSocket server listening on port %d\n", PORT);

    // Keep server_fd as the listening socket.
    // Each accepted connection gets its own client descriptor.
    client_a = -1;
    client_b = -1;

    int clients[MAX_CLIENTS] = { -1, -1 };
    int upgraded[MAX_CLIENTS] = { 0, 0 };

    unsigned char buffers[MAX_CLIENTS][BUFFER_SIZE];
    size_t buffer_lengths[MAX_CLIENTS] = { 0, 0 };

    while (1) {
        fd_set read_fds;

        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);

        int max_fd = server_fd;

        if (client_a != -1) {
            FD_SET(client_a, &read_fds);
            if (client_a > max_fd)
                max_fd = client_a;
        }

        if (client_b != -1) {
            FD_SET(client_b, &read_fds);
            if (client_b > max_fd)
                max_fd = client_b;
        }

        int ready = select(
            max_fd + 1,
            &read_fds,
            NULL,
            NULL,
            NULL
        );

        if (ready == -1) {
            if (errno == EINTR)
                continue;

            perror("select");
            break;
        }

        // Accept a new TCP connection.
        if (FD_ISSET(server_fd, &read_fds)) {
            int new_fd = accept(server_fd, NULL, NULL);

            if (new_fd == -1) {
                perror("accept");
            }
            else if (new_fd >= FD_SETSIZE) {
                fprintf(stderr, "Socket exceeds FD_SETSIZE\n");
                close(new_fd);
            }
            else if (client_a == -1) {
                client_a = new_fd;
                clients[0] = new_fd;
                upgraded[0] = 0;
                buffer_lengths[0] = 0;

                printf("Client A connected via TCP.\n");
            }
            else if (client_b == -1) {
                client_b = new_fd;
                clients[1] = new_fd;
                upgraded[1] = 0;
                buffer_lengths[1] = 0;

                printf("Client B connected via TCP.\n");
            }
            else {
                printf("Maximum clients reached.\n");
                close(new_fd);
            }
        }

        // Handle incoming data from each client.
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int fd = clients[i];

            if (fd == -1 || !FD_ISSET(fd, &read_fds))
                continue;

            size_t used = buffer_lengths[i];

            if (used >= BUFFER_SIZE - 1) {
                printf("Client buffer full; closing connection.\n");
                goto disconnect_client;
            }

            ssize_t n = recv(
                fd,
                buffers[i] + used,
                BUFFER_SIZE - 1 - used,
                0
            );

            if (n <= 0) {
                if (n < 0 && errno == EINTR)
                    continue;

                printf("Client %c disconnected.\n", 'A' + i);
                goto disconnect_client;
            }

            buffer_lengths[i] += (size_t)n;
            buffers[i][buffer_lengths[i]] = '\0';

            // Step 1: HTTP handshake.
            if (!upgraded[i]) {
                int result = websocket_handshake(
                    fd,
                    buffers[i],
                    &buffer_lengths[i]
                );

                if (result == 1)
                    continue;

                if (result == -1) {
                    fprintf(stderr, "Invalid WebSocket handshake.\n");
                    goto disconnect_client;
                }

                upgraded[i] = 1;
                printf("Client %c upgraded to WebSocket.\n", 'A' + i);

                char role_message[32];
                snprintf(role_message, sizeof(role_message), "SYS:ROLE:%c", 'A' + i);
                if (send_system_message(fd, role_message) == -1)
                    goto disconnect_client;

                int other = 1 - i;
                if (clients[other] != -1 && upgraded[other]) {
                    if (send_system_message(clients[0], "SYS:READY") == -1 ||
                        send_system_message(clients[1], "SYS:READY") == -1)
                        goto disconnect_client;
                } else {
                    if (send_system_message(fd, "SYS:WAITING") == -1)
                        goto disconnect_client;
                }
            }

            // Step 2: Parse every complete frame in the buffer.
            while (buffer_lengths[i] > 0) {
                uint8_t opcode;
                const unsigned char *payload;
                uint64_t payload_length;

                int result = parse_websocket_frame(
                    buffers[i],
                    buffer_lengths[i],
                    &opcode,
                    &payload,
                    &payload_length
                );

                if (result == 1)
                    break;  // Wait for more TCP bytes.

                if (result == -1) {
                    fprintf(stderr, "Invalid/unsupported WebSocket frame.\n");
                    goto disconnect_client;
                }

                size_t header_length =
                    (size_t)(payload - buffers[i]);

                size_t frame_length =
                    header_length + (size_t)payload_length;

                // Unmask the payload in place.
                const unsigned char *mask_key = payload - 4;

                for (uint64_t j = 0; j < payload_length; j++) {
                    buffers[i][header_length + (size_t)j] ^=
                        mask_key[j % 4];
                }

                unsigned char *message =
                    buffers[i] + header_length;

                // Close frame.
                if (opcode == 0x8) {
                    send_websocket_frame(
                        fd, 0x8, message, (size_t)payload_length
                    );

                    goto disconnect_client;
                }

                // Ping -> Pong.
                if (opcode == 0x9) {
                    if (send_websocket_frame(
                        fd, 0xA, message, (size_t)payload_length
                    ) == -1) {
                        goto disconnect_client;
                    }
                }

                // Ignore Pong frames.
                if (opcode == 0xA) {
                    // No action required.
                }

                // Text or binary message.
                if (opcode == 0x1 || opcode == 0x2) {
                    int other = 1 - i;
                    int target = clients[other];

                    // Messages are allowed only when both clients have
                    // completed the WebSocket handshake.
                    if (target == -1 || !upgraded[other]) {
                        send_system_message(fd, "SYS:WAITING");
                        memmove(
                            buffers[i],
                            buffers[i] + frame_length,
                            buffer_lengths[i] - frame_length
                        );
                        buffer_lengths[i] -= frame_length;
                        buffers[i][buffer_lengths[i]] = '\0';
                        continue;
                    }

                    printf(
                        "Client %c sent %llu payload bytes.\n",
                        'A' + i,
                        (unsigned long long)payload_length
                    );

                    if (send_websocket_frame(
                        target,
                        opcode,
                        message,
                        (size_t)payload_length
                    ) == -1) {
                        if (target == fd)
                            goto disconnect_client;

                        // The other client's connection may have failed.
                        fprintf(stderr, "Could not relay to other client.\n");
                    }
                }

                // Remove the processed frame, preserving any
                // following frame already received from TCP.
                memmove(
                    buffers[i],
                    buffers[i] + frame_length,
                    buffer_lengths[i] - frame_length
                );

                buffer_lengths[i] -= frame_length;
                buffers[i][buffer_lengths[i]] = '\0';
            }

            continue;

        disconnect_client:
            close(fd);

            if (clients[1 - i] != -1 && upgraded[1 - i])
                send_system_message(clients[1 - i], "SYS:PEER_LEFT");

            clients[i] = -1;
            upgraded[i] = 0;
            buffer_lengths[i] = 0;

            if (i == 0)
                client_a = -1;
            else
                client_b = -1;
        }
    }

    if (client_a != -1)
        close(client_a);

    if (client_b != -1)
        close(client_b);

    close(server_fd);

    return 0;
}