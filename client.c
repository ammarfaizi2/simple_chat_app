// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

static const char server_addr[] = "127.0.0.1";
static const unsigned short server_port = 8787;

struct data {
	uint16_t	len;
	char		msg[];
};

static int create_socket_and_connect(void)
{
	struct sockaddr_in addr;
	int ret;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (inet_pton(AF_INET, server_addr, &addr.sin_addr) != 1) {
		printf("Invalid server address: %s\n", server_addr);
		close(fd);
		return -1;
	}
	addr.sin_port = htons(server_port);

	printf("Connecting to %s:%hu...\n", server_addr, server_port);
	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		perror("connect");
		close(fd);
		return -1;
	}

	printf("Successfully connected to the server!\n");
	return fd;
}

static int send_data_to_server(int tcp_fd, struct data *d)
{
	ssize_t ret;

	ret = send(tcp_fd, d, sizeof(*d) + d->len, 0);
	if (ret < 0) {
		perror("send");
		return -1;
	}

	return 0;
}

static int get_input_and_send(int tcp_fd, struct data *d)
{
	size_t len;

	printf("Enter your message: ");
	if (!fgets(d->msg, 65535, stdin)) {
		printf("EOF!\n");
		return -1;
	}

	len = strlen(d->msg);
	if (d->msg[len - 1] == '\n') {
		d->msg[len - 1] = '\0';
		len--;
	}

	if (len == 0)
		return 0;

	if (!strcmp(d->msg, "exit"))
		return -1;

	d->len = htons((uint16_t)len);
	send_data_to_server(tcp_fd, d);
	return 0;
}

static void interpret_server_message(struct data *d)
{
	d->len = htons(d->len);
	d->msg[d->len] = '\0';
	printf("Server said: %s\n", d->msg);
}

static int recv_data_from_server(int tcp_fd, struct data *d)
{
	ssize_t ret;

	printf("Waiting message from the server...\n");
	ret = recv(tcp_fd, d, sizeof(*d) + 65535 - 1, 0);
	if (ret < 0) {
		perror("recv");
		return -1;
	}

	if (ret == 0) {
		printf("Server disconnected!\n");
		return -1;
	}

	return 0;
}

static int start_chat(int tcp_fd)
{
	struct data *d;

	d = malloc(sizeof(*d) + 65535);
	if (!d) {
		perror("malloc");
		return -1;
	}

	printf("Send 'exit' or press CTRL + D to end the chat.\n\n");
	while (1) {
		if (get_input_and_send(tcp_fd, d))
			break;

		if (recv_data_from_server(tcp_fd, d))
			break;

		interpret_server_message(d);
	}
	free(d);
	return 0;
}

int main(void)
{
	int tcp_fd;

	tcp_fd = create_socket_and_connect();
	if (tcp_fd < 0)
		return 1;

	start_chat(tcp_fd);
	close(tcp_fd);
	return 0;
}
