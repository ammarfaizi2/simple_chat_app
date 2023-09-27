// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

static const char bind_addr[] = "127.0.0.1";
static const unsigned short bind_port = 8787;

struct data {
	uint16_t	len;
	char		msg[];
};

static int create_socket(void)
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
	if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
		printf("Invalid bind address: %s\n", bind_addr);
		return -1;
	}
	addr.sin_port = htons(bind_port);

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	ret = listen(fd, 10);
	if (ret < 0) {
		perror("listen");
		close(fd);
		return -1;
	}

	printf("Listening on %s:%hu...\n", bind_addr, bind_port);
	return fd;
}

static int send_data_to_server(int client_fd, struct data *d)
{
	ssize_t ret;

	ret = send(client_fd, d, sizeof(*d) + d->len, 0);
	if (ret < 0) {
		perror("send");
		return -1;
	}

	return 0;
}

static int get_input_and_send(int client_fd, struct data *d)
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
	send_data_to_server(client_fd, d);
	return 0;
}

static void interpret_client_message(struct data *d)
{
	d->len = htons(d->len);
	d->msg[d->len] = '\0';
	printf("Client said: %s\n", d->msg);
}

static void receive_data(int client_fd)
{
	struct data *d;
	ssize_t ret;

	d = malloc(sizeof(*d) + 65535);
	if (!d) {
		perror("malloc");
		return;
	}

	while (1) {
		printf("Waiting message from the client...\n");
		ret = recv(client_fd, d, sizeof(*d) + 65535 - 1, 0);
		if (ret < 0) {
			perror("recv");
			break;
		}

		if (ret == 0) {
			printf("Client disconnects\n");
			break;
		}

		interpret_client_message(d);
		if (get_input_and_send(client_fd, d))
			break;
	}
	free(d);
}

static int run_event_loop(int tcp_fd)
{
	struct sockaddr_in addr;
	socklen_t addr_len;
	int client_fd;
	char str_addr[INET_ADDRSTRLEN];
	unsigned short port;

	printf("Waiting for connection...\n");
	addr_len = sizeof(addr_len);
	client_fd = accept(tcp_fd, (struct sockaddr *)&addr, &addr_len);
	if (client_fd < 0) {
		perror("accept");
		return -1;
	}

	inet_ntop(AF_INET, &addr.sin_addr, str_addr, sizeof(str_addr));
	port = ntohs(addr.sin_port);

	printf("Accepted a client with address %s and port %hu\n", str_addr, port);
	receive_data(client_fd);
	close(client_fd);
	return 0;
}

static void start_event_loop(int tcp_fd)
{
	int ret;

	while (1) {
		ret = run_event_loop(tcp_fd);
		if (ret < 0)
			break;
	}
}

int main(void)
{
	int tcp_fd;

	tcp_fd = create_socket();
	if (tcp_fd < 0)
		return 1;

	start_event_loop(tcp_fd);
	close(tcp_fd);
	return 0;
}
