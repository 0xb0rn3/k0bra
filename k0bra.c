#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <signal.h>
#include <time.h>

/* Core configuration constants */
#define MAX_IP_STR 16
#define MAX_THREADS 256
#define DEFAULT_TIMEOUT_SEC 1
#define DEFAULT_TIMEOUT_USEC 500000
#define MAX_PORTS 65535
#define MAX_INTERFACES 64
#define INTERFACE_NAME_LEN 16
#define BANNER_PORT_TIMEOUT 3
#define MAX_SERVICE_NAME 32

/* Visual enhancements with color codes */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_WHITE   "\033[1;37m"

/* Service mapping structure */
typedef struct {
    int port;
    char service[MAX_SERVICE_NAME];
} port_service;

/* Default service mappings */
const port_service DEFAULT_PORTS[] = {
    {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
    {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
    {443, "HTTPS"}, {445, "SMB"}, {3306, "MySQL"}, {5432, "PostgreSQL"},
    {3389, "RDP"}, {8080, "HTTP-Proxy"}, {27017, "MongoDB"}
};

const int DEFAULT_PORTS_COUNT = sizeof(DEFAULT_PORTS) / sizeof(port_service);

/* Network interface information */
typedef struct {
    char name[INTERFACE_NAME_LEN];
    char ip[MAX_IP_STR];
    unsigned char mac[6];
} interface_info;

/* Host scanning results */
typedef struct {
    char ip[MAX_IP_STR];
    unsigned char mac[6];
    struct {
        int port;
        char service[MAX_SERVICE_NAME];
        char banner[256];
    } ports[MAX_PORTS];
    int port_count;
    int is_alive;
    time_t response_time;
} host_result;

/* Thread arguments */
typedef struct {
    char *target_ip;
    int start_port;
    int end_port;
    host_result *host;
    struct timeval timeout;
} scan_args;

/* Global variables */
host_result *results = NULL;
int total_hosts = 0;
pthread_mutex_t results_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t scanning = 1;

void show_banner() {
    printf("\n%s", COLOR_CYAN);
    printf("    ██╗  ██╗ ██████╗ ██████╗ ██████╗  █████╗ \n");
    printf("    ██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗\n");
    printf("    █████╔╝ ██║   ██║██████╔╝██████╔╝███████║\n");
    printf("    ██╔═██╗ ██║   ██║██╔══██╗██╔══██╗██╔══██║\n");
    printf("    ██║  ██╗╚██████╔╝██████╔╝██║  ██║██║  ██║\n");
    printf("    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝%s\n", COLOR_RESET);
    printf("%s    Advanced Network Scanner v2.0%s\n\n", COLOR_WHITE, COLOR_RESET);
}

void calculate_network_range(const char *cidr, uint32_t *start_ip, uint32_t *end_ip) {
    char ip_str[MAX_IP_STR];
    int prefix;
    sscanf(cidr, "%[^/]/%d", ip_str, &prefix);
    
    struct in_addr addr;
    inet_pton(AF_INET, ip_str, &addr);
    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask = 0xffffffff << (32 - prefix);
    
    *start_ip = ip & mask;
    *end_ip = *start_ip + (1 << (32 - prefix)) - 1;
}

void list_interfaces(interface_info *interfaces, int *count) {
    struct ifaddrs *ifaddr, *ifa;
    *count = 0;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    
    for (ifa = ifaddr; ifa != NULL && *count < MAX_INTERFACES; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
            continue;
            
        struct ifreq ifr;
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        
        strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
        strncpy(interfaces[*count].name, ifa->ifa_name, INTERFACE_NAME_LEN-1);
        
        struct sockaddr_in *addr = (struct sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &addr->sin_addr, interfaces[*count].ip, MAX_IP_STR);
        
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
            memcpy(interfaces[*count].mac, ifr.ifr_hwaddr.sa_data, 6);
        }
        
        close(sock);
        (*count)++;
    }
    
    freeifaddrs(ifaddr);
}

const char* get_service_name(int port) {
    static char service[MAX_SERVICE_NAME];
    struct servent *serv;
    
    for (int i = 0; i < DEFAULT_PORTS_COUNT; i++) {
        if (DEFAULT_PORTS[i].port == port) {
            return DEFAULT_PORTS[i].service;
        }
    }
    
    serv = getservbyport(htons(port), "tcp");
    if (serv != NULL) {
        strncpy(service, serv->s_name, MAX_SERVICE_NAME-1);
    } else {
        snprintf(service, MAX_SERVICE_NAME-1, "unknown");
    }
    
    return service;
}


void get_banner(int sock, char *banner, size_t banner_size) {
    struct timeval timeout = {BANNER_PORT_TIMEOUT, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    char *http_request = "HEAD / HTTP/1.0\r\n\r\n";
    send(sock, http_request, strlen(http_request), 0);
    
    ssize_t bytes = recv(sock, banner, banner_size - 1, 0);
    if (bytes > 0) {
        banner[bytes] = '\0';
        for (int i = 0; i < bytes; i++) {
            if (banner[i] == '\n' || banner[i] == '\r') banner[i] = ' ';
        }
    } else {
        banner[0] = '\0';
    }
}

void show_progress_bar(int current, int total) {
    const int bar_width = 50;
    float progress = (float)current / total;
    int pos = bar_width * progress;
    
    printf("\r%s[", COLOR_BLUE);
    for (int i = 0; i < bar_width; i++) {
        if (i < pos) printf("█");
        else if (i == pos) printf("▓");
        else printf("░");
    }
    printf("] %d%%%s", (int)(progress * 100), COLOR_RESET);
    fflush(stdout);
}

void* port_scan_thread(void *arg) {
    scan_args *args = (scan_args*)arg;
    struct sockaddr_in target;
    
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = inet_addr(args->target_ip);
    
    for (int port = args->start_port; port <= args->end_port && scanning; port++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &args->timeout, sizeof(args->timeout));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &args->timeout, sizeof(args->timeout));
        
        target.sin_port = htons(port);
        
        time_t start_time = time(NULL);
        if (connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0) {
            pthread_mutex_lock(&results_mutex);
            int idx = args->host->port_count;
            args->host->ports[idx].port = port;
            strncpy(args->host->ports[idx].service, get_service_name(port), MAX_SERVICE_NAME-1);
            get_banner(sock, args->host->ports[idx].banner, sizeof(args->host->ports[idx].banner));
            args->host->port_count++;
            args->host->response_time = time(NULL) - start_time;
            pthread_mutex_unlock(&results_mutex);
        }
        close(sock);
    }
    
    return NULL;
}

void scan_network(const char *cidr, const char *interface) {
    uint32_t start_ip, end_ip;
    calculate_network_range(cidr, &start_ip, &end_ip);
    
    total_hosts = end_ip - start_ip + 1;
    results = calloc(total_hosts, sizeof(host_result));
    
    printf("\n%s[*] Starting scan on %s%s\n", COLOR_BLUE, interface, COLOR_RESET);
    printf("%s[*] Target: %s%s\n\n", COLOR_BLUE, cidr, COLOR_RESET);
    
    int current_host = 0;
    for (uint32_t ip = start_ip; ip <= end_ip && scanning; ip++) {
        struct in_addr addr;
        addr.s_addr = htonl(ip);
        char *ip_str = inet_ntoa(addr);
        
        show_progress_bar(++current_host, total_hosts);
        
        int host_index = ip - start_ip;
        strncpy(results[host_index].ip, ip_str, MAX_IP_STR-1);
        
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(ip_str);
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        struct timeval timeout = {DEFAULT_TIMEOUT_SEC, DEFAULT_TIMEOUT_USEC};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
            results[host_index].is_alive = 1;
            close(sock);
            
            pthread_t threads[MAX_THREADS];
            scan_args thread_args[MAX_THREADS];
            int ports_per_thread = MAX_PORTS / MAX_THREADS + 1;
            
            for (int i = 0; i < MAX_THREADS && scanning; i++) {
                thread_args[i].target_ip = ip_str;
                thread_args[i].start_port = i * ports_per_thread;
                thread_args[i].end_port = (i + 1) * ports_per_thread - 1;
                thread_args[i].host = &results[host_index];
                thread_args[i].timeout = timeout;
                
                pthread_create(&threads[i], NULL, port_scan_thread, &thread_args[i]);
            }
            
            for (int i = 0; i < MAX_THREADS; i++) {
                pthread_join(threads[i], NULL);
            }
            
            printf("\n%s[+] Host %s: %d ports (Response: %lds)%s\n",
                   COLOR_GREEN, ip_str, results[host_index].port_count,
                   results[host_index].response_time, COLOR_RESET);
                   
            for (int j = 0; j < results[host_index].port_count; j++) {
                printf("    %s→ %d/tcp%s - %s%s%s\n",
                       COLOR_YELLOW,
                       results[host_index].ports[j].port,
                       COLOR_RESET,
                       COLOR_CYAN,
                       results[host_index].ports[j].service,
                       COLOR_RESET);
                       
                if (strlen(results[host_index].ports[j].banner) > 0) {
                    printf("      Banner: %s\n", results[host_index].ports[j].banner);
                }
            }
            printf("\n");
        }
    }
    printf("\n%s[*] Scan complete%s\n", COLOR_BLUE, COLOR_RESET);
}

void cleanup() {
    if (results != NULL) {
        free(results);
        results = NULL;
    }
}

void signal_handler(int signum) {
    printf("\n%s[!] Scan interrupted. Cleaning up...%s\n", COLOR_RED, COLOR_RESET);
    scanning = 0;
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        printf("%s[!] Root privileges required%s\n", COLOR_RED, COLOR_RESET);
        return 1;
    }

    signal(SIGINT, signal_handler);
    show_banner();
    
    interface_info interfaces[MAX_INTERFACES];
    int interface_count;
    list_interfaces(interfaces, &interface_count);
    if (interface_count == 0) {
        printf("%s[!] No network interfaces found%s\n", COLOR_RED, COLOR_RESET);
        return 1;
    }
    
    printf("%s=== Available Network Interfaces ===%s\n\n", COLOR_CYAN, COLOR_RESET);
    for (int i = 0; i < interface_count; i++) {
        printf("%s[%d] %s%s\n", COLOR_YELLOW, i + 1, interfaces[i].name, COLOR_RESET);
        printf("    IP: %s\n", interfaces[i].ip);
        printf("    MAC: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
               interfaces[i].mac[0], interfaces[i].mac[1], interfaces[i].mac[2],
               interfaces[i].mac[3], interfaces[i].mac[4], interfaces[i].mac[5]);
    }
    
    int choice;
    do {
        printf("Select interface (1-%d): ", interface_count);
        scanf("%d", &choice);
        while(getchar() != '\n');
    } while (choice < 1 || choice > interface_count);
    
    char network[64];
    printf("\nEnter target network (CIDR format, e.g. 192.168.1.0/24): ");
    fgets(network, sizeof(network), stdin);
    network[strcspn(network, "\n")] = 0;
    
    printf("\n%s[*] Initializing scan...%s\n", COLOR_BLUE, COLOR_RESET);
    scan_network(network, interfaces[choice-1].name);
    
    if (scanning) {
        printf("\n%s=== Scan Summary ===%s\n", COLOR_MAGENTA, COLOR_RESET);
        int hosts_alive = 0;
        int total_ports = 0;
        
        for (int i = 0; i < total_hosts; i++) {
            if (results[i].is_alive) {
                hosts_alive++;
                total_ports += results[i].port_count;
            }
        }
        
        printf("Total hosts scanned: %d\n", total_hosts);
        printf("Hosts alive: %d\n", hosts_alive);
        printf("Total open ports: %d\n", total_ports);
        printf("Average ports per host: %.2f\n\n", 
               hosts_alive > 0 ? (float)total_ports / hosts_alive : 0);
    }
    
    cleanup();
    return 0;
}
