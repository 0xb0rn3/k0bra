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
#include <pcap.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <json-c/json.h>
#include <ctype.h>

/* Configuration Constants */
#define MAX_IP_STR 64
#define MAX_THREADS 128
#define MAX_PORTS 65535
#define MAX_INTERFACES 32
#define INTERFACE_NAME_LEN 32
#define MAX_SERVICE_NAME 64
#define PACKET_LEN 8192
#define PCAP_SNAPLEN 65535
#define PCAP_TIMEOUT 1000
#define MAX_PATH_LEN 1024
#define MAX_COMMAND_LEN 256
#define MAX_ERROR_LEN 256
#define MAX_BANNER_LEN 2048
#define MAX_VERSION_LEN 64

/* Timeouts and Limits */
#define DEFAULT_CONNECT_TIMEOUT_SEC 2
#define DEFAULT_CONNECT_TIMEOUT_USEC 0
#define BANNER_GRAB_TIMEOUT 3
#define DEFAULT_RATE_LIMIT 1000
#define MIN_SCAN_DELAY_MS 1
#define MAX_RETRIES 3

/* Exit Codes */
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define EXIT_ARGS_ERROR 2
#define EXIT_PERM_ERROR 3
#define EXIT_MEM_ERROR 4
#define EXIT_NET_ERROR 5

/* Colors */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_WHITE   "\033[1;37m"

/* Scan Types */
typedef enum {
    SCAN_TCP_CONNECT = 0,
    SCAN_SYN,
    SCAN_UDP,
    SCAN_SERVICE
} scan_type_t;

/* Port State */
typedef enum {
    PORT_CLOSED = 0,
    PORT_OPEN,
    PORT_FILTERED
} port_state_t;

/* Service Information */
typedef struct {
    uint16_t port;
    char service[MAX_SERVICE_NAME];
    char probe[256];
    char pattern[64];
    uint8_t protocol;
} service_info_t;

/* Network Interface */
typedef struct {
    char name[INTERFACE_NAME_LEN];
    char ip[MAX_IP_STR];
    uint8_t mac[6];
    int index;
    int is_up;
} interface_info_t;

/* Port Information */
typedef struct {
    uint16_t port;
    char service[MAX_SERVICE_NAME];
    char banner[MAX_BANNER_LEN];
    char version[MAX_VERSION_LEN];
    uint8_t protocol;
    port_state_t state;
    float response_time;
} port_info_t;

/* Host Result */
typedef struct {
    char ip[MAX_IP_STR];
    uint8_t mac[6];
    port_info_t *ports;
    uint32_t port_count;
    uint8_t is_alive;
    time_t discovery_time;
    float rtt_ms;
} host_result_t;

/* Scan Configuration */
typedef struct {
    scan_type_t scan_type;
    uint32_t rate_limit;
    uint8_t verbose;
    char output_format[16];
    char output_file[MAX_PATH_LEN];
    struct timeval timeout;
    uint8_t retries;
    uint16_t min_rtt;
    uint16_t max_rtt;
    uint8_t service_detection;
    uint8_t banner_grab;
    char target_ip[MAX_IP_STR];
    char interface[INTERFACE_NAME_LEN];
    uint16_t start_port;
    uint16_t end_port;
} scan_config_t;

/* Thread Arguments */
typedef struct {
    char target_ip[MAX_IP_STR];
    uint16_t start_port;
    uint16_t end_port;
    host_result_t *host;
    const scan_config_t *config;
    int thread_id;
} thread_args_t;

/* Known Service Patterns */
static const service_info_t KNOWN_SERVICES[] = {
    {21, "FTP", "220", "FTP", 6},
    {22, "SSH", "SSH-2.0", "SSH", 6},
    {23, "Telnet", "\xff\xfb", "Telnet", 6},
    {25, "SMTP", "220", "SMTP", 6},
    {53, "DNS", "\x00\x00\x10\x00\x00", "DNS", 17},
    {80, "HTTP", "GET / HTTP/1.0\r\n\r\n", "HTTP", 6},
    {110, "POP3", "+OK", "POP3", 6},
    {143, "IMAP", "* OK", "IMAP", 6},
    {443, "HTTPS", "\x16\x03", "HTTPS", 6},
    {3306, "MySQL", "\x00\x00\x00\x0a", "MySQL", 6},
    {5432, "PostgreSQL", "\x00\x00\x00\x08", "PostgreSQL", 6},
    {27017, "MongoDB", "\x3f\x00\x00\x00", "MongoDB", 6}
};

/* Global Variables */
static host_result_t *scan_results = NULL;
static uint32_t total_hosts = 0;
static pthread_mutex_t results_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t scanning = 1;
static scan_config_t global_config = {
    .scan_type = SCAN_TCP_CONNECT,
    .rate_limit = DEFAULT_RATE_LIMIT,
    .verbose = 0,
    .timeout = {DEFAULT_CONNECT_TIMEOUT_SEC, DEFAULT_CONNECT_TIMEOUT_USEC},
    .retries = 2,
    .min_rtt = 100,
    .max_rtt = 2000,
    .service_detection = 1,
    .banner_grab = 1,
    .start_port = 1,
    .end_port = MAX_PORTS
};

/* Function Prototypes */
static void cleanup(void);
static void signal_handler(int signum);
static void show_banner(void);
static int parse_arguments(int argc, char *argv[]);
static void initialize_scanner(void);
static int validate_ip_address(const char *ip);
static int get_interface_info(interface_info_t *info);
static void *port_scan_thread(void *arg);
static int detect_service(int sock, port_info_t *port);
static void banner_grab(int sock, port_info_t *port);
static void write_json_output(const char *filename);
static void print_progress(float percentage);
static void print_results(void);
static int create_raw_socket(void);
static void send_syn_packet(int sock, const char *target_ip, uint16_t port);
static void process_packet(const uint8_t *packet, size_t len);

/* Implementation of core functions */

void show_banner(void) {
    printf("%s\n", COLOR_CYAN);
    printf("    ██╗  ██╗ ██████╗ ██████╗ ██████╗  █████╗ \n");
    printf("    ██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗\n");
    printf("    █████╔╝ ██║   ██║██████╔╝██████╔╝███████║\n");
    printf("    ██╔═██╗ ██║   ██║██╔══██╗██╔══██╗██╔══██║\n");
    printf("    ██║  ██╗╚██████╔╝██████╔╝██║  ██║██║  ██║\n");
    printf("    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\n");
    printf("%s    Advanced Network Scanner v3.0%s\n\n", COLOR_WHITE, COLOR_RESET);
}

int validate_ip_address(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

void cleanup(void) {
    if (scan_results) {
        for (uint32_t i = 0; i < total_hosts; i++) {
            if (scan_results[i].ports) {
                free(scan_results[i].ports);
            }
        }
        free(scan_results);
        scan_results = NULL;
    }
    pthread_mutex_destroy(&results_mutex);
}

void signal_handler(int signum) {
    scanning = 0;
    printf("\n%s[!] Scan interrupted. Cleaning up...%s\n", COLOR_RED, COLOR_RESET);
}

int get_interface_info(interface_info_t *info) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET && strcmp(ifa->ifa_name, info->name) == 0) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                          host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                freeifaddrs(ifaddr);
                return -1;
            }
            strncpy(info->ip, host, MAX_IP_STR - 1);
            info->is_up = 1;

            // Get MAC address
            struct ifreq ifr;
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd >= 0) {
                strcpy(ifr.ifr_name, info->name);
                if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                    memcpy(info->mac, ifr.ifr_hwaddr.sa_data, 6);
                }
                close(fd);
            }
            
            freeifaddrs(ifaddr);
            return 0;
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

void *port_scan_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    struct sockaddr_in target;
    int sock;
    
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    if (inet_pton(AF_INET, args->target_ip, &target.sin_addr) != 1) {
        return NULL;
    }

    for (uint16_t port = args->start_port; 
         port <= args->end_port && scanning; 
         port++) {
        
        // Rate limiting
        usleep(1000000 / args->config->rate_limit);
        
        sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sock < 0) continue;
        
        // Set socket options
        struct timeval timeout = args->config->timeout;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        target.sin_port = htons(port);
        
        // Connect with timeout
        int res = connect(sock, (struct sockaddr*)&target, sizeof(target));
        if (res < 0 && errno == EINPROGRESS) {
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);
            
            res = select(sock + 1, NULL, &fdset, NULL, &timeout);
            if (res > 0) {
                int so_error;
                socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error == 0) {
                    // Port is open
                    pthread_mutex_lock(&results_mutex);
                    
                    int idx = args->host->port_count++;
                    args->host->ports[idx].port = port;
                    args->host->ports[idx].state = PORT_OPEN;
                    
                    // Service detection
                    if (args->config->service_detection) {
                        detect_service(sock, &args->host->ports[idx]);
                    }
                    
                    // Banner grabbing
                    if (args->config->banner_grab) {
                        banner_grab(sock, &args->host->ports[idx]);
                    }
                    
                    pthread_mutex_unlock(&results_mutex);
                }
            }
        }
        
        close(sock);
    }
    
    return NULL;
}

int detect_service(int sock, port_info_t *port) {
    char buffer[MAX_BANNER_LEN];
    ssize_t bytes;
    
    // Find matching service
    for (size_t i = 0; i < sizeof(KNOWN_SERVICES)/sizeof(service_info_t); i++) {
        if (port->port == KNOWN_SERVICES[i].port) {
            strncpy(port->service, KNOWN_SERVICES[i].service, MAX_SERVICE_NAME - 1);
            
            // Send probe if it exists
            if (KNOWN_SERVICES[i].probe[0] != '\0') {
                send(sock, KNOWN_SERVICES[i].probe, 
                     strlen(KNOWN_SERVICES[i].probe), 0);
                
                bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (bytes > 0) {
                    buffer[bytes] = '\0';
                    strncpy(port->banner, buffer, MAX_BANNER_LEN - 1);
                    
                    // Version detection
                    char *version = strstr(buffer, KNOWN_SERVICES[i].pattern);
                    if (version) {
                        char *end = strpbrk(version, "\r\n");
                        if (end) *end = '\0';
                        strncpy(port->version, version, MAX_VERSION_LEN - 1);
                    }
                    return 1;
                }
            }
        }
    }
    
    return 0;
}

void banner_grab(int sock, port_info_t *port) {
    char buffer[MAX_BANNER_LEN];
    struct timeval timeout = {BANNER_GRAB_TIMEOUT, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        strncpy(port->banner, buffer, MAX_BANNER_LEN - 1);
    }
}

void write_json_output(const char *filename) {
    json_object *root = json_object_new_object();
    json_object *scan_info = json_object_new_object();
    json_object *hosts_array = json_object_new_array();
    
    // Add scan information
    json_object_object_add(scan_info, "scan_type", 
        json_object_new_string(global_config.scan_type == SCAN_TCP_CONNECT ? 
            "TCP Connect" : "SYN"));
    json_object_object_add(scan_info, "start_time", 
        json_object_new_int64(time(NULL)));
    
    // Add hosts
    for (uint32_t i = 0; i < total_hosts; i++) {
        if (scan_results[i].is_alive) {
            json_object *host_obj = json_object_new_object();
            json_object_object_add(host_obj, "ip", 
                json_object_new_string(scan_results[i].ip));
            
            // Add ports
            json_object *ports_array = json_object_new_array();
            for (uint32_t j = 0; j < scan_results[i].port_count; j++) {
                json_object *port_obj = json_object_new_object();
                json_object_object_add(port_obj, "port", 
                    json_object_new_int(scan_results[i].ports[j].port));
                json_object_object_add(port_obj, "state", 
                    json_object_new_string(scan_results[i].ports[j].state == PORT_OPEN ? 
                        "open" : "filtered"));
                json_object_object_add(port_obj, "service", 
                    json_object_new_string(scan_results[i].ports[j].service));
                
                if (strlen(scan_results[i].ports[j].version) > 0) {
                    json_object_object_add(port_obj, "version",
                        json_object_new_string(scan_results[i].ports[j].version));
                }
                
                if (strlen(scan_results[i].ports[j].banner) > 0) {
                    json_object_object_add(port_obj, "banner",
                        json_object_new_string(scan_results[i].ports[j].banner));
                }
                
                json_object_array_add(ports_array, port_obj);
            }
            
            json_object_object_add(host_obj, "ports", ports_array);
            json_object_array_add(hosts_array, host_obj);
        }
    }
    
    json_object_object_add(root, "scan_info", scan_info);
    json_object_object_add(root, "hosts", hosts_array);
    
    FILE *f = fopen(filename, "w");
    if (f) {
        fprintf(f, "%s\n", json_object_to_json_string_ext(root, 
            JSON_C_TO_STRING_PRETTY));
        fclose(f);
    }
    
    json_object_put(root);
}

void print_progress(float percentage) {
    const int bar_width = 50;
    int pos = bar_width * percentage;
    
    printf("\r%s[", COLOR_BLUE);
    for (int i = 0; i < bar_width; i++) {
        if (i < pos) printf("█");
        else if (i == pos) printf("▓");
        else printf("░");
    }
    printf("] %.1f%%%s", percentage * 100.0, COLOR_RESET);
    fflush(stdout);
}

void print_results(void) {
    printf("\n%s=== Scan Results ===%s\n\n", COLOR_MAGENTA, COLOR_RESET);
    
    int total_open_ports = 0;
    int hosts_alive = 0;
    
    for (uint32_t i = 0; i < total_hosts; i++) {
        if (scan_results[i].is_alive) {
            hosts_alive++;
            printf("%s[+] Host: %s%s\n", COLOR_GREEN, scan_results[i].ip, COLOR_RESET);
            
            for (uint32_t j = 0; j < scan_results[i].port_count; j++) {
                if (scan_results[i].ports[j].state == PORT_OPEN) {
                    total_open_ports++;
                    printf("    %s→ %d/tcp%s - %s%s%s", 
                           COLOR_YELLOW,
                           scan_results[i].ports[j].port,
                           COLOR_RESET,
                           COLOR_CYAN,
                           scan_results[i].ports[j].service,
                           COLOR_RESET);
                    
                    if (strlen(scan_results[i].ports[j].version) > 0) {
                        printf(" (%s)", scan_results[i].ports[j].version);
                    }
                    printf("\n");
                    
                    if (strlen(scan_results[i].ports[j].banner) > 0) {
                        printf("      Banner: %.*s\n", 60, 
                               scan_results[i].ports[j].banner);
                    }
                }
            }
            printf("\n");
        }
    }
    
    printf("\n%s=== Summary ===%s\n", COLOR_MAGENTA, COLOR_RESET);
    printf("Total hosts scanned: %d\n", total_hosts);
    printf("Hosts alive: %d\n", hosts_alive);
    printf("Total open ports: %d\n", total_open_ports);
    printf("Average open ports per host: %.1f\n\n",
           hosts_alive > 0 ? (float)total_open_ports / hosts_alive : 0);
}

int parse_arguments(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "i:t:p:s:r:o:vhb")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(global_config.interface, optarg, INTERFACE_NAME_LEN - 1);
                break;
            case 't':
                if (!validate_ip_address(optarg)) {
                    fprintf(stderr, "Invalid IP address: %s\n", optarg);
                    return -1;
                }
                strncpy(global_config.target_ip, optarg, MAX_IP_STR - 1);
                break;
            case 'p':
                if (sscanf(optarg, "%hu-%hu", 
                    &global_config.start_port, 
                    &global_config.end_port) != 2) {
                    global_config.start_port = 1;
                    global_config.end_port = MAX_PORTS;
                }
                break;
            case 's':
                if (strcmp(optarg, "syn") == 0)
                    global_config.scan_type = SCAN_SYN;
                else if (strcmp(optarg, "connect") == 0)
                    global_config.scan_type = SCAN_TCP_CONNECT;
                break;
            case 'r':
                global_config.rate_limit = atoi(optarg);
                break;
            case 'o':
                strncpy(global_config.output_file, optarg, MAX_PATH_LEN - 1);
                break;
            case 'v':
                global_config.verbose = 1;
                break;
            case 'b':
                global_config.banner_grab = 1;
                break;
            case 'h':
                printf("Usage: %s [options]\n", argv[0]);
                printf("Options:\n");
                printf("  -i <interface>    Network interface to use\n");
                printf("  -t <target>       Target IP address or range\n");
                printf("  -p <port-range>   Port range (e.g., 1-1024)\n");
                printf("  -s <scan-type>    Scan type (connect/syn)\n");
                printf("  -r <rate>         Rate limit (packets per second)\n");
                printf("  -o <file>         Output file (JSON format)\n");
                printf("  -v                Verbose output\n");
                printf("  -b                Enable banner grabbing\n");
                printf("  -h                Show this help message\n");
                return -1;
            default:
                fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
                return -1;
        }
    }
    
    return 0;
}

static void initialize_scanner(void) {
    // Initialize random seed
    srand(time(NULL));
    
    // Initialize default configuration values if not set
    if (strlen(global_config.interface) == 0) {
        strncpy(global_config.interface, "eth0", INTERFACE_NAME_LEN - 1);
    }
    
    if (global_config.rate_limit == 0) {
        global_config.rate_limit = DEFAULT_RATE_LIMIT;
    }
    
    if (global_config.retries == 0) {
        global_config.retries = MAX_RETRIES;
    }
    
    // Initialize results mutex
    pthread_mutex_init(&results_mutex, NULL);
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "%s[!] Root privileges required%s\n", 
                COLOR_RED, COLOR_RESET);
        return EXIT_PERM_ERROR;
    }

    signal(SIGINT, signal_handler);
    show_banner();

    if (parse_arguments(argc, argv) != 0) {
        return EXIT_ARGS_ERROR;
    }

    // Initialize scanner
    initialize_scanner();
    
    // Get interface info
    interface_info_t iface;
    strncpy(iface.name, global_config.interface, INTERFACE_NAME_LEN - 1);
    if (get_interface_info(&iface) != 0) {
        fprintf(stderr, "Failed to get interface information\n");
        return EXIT_NET_ERROR;
    }

    // Allocate results array
    scan_results = calloc(1, sizeof(host_result_t));
    if (!scan_results) {
        fprintf(stderr, "Memory allocation failed\n");
        return EXIT_MEM_ERROR;
    }
    total_hosts = 1;

    // Initialize first host
    strncpy(scan_results[0].ip, global_config.target_ip, MAX_IP_STR - 1);
    scan_results[0].ports = calloc(MAX_PORTS, sizeof(port_info_t));
    if (!scan_results[0].ports) {
        cleanup();
        fprintf(stderr, "Memory allocation failed\n");
        return EXIT_MEM_ERROR;
    }

    // Create thread pool
    pthread_t threads[MAX_THREADS];
    thread_args_t thread_args[MAX_THREADS];
    
    uint16_t ports_per_thread = (global_config.end_port - global_config.start_port + 1) / MAX_THREADS;
    
    printf("%s[*] Starting scan on %s (%s)%s\n", 
           COLOR_BLUE, global_config.target_ip, iface.name, COLOR_RESET);
    printf("%s[*] Scanning ports %d-%d%s\n\n", 
           COLOR_BLUE, global_config.start_port, global_config.end_port, COLOR_RESET);

    // Launch threads
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_args[i].start_port = global_config.start_port + (i * ports_per_thread);
        thread_args[i].end_port = i == MAX_THREADS - 1 ? 
            global_config.end_port : 
            thread_args[i].start_port + ports_per_thread - 1;
        
        strncpy(thread_args[i].target_ip, global_config.target_ip, MAX_IP_STR - 1);
        thread_args[i].host = &scan_results[0];
        thread_args[i].config = &global_config;
        thread_args[i].thread_id = i;

        if (pthread_create(&threads[i], NULL, port_scan_thread, &thread_args[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            continue;
        }
    }

    // Monitor progress
    while (scanning) {
        float progress = 0;
        for (int i = 0; i < MAX_THREADS; i++) {
            progress += (float)(thread_args[i].end_port - thread_args[i].start_port + 1) / 
                       (global_config.end_port - global_config.start_port + 1);
        }
        print_progress(progress);
        usleep(100000);  // 100ms update interval
    }

    // Wait for threads
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Print results
    print_results();

    // Write JSON output if specified
    if (strlen(global_config.output_file) > 0) {
        write_json_output(global_config.output_file);
        printf("%s[*] Results written to %s%s\n", 
               COLOR_BLUE, global_config.output_file, COLOR_RESET);
    }

    cleanup();
    return EXIT_SUCCESS;
}
