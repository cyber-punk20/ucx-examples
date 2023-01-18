# ifndef UCP_COMMON_H
# define UCP_COMMON_H
#include <ucp/api/ucp.h>

#include <string.h>    /* memset */
#include <arpa/inet.h> /* inet_addr */
#include <unistd.h>    /* getopt */
#include <stdlib.h>    /* atoi */

#define DEFAULT_PORT           13337
#define IP_STRING_LEN          50
#define PORT_STRING_LEN        8
#define PRINT_INTERVAL         20
#define DEFAULT_NUM_ITERATIONS 40
#define TEST_AM_ID             0
#define SERVER_MAX_CLIENT_CNT 128
#define MEM_PER_CLIENT 50 * 1024 * 1024
#define DEBUG_DATA_CHECK true

typedef enum {
    CLIENT_SERVER_SEND_RECV_STREAM  = UCS_BIT(0),
    CLIENT_SERVER_SEND_RECV_TAG     = UCS_BIT(1),
    CLIENT_SERVER_SEND_RECV_AM      = UCS_BIT(2),
    CLIENT_SERVER_SEND_RECV_RMA      = UCS_BIT(3),
    CLIENT_SERVER_SEND_RECV_DEFAULT = CLIENT_SERVER_SEND_RECV_STREAM
} send_recv_type_t;

/**
 * Descriptor of the data received with AM API.
 */
typedef struct AM_DATA_DESC{
    volatile int complete;
    int          is_rndv;
    void         *desc;
    void         *recv_buf;
} AM_DATA_DESC;

extern long test_string_length;
extern long iov_cnt;
extern long total_transfer_size;

extern send_recv_type_t send_recv_type;

extern sa_family_t ai_family;
extern uint16_t server_port;
int parse_cmd(int argc, char *const argv[], char **server_addr);
char* sockaddr_get_ip_str(const struct sockaddr_storage *sock_addr,
                                 char *ip_str, size_t max_size);
char* sockaddr_get_port_str(const struct sockaddr_storage *sock_addr,
                                   char *port_str, size_t max_size);
void set_sock_addr(const char *address_str, struct sockaddr_storage *saddr);
int init_context(ucp_context_h *ucp_context, ucp_worker_h *ucp_worker, send_recv_type_t send_recv_type);
int init_worker(ucp_context_h ucp_context, ucp_worker_h *ucp_worker);
int client_server_do_work(ucp_worker_h ucp_worker, ucp_ep_h ep, send_recv_type_t send_recv_type, AM_DATA_DESC* am_data_desc_p, int is_server);
ucs_status_t ucp_am_data_cb(void *arg, const void *header, size_t header_length,
                            void *data, size_t length,
                            const ucp_am_recv_param_t *param);
void err_cb(void *arg, ucp_ep_h ep, ucs_status_t status);
ucs_status_t register_am_recv_callback(ucp_worker_h worker, AM_DATA_DESC* am_data_desc);
void ep_close(ucp_worker_h ucp_worker, ucp_ep_h ep, uint64_t flags);
# endif