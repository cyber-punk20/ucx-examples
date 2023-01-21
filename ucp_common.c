#include "ucp_common.h"
#include "ucp_common_utils.h"


send_recv_type_t send_recv_type = CLIENT_SERVER_SEND_RECV_DEFAULT;

long test_string_length = 1024 * 1024 * 5;
long iov_cnt            = 1;

sa_family_t ai_family   = AF_INET;
uint16_t server_port    = DEFAULT_PORT;
static int num_iterations      = DEFAULT_NUM_ITERATIONS;
static int connection_closed   = 1;
long total_transfer_size = (num_iterations + 2) * iov_cnt * test_string_length;

typedef struct test_req {
    int complete;
} test_req_t;

/**
 * Descriptor of the data received with AM API.
 */
// static struct {
//     volatile int complete;
//     int          is_rndv;
//     void         *desc;
//     void         *recv_buf;
// } am_data_desc = {0, 0, NULL, NULL};

/**
 * Parse the command line arguments.
 */
int parse_cmd(int argc, char *const argv[], char **server_addr)
{
    int c = 0;
    int port;

    while ((c = getopt(argc, argv, "a:l:p:c:6i:s:v:m:h")) != -1) {
        switch (c) {
        case 'a':
            *server_addr = optarg;
            break;
        case 'i':
            num_iterations = atoi(optarg);
            break;
        case 'v':
            iov_cnt = atol(optarg);
            if (iov_cnt <= 0) {
                fprintf(stderr, "Wrong iov count %ld\n", iov_cnt);
                return UCS_ERR_UNSUPPORTED;
            }
            break;
        // case 'h':
        default:
        //     usage();
            return -1;
        }
    }

    return 0;
}


char* sockaddr_get_ip_str(const struct sockaddr_storage *sock_addr,
                                 char *ip_str, size_t max_size)
{
    struct sockaddr_in  addr_in;
    struct sockaddr_in6 addr_in6;

    switch (sock_addr->ss_family) {
    case AF_INET:
        memcpy(&addr_in, sock_addr, sizeof(struct sockaddr_in));
        inet_ntop(AF_INET, &addr_in.sin_addr, ip_str, max_size);
        return ip_str;
    case AF_INET6:
        memcpy(&addr_in6, sock_addr, sizeof(struct sockaddr_in6));
        inet_ntop(AF_INET6, &addr_in6.sin6_addr, ip_str, max_size);
        return ip_str;
    default:
        return "Invalid address family";
    }
}

char* sockaddr_get_port_str(const struct sockaddr_storage *sock_addr,
                                   char *port_str, size_t max_size)
{
    struct sockaddr_in  addr_in;
    struct sockaddr_in6 addr_in6;

    switch (sock_addr->ss_family) {
    case AF_INET:
        memcpy(&addr_in, sock_addr, sizeof(struct sockaddr_in));
        snprintf(port_str, max_size, "%d", ntohs(addr_in.sin_port));
        return port_str;
    case AF_INET6:
        memcpy(&addr_in6, sock_addr, sizeof(struct sockaddr_in6));
        snprintf(port_str, max_size, "%d", ntohs(addr_in6.sin6_port));
        return port_str;
    default:
        return "Invalid address family";
    }
}



static void print_iov(const ucp_dt_iov_t *iov)
{
    char *msg = (char*)alloca(test_string_length);
    size_t idx;

    for (idx = 0; idx < iov_cnt; idx++) {
        /* In case of Non-System memory */
        mem_type_memcpy(msg, iov[idx].buffer, test_string_length);
        printf("%s.\n", msg);
    }
}

/**
 * Print the received message on the server side or the sent data on the client
 * side.
 */
static
void print_result(int is_server, const ucp_dt_iov_t *iov, int current_iter)
{
    if (is_server) {
        printf("Server: iteration #%d\n", (current_iter + 1));
        printf("UCX data message was received\n");
        printf("\n\n----- UCP TEST SUCCESS -------\n\n");
    } else {
        printf("Client: iteration #%d\n", (current_iter + 1));
        printf("\n\n------------------------------\n\n");
    }

    print_iov(iov);

    printf("\n\n------------------------------\n\n");
}

static void check_iov(const ucp_dt_iov_t *iov) {
    size_t idx;
    bool check_res = true;
    for (idx = 0; idx < iov_cnt; idx++) {
        /* In case of Non-System memory */
        if(!check_test_string((char*)iov[idx].buffer, test_string_length)) {
            check_res = false;
            break;
        }
    }
    if(check_res) {
        printf("Server receives test data correctly from client\n");
    }
    else {
        printf("[ERR]Server receives test data incorrectly from client\n");
    }
}

static void check_result(int is_server, const ucp_dt_iov_t *iov, unsigned int client_idx, int current_iter) {
    if (is_server) {
        printf("Server: iteration #%d client idx #%d\n", (current_iter + 1), client_idx);
        printf("UCX data message was received\n");
        printf("\n\n----- UCP TEST SUCCESS -------\n\n");
        check_iov(iov);
    } else {
        printf("Client: iteration #%d\n", (current_iter + 1));
        printf("\n\n------------------------------\n\n");
    }
}

void buffer_free(ucp_dt_iov_t *iov)
{
    // size_t idx;

    // for (idx = 0; idx < iov_cnt; idx++) {
    //     mem_type_free(iov[idx].buffer);
    // }
    // free(iov);
}

int buffer_malloc(ucp_dt_iov_t *iov, unsigned int client_idx, void* ptr, int current_iter)
{
    size_t idx;
    
    for (idx = 0; idx < iov_cnt; idx++) {
        iov[idx].length = test_string_length;
        iov[idx].buffer = (char *)ptr + client_idx * total_transfer_size + current_iter * iov_cnt * test_string_length + idx * test_string_length;
        printf("buffer malloc for client idx #%d, current iter #%d, ptr #%p\n", client_idx, current_iter, iov[idx].buffer);
        if (iov[idx].buffer == NULL) {
            buffer_free(iov);
            return -1;
        }
    }

    return 0;
}

int fill_buffer(ucp_dt_iov_t *iov)
{
    int ret = 0;
    size_t idx;
    if(DEBUG_DATA_CHECK) {
        for (idx = 0; idx < iov_cnt; idx++) {
            ret = generate_test_string((char*)iov[idx].buffer, iov[idx].length);
            if (ret != 0) {
                break;
            }
        }
        CHKERR_ACTION(ret != 0, "generate test string", return -1;);
    }

    
    return 0;
}


/**
 * Initialize the UCP context and worker.
 */
int init_context(ucp_context_h *ucp_context, ucp_worker_h *ucp_worker,
                        send_recv_type_t send_recv_type) 
{
    /* UCP objects */
    ucp_params_t ucp_params;
    ucs_status_t status;
    int ret = 0;

    memset(&ucp_params, 0, sizeof(ucp_params));

    /* UCP initialization */
    ucp_params.field_mask = UCP_PARAM_FIELD_FEATURES | UCP_PARAM_FIELD_NAME;
    ucp_params.name       = "ucp_client_server";
    if (send_recv_type == CLIENT_SERVER_SEND_RECV_STREAM) {
        ucp_params.features = UCP_FEATURE_STREAM;
    } 
    // else if (send_recv_type == CLIENT_SERVER_SEND_RECV_TAG) {
    //     ucp_params.features = UCP_FEATURE_TAG;
    // } 
    else {
        ucp_params.features = UCP_FEATURE_AM;
    }
    status = ucp_init(&ucp_params, NULL, ucp_context);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_init (%s)\n", ucs_status_string(status));
        ret = -1;
        goto err;
    }

    ret = init_worker(*ucp_context, ucp_worker);
    if (ret != 0) {
        goto err_cleanup;
    }

    return ret;

err_cleanup:
    ucp_cleanup(*ucp_context);
err:
    return ret;
}


/**
 * Create a ucp worker on the given ucp context.
 */
int init_worker(ucp_context_h ucp_context, ucp_worker_h *ucp_worker)
{
    ucp_worker_params_t worker_params;
    ucs_status_t status;
    int ret = 0;

    memset(&worker_params, 0, sizeof(worker_params));

    worker_params.field_mask  = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    status = ucp_worker_create(ucp_context, &worker_params, ucp_worker);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_worker_create (%s)\n", ucs_status_string(status));
        ret = -1;
    }

    return ret;
}

static int
fill_request_param(ucp_dt_iov_t *iov, 
                   unsigned int client_idx, void* ptr, int current_iter,
                   int is_client,
                   void **msg, size_t *msg_length,
                   test_req_t *ctx, ucp_request_param_t *param)
{
    CHKERR_ACTION(buffer_malloc(iov, client_idx, ptr, current_iter) != 0, "allocate memory", return -1;);

    if (is_client && (fill_buffer(iov) != 0)) {
        buffer_free(iov);
        return -1;
    }

    *msg        = (iov_cnt == 1) ? iov[0].buffer : iov;
    *msg_length = (iov_cnt == 1) ? iov[0].length : iov_cnt;

    ctx->complete       = 0;
    param->op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                          UCP_OP_ATTR_FIELD_DATATYPE |
                          UCP_OP_ATTR_FIELD_USER_DATA;
    param->datatype     = (iov_cnt == 1) ? ucp_dt_make_contig(1) :
                          UCP_DATATYPE_IOV;
    param->user_data    = ctx;

    return 0;
}



/**
 * Set an address for the server to listen on - INADDR_ANY on a well known port.
 */
void set_sock_addr(const char *address_str, struct sockaddr_storage *saddr)
{
    struct sockaddr_in *sa_in;
    struct sockaddr_in6 *sa_in6;

    /* The server will listen on INADDR_ANY */
    memset(saddr, 0, sizeof(*saddr));

    switch (ai_family) {
    case AF_INET:
        sa_in = (struct sockaddr_in*)saddr;
        if (address_str != NULL) {
            inet_pton(AF_INET, address_str, &sa_in->sin_addr);
        } else {
            sa_in->sin_addr.s_addr = INADDR_ANY;
        }
        sa_in->sin_family = AF_INET;
        sa_in->sin_port   = htons(server_port);
        break;
    case AF_INET6:
        sa_in6 = (struct sockaddr_in6*)saddr;
        if (address_str != NULL) {
            inet_pton(AF_INET6, address_str, &sa_in6->sin6_addr);
        } else {
            sa_in6->sin6_addr = in6addr_any;
        }
        sa_in6->sin6_family = AF_INET6;
        sa_in6->sin6_port   = htons(server_port);
        break;
    default:
        fprintf(stderr, "Invalid address family");
        break;
    }
}

static void common_cb(void *user_data, const char *type_str)
{
    test_req_t *ctx;

    if (user_data == NULL) {
        fprintf(stderr, "user_data passed to %s mustn't be NULL\n", type_str);
        return;
    }

    ctx           = (test_req_t*)user_data;
    ctx->complete = 1;
}

/**
 * The callback on the receiving side, which is invoked upon receiving the
 * active message.
 */
static void am_recv_cb(void *request, ucs_status_t status, size_t length,
                       void *user_data)
{
    common_cb(user_data, "am_recv_cb");
}

/**
 * The callback on the sending side, which is invoked after finishing sending
 * the message.
 */
static void send_cb(void *request, ucs_status_t status, void *user_data)
{
    common_cb(user_data, "send_cb");
}

/**
 * The callback on the receiving side, which is invoked upon receiving the
 * stream message.
 */
static void stream_recv_cb(void *request, ucs_status_t status, size_t length,
                           void *user_data)
{
    common_cb(user_data, "stream_recv_cb");
}


/**
 * Error handling callback.
 */
void err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
{
    printf("error handling callback was invoked with status %d (%s)\n",
           status, ucs_status_string(status));
    connection_closed = 1;
}

ucs_status_t register_am_recv_callback(ucp_worker_h worker, AM_DATA_DESC* am_data_desc_p) 
{
    ucp_am_handler_param_t param;

    param.field_mask = UCP_AM_HANDLER_PARAM_FIELD_ID |
                       UCP_AM_HANDLER_PARAM_FIELD_CB |
                       UCP_AM_HANDLER_PARAM_FIELD_ARG;
    param.id         = TEST_AM_ID;
    param.cb         = ucp_am_data_cb;
    param.arg        = am_data_desc_p; /* not used in our callback */
    return ucp_worker_set_am_recv_handler(worker, &param);
}

ucs_status_t ucp_am_data_cb(void *arg, const void *header, size_t header_length,
                            void *data, size_t length,
                            const ucp_am_recv_param_t *param)
{
    ucp_dt_iov_t *iov;
    size_t idx;
    size_t offset;

    if (length != iov_cnt * test_string_length) {
        fprintf(stderr, "received wrong data length %ld (expected %ld)",
                length, iov_cnt * test_string_length);
        return UCS_OK;
    }

    if (header_length != 0) {
        fprintf(stderr, "received unexpected header, length %ld", header_length);
    }
    AM_DATA_DESC* am_data_desc_p = (AM_DATA_DESC*)arg;
    am_data_desc_p->complete = 1;

    if (param->recv_attr & UCP_AM_RECV_ATTR_FLAG_RNDV) {
        /* Rendezvous request arrived, data contains an internal UCX descriptor,
         * which has to be passed to ucp_am_recv_data_nbx function to confirm
         * data transfer.
         */
        am_data_desc_p->is_rndv = 1;
        am_data_desc_p->desc    = data;
        return UCS_INPROGRESS;
    }

    /* Message delivered with eager protocol, data should be available
     * immediately
     */
    am_data_desc_p->is_rndv = 0;

    iov = (ucp_dt_iov_t*)am_data_desc_p->recv_buf;
    offset = 0;
    for (idx = 0; idx < iov_cnt; idx++) {
        mem_type_memcpy(iov[idx].buffer, UCS_PTR_BYTE_OFFSET(data, offset),
                        iov[idx].length);
        offset += iov[idx].length;
    }

    return UCS_OK;
}

/**
 * Progress the request until it completes.
 */
static ucs_status_t request_wait(ucp_worker_h ucp_worker, void *request,
                                 test_req_t *ctx)
{
    ucs_status_t status;

    /* if operation was completed immediately */
    if (request == NULL) {
        return UCS_OK;
    }

    if (UCS_PTR_IS_ERR(request)) {
        return UCS_PTR_STATUS(request);
    }

    while (ctx->complete == 0) {
        ucp_worker_progress(ucp_worker);
    }
    status = ucp_request_check_status(request);

    ucp_request_free(request);

    return status;
}

static int request_finalize(ucp_worker_h ucp_worker, test_req_t *request,
                            test_req_t *ctx, unsigned int client_idx, int is_server, ucp_dt_iov_t *iov,
                            int current_iter)
{
    int ret = 0;
    ucs_status_t status;

    status = request_wait(ucp_worker, request, ctx);
    if (status != UCS_OK) {
        fprintf(stderr, "unable to %s UCX message (%s)\n",
                is_server ? "receive": "send", ucs_status_string(status));
        ret = -1;
        goto release_iov;
    }

    /* Print the output of the first, last and every PRINT_INTERVAL iteration */
    if(DEBUG_DATA_CHECK) {
        if ((current_iter == 0) || (current_iter == (num_iterations - 1)) ||
            !((current_iter + 1) % (PRINT_INTERVAL))) {
            // print_result(is_server, iov, current_iter);
            check_result(is_server, iov, client_idx, current_iter);
        }
    }
    

release_iov:
    buffer_free(iov);
    return ret;
}

/**
 * Send and receive a message using Active Message API.
 * The client sends a message to the server and waits until the send is completed.
 * The server gets a message from the client and if it is rendezvous request,
 * initiates receive operation.
 */
static int send_recv_am(ucp_worker_h ucp_worker, ucp_ep_h ep, AM_DATA_DESC* am_data_desc_p, 
                        unsigned int client_idx, 
                        void* ptr,
                        int is_server,
                        int current_iter)
{
    ucp_dt_iov_t *iov = (ucp_dt_iov_t *)alloca(iov_cnt * sizeof(ucp_dt_iov_t));
    test_req_t *request;
    ucp_request_param_t params;
    size_t msg_length;
    void *msg;
    test_req_t ctx;
    memset(iov, 0, iov_cnt * sizeof(*iov));

    if (fill_request_param(iov, client_idx, ptr, current_iter, !is_server, &msg, &msg_length,
                           &ctx, &params) != 0) {
        return -1;
    }
    if (is_server) {
        am_data_desc_p->recv_buf = iov;

        /* waiting for AM callback has called */
        while (!am_data_desc_p->complete) {
            ucp_worker_progress(ucp_worker);
        }

        am_data_desc_p->complete = 0;

        if (am_data_desc_p->is_rndv) {
            /* Rendezvous request has arrived, need to invoke receive operation
             * to confirm data transfer from the sender to the "recv_message"
             * buffer. */
            params.op_attr_mask |= UCP_OP_ATTR_FLAG_NO_IMM_CMPL;
            params.cb.recv_am    = am_recv_cb;
            request              = (test_req_t*)ucp_am_recv_data_nbx(ucp_worker,
                                                        am_data_desc_p->desc,
                                                        msg, msg_length,
                                                        &params);
        } else {
            /* Data has arrived eagerly and is ready for use, no need to
             * initiate receive operation. */
            request = NULL;
        }
    } else {
        /* Client sends a message to the server using the AM API */
        params.cb.send = (ucp_send_nbx_callback_t)send_cb;
        request        = (test_req_t*)ucp_am_send_nbx(ep, TEST_AM_ID, NULL, 0ul, msg,
                                         msg_length, &params);
    }

    return request_finalize(ucp_worker, request, &ctx, client_idx, is_server, iov,
                            current_iter);
}

/**
 * Send and receive a message using the Stream API.
 * The client sends a message to the server and waits until the send it completed.
 * The server receives a message from the client and waits for its completion.
 */
static int send_recv_stream(ucp_worker_h ucp_worker, ucp_ep_h ep, 
                            unsigned int client_idx, 
                            void* ptr,
                            int is_server,
                            int current_iter)
{
    ucp_dt_iov_t *iov = (ucp_dt_iov_t *)alloca(iov_cnt * sizeof(ucp_dt_iov_t));
    ucp_request_param_t param;
    test_req_t *request;
    size_t msg_length;
    void *msg;
    test_req_t ctx;

    memset(iov, 0, iov_cnt * sizeof(*iov));

    if (fill_request_param(iov, client_idx, ptr, current_iter, !is_server, &msg, &msg_length,
                           &ctx, &param) != 0) {
        return -1;
    }

    if (!is_server) {
        /* Client sends a message to the server using the stream API */
        param.cb.send = send_cb;
        request       = (test_req_t *)ucp_stream_send_nbx(ep, msg, msg_length, &param);
    } else {
        /* Server receives a message from the client using the stream API */
        param.op_attr_mask  |= UCP_OP_ATTR_FIELD_FLAGS;
        param.flags          = UCP_STREAM_RECV_FLAG_WAITALL;
        param.cb.recv_stream = stream_recv_cb;
        request              = (test_req_t *)ucp_stream_recv_nbx(ep, msg, msg_length,
                                                   &msg_length, &param);
    }

    return request_finalize(ucp_worker, request, &ctx, client_idx, is_server, iov,
                            current_iter);
}


static int client_server_communication(ucp_worker_h worker, ucp_ep_h ep, 
                                        send_recv_type_t send_recv_type, 
                                        AM_DATA_DESC* am_data_desc_p,
                                        unsigned int client_idx,
                                        void* ptr,
                                        int is_server, int current_iter)
{
    int ret;

    switch (send_recv_type) {
    case CLIENT_SERVER_SEND_RECV_STREAM:
        /* Client-Server communication via Stream API */
        ret = send_recv_stream(worker, ep, client_idx, ptr, is_server, current_iter);
        break;
    // case CLIENT_SERVER_SEND_RECV_TAG:
    //     /* Client-Server communication via Tag-Matching API */
    //     ret = send_recv_tag(worker, ep, is_server, current_iter);
    //     break;
    case CLIENT_SERVER_SEND_RECV_AM:
        /* Client-Server communication via AM API. */
        ret = send_recv_am(worker, ep, am_data_desc_p, client_idx, ptr, is_server, current_iter);
        break;
    default:
        fprintf(stderr, "unknown send-recv type %d\n", send_recv_type);
        return -1;
    }

    return ret;
}

int client_server_do_work(ucp_worker_h ucp_worker, ucp_ep_h ep, send_recv_type_t send_recv_type, 
                          AM_DATA_DESC* am_data_desc_p, 
                          unsigned int client_idx,
                          void* ptr,
                          int is_server)
{
    int i, ret = 0;
    ucs_status_t status;

    connection_closed = 0;

    for (i = 0; i < num_iterations; i++) {
        ret = client_server_communication(ucp_worker, ep, send_recv_type,
                                          am_data_desc_p,
                                          client_idx,
                                          ptr,
                                          is_server, i);
        if (ret != 0) {
            fprintf(stderr, "%s failed on iteration #%d\n",
                    (is_server ? "server": "client"), i + 1);
            goto out;
        }
    }

    /* Register recv callback on the client side to receive FIN message */
    if (!is_server  && (send_recv_type == CLIENT_SERVER_SEND_RECV_AM)) {
        status = register_am_recv_callback(ucp_worker, am_data_desc_p);
        if (status != UCS_OK) {
            ret = -1;
            goto out;
        }
    }

    /* FIN message in reverse direction to acknowledge delivery */
    ret = client_server_communication(ucp_worker, ep, send_recv_type, am_data_desc_p,
                                      client_idx,
                                      ptr,
                                      !is_server, i);
    if (ret != 0) {
        fprintf(stderr, "%s failed on FIN message\n",
                (is_server ? "server": "client"));
        goto out;
    }

    printf("%s FIN message\n", is_server ? "sent" : "received");

    /* Server waits until the client closed the connection after receiving FIN */
    while (is_server && !connection_closed) {
        ucp_worker_progress(ucp_worker);
    }

out:
    return ret;
}

/**
 * Close UCP endpoint.
 *
 * @param [in]  worker  Handle to the worker that the endpoint is associated
 *                      with.
 * @param [in]  ep      Handle to the endpoint to close.
 * @param [in]  flags   Close UCP endpoint mode. Please see
 *                      @a ucp_ep_close_flags_t for details.
 */
void ep_close(ucp_worker_h ucp_worker, ucp_ep_h ep, uint64_t flags)
{
    ucp_request_param_t param;
    ucs_status_t status;
    void *close_req;

    param.op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS;
    param.flags        = flags;
    close_req          = ucp_ep_close_nbx(ep, &param);
    if (UCS_PTR_IS_PTR(close_req)) {
        do {
            ucp_worker_progress(ucp_worker);
            status = ucp_request_check_status(close_req);
        } while (status == UCS_INPROGRESS);
        ucp_request_free(close_req);
    } else {
        status = UCS_PTR_STATUS(close_req);
    }

    if (status != UCS_OK) {
        fprintf(stderr, "failed to close ep %p: %s\n", (void*)ep,
                ucs_status_string(status));
    }
}
