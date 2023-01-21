#include <ucp/api/ucp.h>
#include "ucp_common.h"
#include "ucp_common_utils.h"

#include "thread_pool.h"

#include <thread>
#include <vector>
#include <mutex>
#include <queue>
#include <condition_variable>


#include <string.h>    /* memset */
#include <arpa/inet.h> /* inet_addr */
#include <unistd.h>    /* getopt */
#include <stdlib.h>    /* atoi */

#include <mpi.h> 

/**
 * Server's application context to be used in the user's connection request
 * callback.
 * It holds the server's listener and the handle to an incoming connection request.
 */
typedef struct ucx_server_ctx {
    // volatile ucp_conn_request_h conn_request;
    ucp_listener_h              listener;
    std::queue<ucp_conn_request_h> context_queue;
    std::mutex context_queue_mutex;
    std::condition_variable context_queue_condition;
    unsigned int client_idx = 0;
} ucx_server_ctx_t;









static ucs_status_t server_create_ep(ucp_worker_h data_worker,
                                     ucp_conn_request_h conn_request,
                                     ucp_ep_h *server_ep)
{
    ucp_ep_params_t ep_params;
    ucs_status_t    status;

    /* Server creates an ep to the client on the data worker.
     * This is not the worker the listener was created on.
     * The client side should have initiated the connection, leading
     * to this ep's creation */
    ep_params.field_mask      = UCP_EP_PARAM_FIELD_ERR_HANDLER |
                                UCP_EP_PARAM_FIELD_CONN_REQUEST;
    ep_params.conn_request    = conn_request;
    ep_params.err_handler.cb  = err_cb;
    ep_params.err_handler.arg = NULL;

    status = ucp_ep_create(data_worker, &ep_params, server_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to create an endpoint on the server: (%s)\n",
                ucs_status_string(status));
    }

    return status;
}

/**
 * The callback on the server side which is invoked upon receiving a connection
 * request from the client.
 */
static void server_conn_handle_cb(ucp_conn_request_h conn_request, void *arg) {
    ucx_server_ctx_t *context = (ucx_server_ctx_t *)arg;
    ucp_conn_request_attr_t attr;
    char ip_str[IP_STRING_LEN];
    char port_str[PORT_STRING_LEN];
    ucs_status_t status;

    attr.field_mask = UCP_CONN_REQUEST_ATTR_FIELD_CLIENT_ADDR;
    status = ucp_conn_request_query(conn_request, &attr);
    if (status == UCS_OK) {
        printf("Server received a connection request from client at address %s:%s\n",
               sockaddr_get_ip_str(&attr.client_address, ip_str, sizeof(ip_str)),
               sockaddr_get_port_str(&attr.client_address, port_str, sizeof(port_str)));
    } else if (status != UCS_ERR_UNSUPPORTED) {
        fprintf(stderr, "failed to query the connection request (%s)\n",
                ucs_status_string(status));
    }
    
    {
        std::unique_lock<std::mutex> lock(context->context_queue_mutex);
        context->context_queue.emplace(conn_request);
    }
    context->context_queue_condition.notify_one();
    // if (context->conn_request == NULL) {
    //     context->conn_request = conn_request;
    // } else {
    //     /* The server is already handling a connection request from a client,
    //      * reject this new one */
    //     printf("Rejecting a connection request. "
    //            "Only one client at a time is supported.\n");
    //     status = ucp_listener_reject(context->listener, conn_request);
    //     if (status != UCS_OK) {
    //         fprintf(stderr, "server failed to reject a connection request: (%s)\n",
    //                 ucs_status_string(status));
    //     }
    // }
}

/**
 * Initialize the server side. The server starts listening on the set address.
 */
static ucs_status_t
start_server(ucp_worker_h ucp_worker, ucx_server_ctx_t *context,
             ucp_listener_h *listener_p, const char *address_str) 
{
    struct sockaddr_storage listen_addr;
    ucp_listener_params_t params;
    ucp_listener_attr_t attr;
    ucs_status_t status;
    char ip_str[IP_STRING_LEN];
    char port_str[PORT_STRING_LEN];

    set_sock_addr(address_str, &listen_addr);

    params.field_mask         = UCP_LISTENER_PARAM_FIELD_SOCK_ADDR |
                                UCP_LISTENER_PARAM_FIELD_CONN_HANDLER;
    params.sockaddr.addr      = (const struct sockaddr*)&listen_addr;
    params.sockaddr.addrlen   = sizeof(listen_addr);
    params.conn_handler.cb    = server_conn_handle_cb;
    params.conn_handler.arg   = context;
    /* Create a listener on the server side to listen on the given address.*/
    status = ucp_listener_create(ucp_worker, &params, listener_p);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to listen (%s)\n", ucs_status_string(status));
        goto out;
    }

    /* Query the created listener to get the port it is listening on. */
    /* Query the created listener to get the port it is listening on. */
    attr.field_mask = UCP_LISTENER_ATTR_FIELD_SOCKADDR;
    status = ucp_listener_query(*listener_p, &attr);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to query the listener (%s)\n",
                ucs_status_string(status));
        ucp_listener_destroy(*listener_p);
        goto out;
    }

    fprintf(stderr, "server is listening on IP %s port %s\n",
            sockaddr_get_ip_str(&attr.sockaddr, ip_str, IP_STRING_LEN),
            sockaddr_get_port_str(&attr.sockaddr, port_str, PORT_STRING_LEN));

    printf("Waiting for connection...\n");

out:
    return status;
}

static void* server_progress(void* args) {
    ucp_worker_h ucp_worker = *((ucp_worker_h*)args);
    printf("Waiting for connection...\n");
    while (true) {
        ucp_worker_progress(ucp_worker);
    }
    return NULL;
}

static void* allocate_memory_for_rma(int client_cnt, int mem_size_per_client) {
    void* ptr = mem_type_malloc(client_cnt * mem_size_per_client);
    return ptr;
}

// MAIN THREAD
static int run_server(ucp_context_h ucp_context, ucp_worker_h ucp_worker,
                      char *listen_addr, send_recv_type_t send_recv_type)
{
    ucx_server_ctx_t context;
    ucs_status_t     status;
    int              ret;
    
    const unsigned int number_of_threads = std::thread::hardware_concurrency();
    ThreadPool pool(number_of_threads);


    
    void* ptr = allocate_memory_for_rma(SERVER_MAX_CLIENT_CNT, total_transfer_size);
    
    /* Create a listener on the worker created at first. The 'connection
     * worker' - used for connection establishment between client and server.
     * This listener will stay open for listening to incoming connection
     * requests from the client */
    status = start_server(ucp_worker, &context, &context.listener, listen_addr);
    if (status != UCS_OK) {
        ret = -1;
        ucp_worker_destroy(ucp_worker);
        return ret;
    }
    
    /* Server is always up listening */
    pthread_t server_listener_thread_id;
    int listener_thread = pthread_create(&server_listener_thread_id, NULL, &server_progress, &ucp_worker);
    while (1) {
        ucp_conn_request_h conn_request = NULL;
        unsigned int client_idx = 0;
        {
            std::unique_lock<std::mutex> lock(context.context_queue_mutex);
            context.context_queue_condition.wait(lock,
                [&context]{ return !context.context_queue.empty(); });
            conn_request = std::move(context.context_queue.front());
            context.context_queue.pop();
            context.client_idx++;
            client_idx = context.client_idx;
        }
        
        pool.enqueue([ucp_context, conn_request, send_recv_type, client_idx, ptr]() { 
            printf("deal with connection client idx #%d\n", client_idx);
            ucs_status_t     status;
            int              ret;
            ucp_worker_h     ucp_data_worker;
            ucp_ep_h         server_ep;
            /* Create a data worker (to be used for data exchange between the server
            * and the client after the connection between them was established) */
            ret = init_worker(ucp_context, &ucp_data_worker);
            AM_DATA_DESC am_data_desc = {0, 0, NULL, NULL};
            if (ret != 0) {
                return ret;
            }
            if (send_recv_type == CLIENT_SERVER_SEND_RECV_AM) {
                status = register_am_recv_callback(ucp_data_worker, &am_data_desc);
                if (status != UCS_OK) {
                    ret = -1;
                    goto err_ucp_data_worker;
                }
            }
            

            /* Server creates an ep to the client on the data worker.
            * This is not the worker the listener was created on.
            * The client side should have initiated the connection, leading
            * to this ep's creation */
            status = server_create_ep(ucp_data_worker, conn_request,
                                    &server_ep);
            if (status != UCS_OK) {
                ret = -1;
                // goto err_listener;
                return ret;
            }

            /* The server waits for all the iterations to complete before moving on
            * to the next client */
            ret = client_server_do_work(ucp_data_worker, server_ep, send_recv_type, 
                                        &am_data_desc,
                                        client_idx,
                                        ptr,
                                        1);
            if (ret != 0) {
                goto err_ep;
            }

            /* Close the endpoint to the client */
            // ep_close(ucp_data_worker, server_ep, UCP_EP_CLOSE_MODE_FORCE);

            /* Reinitialize the server's context to be used for the next client */
            // context.conn_request = NULL;
            err_ep:
                ep_close(ucp_data_worker, server_ep, UCP_EP_CLOSE_MODE_FORCE);
            err_ucp_data_worker:
                ucp_worker_destroy(ucp_data_worker);
        });
        
        
    }
    pthread_join(listener_thread, NULL);
    mem_type_free(ptr);
err_listener:
    ucp_listener_destroy(context.listener);

    return UCS_OK;
}

int mpi_rank, nServer=0;	// rank and size of MPI



// static void* get_memory_addr(void* ptr, int client_idx, int mem_size_per_client) {
//     return (ptr + client_idx * mem_size_per_client);
// }

int main(int argc, char ** argv) {
    MPI_Init(NULL, NULL);
	MPI_Comm_size(MPI_COMM_WORLD, &nServer);
	MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
    int ret;
    char *listen_addr = NULL;
    /* UCP objects */
    ucp_context_h ucp_context;
    ucp_worker_h  ucp_worker;
    /* Initialize the UCX required objects */
    ret = init_context(&ucp_context, &ucp_worker, send_recv_type);
    
    if (ret != 0 /*|| ptr == NULL*/) {
        goto err;
    }
    ret = run_server(ucp_context, ucp_worker, listen_addr, send_recv_type);
    
err:
    return ret;

}