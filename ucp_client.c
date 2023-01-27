#include "ucp_common.h"
#include "ucp_common_utils.h"

#include <string.h>    /* memset */
#include <arpa/inet.h> /* inet_addr */
#include <unistd.h>    /* getopt */
#include <stdlib.h>    /* atoi */
#include <sys/time.h>
#include <iostream>
#include <fstream>


#include <mpi.h> 


/**
 * Initialize the client side. Create an endpoint from the client side to be
 * connected to the remote server (to the given IP).
 */
static ucs_status_t start_client(ucp_worker_h ucp_worker,
                                 const char *address_str, ucp_ep_h *client_ep)
{
    ucp_ep_params_t ep_params;
    struct sockaddr_storage connect_addr;
    ucs_status_t status;

    set_sock_addr(address_str, &connect_addr);

    /*
     * Endpoint field mask bits:
     * UCP_EP_PARAM_FIELD_FLAGS             - Use the value of the 'flags' field.
     * UCP_EP_PARAM_FIELD_SOCK_ADDR         - Use a remote sockaddr to connect
     *                                        to the remote peer.
     * UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE - Error handling mode - this flag
     *                                        is temporarily required since the
     *                                        endpoint will be closed with
     *                                        UCP_EP_CLOSE_MODE_FORCE which
     *                                        requires this mode.
     *                                        Once UCP_EP_CLOSE_MODE_FORCE is
     *                                        removed, the error handling mode
     *                                        will be removed.
     */
    ep_params.field_mask       = UCP_EP_PARAM_FIELD_FLAGS       |
                                 UCP_EP_PARAM_FIELD_SOCK_ADDR   |
                                 UCP_EP_PARAM_FIELD_ERR_HANDLER |
                                 UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
    ep_params.err_mode         = UCP_ERR_HANDLING_MODE_PEER;
    ep_params.err_handler.cb   = err_cb;
    ep_params.err_handler.arg  = NULL;
    ep_params.flags            = UCP_EP_PARAMS_FLAGS_CLIENT_SERVER;
    ep_params.sockaddr.addr    = (struct sockaddr*)&connect_addr;
    ep_params.sockaddr.addrlen = sizeof(connect_addr);

    status = ucp_ep_create(ucp_worker, &ep_params, client_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to connect to %s (%s)\n", address_str,
                ucs_status_string(status));
    }

    return status;
}
int mpi_rank, nClient=0;	// rank and size of MPI
static int run_client(ucp_worker_h ucp_worker, char *server_addr,
                      send_recv_type_t send_recv_type)
{
    ucp_ep_h     client_ep;
    ucs_status_t status;
    int          ret;

    status = start_client(ucp_worker, server_addr, &client_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to start client (%s)\n", ucs_status_string(status));
        ret = -1;
        goto out;
    }
    {
        struct timeval end, start;
        AM_DATA_DESC am_data_desc = {0, 0, NULL, NULL};
        void* ptr = mem_type_malloc(total_mem_alloc_size);
        gettimeofday(&start, NULL);
        ret = client_server_do_work(ucp_worker, client_ep, send_recv_type, &am_data_desc, 0, ptr, 0);
        gettimeofday(&end, NULL);
        float delta_s = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
        float bandwidth =  total_transfer_size / delta_s / (1024 * 1024);
        printf("total transfer size: %ld(MB); delta_s: %f(s), bandwidth: %f MB/s\n", total_transfer_size / (1024 * 1024), delta_s, bandwidth); 
        /* Close the endpoint to the server */
        float *bandwidth_arr = NULL;
        if (mpi_rank == 0) {
            bandwidth_arr = (float*)malloc(sizeof(float) * nClient);
        }
        MPI_Gather(&bandwidth, 1, MPI_FLOAT, bandwidth_arr, 1, MPI_FLOAT, 0, MPI_COMM_WORLD);
        if (mpi_rank == 0) {
            std::ofstream result_file("ucp_client_stram_result.txt");
            if (result_file.is_open())
            {
                result_file << "ID Bandwidth\n";
                for(int i = 0; i < nClient; i++) {
                    result_file << i << " " << bandwidth_arr[i] << std::endl;
                }
                result_file.close();
            }
        }
        ep_close(ucp_worker, client_ep, UCP_EP_CLOSE_MODE_FLUSH);
        mem_type_free(ptr);
    }
out:
    return ret;
}

int main(int argc, char **argv)
{
    
    char *server_addr = NULL;
    int ret;
    MPI_Init(NULL, NULL);
	MPI_Comm_size(MPI_COMM_WORLD, &nClient);
	MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
    printf("Client %d is running\n", mpi_rank);
    /* UCP objects */
    ucp_context_h ucp_context;
    ucp_worker_h  ucp_worker;

    ret = parse_cmd(argc, argv, &server_addr);
    if (ret != 0) {
        goto err;
    }

    /* Initialize the UCX required objects */
    ret = init_context(&ucp_context, &ucp_worker, send_recv_type);
    if (ret != 0) {
        goto err;
    }
    MPI_Barrier(MPI_COMM_WORLD);
    /* Client-Server initialization */
    /* Client side */
    ret = run_client(ucp_worker, server_addr, send_recv_type);

    ucp_worker_destroy(ucp_worker);
    ucp_cleanup(ucp_context);
    MPI_Barrier(MPI_COMM_WORLD);
err:
    return ret;
}
