#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>
#include <uct/api/uct.h>
#include "ucp_common.h"
#include "ucp_common_utils.h"

#include "thread_pool.h"

#include <thread>
#include <vector>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <iostream>
#include <fstream>

#include <string.h>    /* memset */
#include <arpa/inet.h> /* inet_addr */
#include <netinet/in.h> 
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>    /* getopt */
#include <stdlib.h>    /* atoi */
#include <sys/time.h>

#include <mpi.h> 
#define IB_DEVICE	"ib0"
#define PORT 8888
int nNUMAPerNode=1;
struct ucp_address {
    struct in_addr sin_addr;
	// int port;
	// char szIP[16];
};

static ucs_status_t server_create_ep(ucp_worker_h data_worker,
                                     ucp_address_t* peer_address,
                                     ucp_ep_h *server_ep)
{
    ucp_ep_params_t ep_params;
    ucs_status_t    status;

    /* Server creates an ep to the client on the data worker.
     * This is not the worker the listener was created on.
     * The client side should have initiated the connection, leading
     * to this ep's creation */
    ep_params.field_mask      = UCP_EP_PARAM_FIELD_ERR_HANDLER |
                                UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
    ep_params.address    = peer_address;
    ep_params.err_handler.cb  = err_cb;
    ep_params.err_handler.arg = NULL;

    status = ucp_ep_create(data_worker, &ep_params, server_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to create an endpoint on the server: (%s)\n",
                ucs_status_string(status));
    }

    return status;
}

int mpi_rank, nServer=0;	// rank and size of MPI



// static void* get_memory_addr(void* ptr, int client_idx, int mem_size_per_client) {
//     return (ptr + client_idx * mem_size_per_client);
// }

void generate_test_string(void* buff, size_t length) {
    for(size_t i = 0; i < length; i++) {
        *((char*)(buff) + i) = 'A' + (i % 26);;
    }
}

bool check_generate_test_string(uint64_t address, size_t length) {
    printf("check_generate_test_string address %p  length %d\n", address, length);
    for(size_t i = 0; i < length; i++) {
        // if(i % 1000000 == 0) printf("check_generate_test_string iter %d\n", i);
        // printf("check_generate_test_string iter %d\n", i);
        // printf("check_generate_test_string iter %d %p\n", i, (((char*)(address)) + i));
        char* curaddr = (((char*)(address)) + i);
        if((*curaddr) != 'A' + (i % 26))  {
            printf("check_generate_test_string iter %d, orginaddr %p, curaddr %p, curchar %d\n", i, address, (((char*)(address)) + i), (*curaddr));
            return false;
        }
    }
    return true;
}
typedef struct test_req {
    int complete;
} test_req_t;

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
static void send_cb(void *request, ucs_status_t status, void *user_data)
{
    common_cb(user_data, "send_cb");
    printf("send complete!!!\n");
}
static void stream_recv_cb(void *request, ucs_status_t status, size_t length,
                           void *user_data)
{
    common_cb(user_data, "stream_recv_cb");
    printf("recv complete!!!\n");
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
typedef struct server_wait_request_param {
    ucp_worker_h  ucp_data_worker;
    test_req_t * request;
    test_req_t ctx;
    uint64_t address;
}server_wait_request_param_t;

std::mutex m;
int req_cnt = 0;

static void* server_wait_request(void* args) {
    server_wait_request_param* param = (server_wait_request_param*)args;
    
    ucs_status_t status = request_wait(param->ucp_data_worker, param->request, &param->ctx);
    printf("server_wait_request status:%d\n", status);
    // if(check_generate_test_string(param->address, total_mem_alloc_size)) {
    //     printf("server_wait_request check pass");
    // }
    {
        std::lock_guard<std::mutex> lk(m);
        req_cnt++;
    }
    ucp_worker_destroy(param->ucp_data_worker);
    return NULL;
}

static void* server_progress(void* args) {
    ucp_worker_h ucp_worker = *((ucp_worker_h*)args);
    printf("Processing...\n");
    while (true) {
        int ops = ucp_worker_progress(ucp_worker);
        if(ops != 0) {
            printf("ucp_worker_progress %d\n", ops);
        }
    }
    return NULL;
}
bool checkallzeros(void* address, size_t length) {
    for(size_t i = 0; i < length; i++) {
        // if(i % 1000000 == 0) printf("check_generate_test_string iter %d\n", i);
        // printf("check_generate_test_string iter %d\n", i);
        // printf("check_generate_test_string iter %d %p\n", i, (((char*)(address)) + i));
        char* curaddr = (((char*)(address)) + i);
        if((*curaddr) != '\0')  {
            return false;
        }
    }
    return true;
}
int main(int argc, char ** argv) {
    MPI_Init(NULL, NULL);
	MPI_Comm_size(MPI_COMM_WORLD, &nServer);
	MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
    int ret;
    /* UCP objects */
    ucp_context_h ucp_context;
    ucp_worker_h  ucp_worker;
    /* Initialize the UCX required objects */
    ret = init_context(&ucp_context, &ucp_worker, send_recv_type);


    // Exchange Address
    ucp_address_t *address_t = NULL;
    
    size_t address_length       = 0;
    ucs_status_t status;
    status = ucp_worker_get_address(ucp_worker, &address_t, &address_length);
    printf("mpi_rank: %d  address_length:%d status:%s ucp_worker_get_address:%s\n", mpi_rank, address_length, ucs_status_string(status), ((char*)(address_t)));
    address_length = address_length + 10;
    void *all_address_t = malloc(address_length * nServer);
    MPI_Barrier(MPI_COMM_WORLD);
    MPI_Allgather(address_t, address_length, MPI_CHAR, all_address_t, address_length, MPI_CHAR, MPI_COMM_WORLD);
    // if(checkallzeros(all_address_t, address_length * nServer)) {
    //     printf("mpi rank %d\t all zeros\n", mpi_rank);
    // } else {
    //     printf("mpi rank %d\t not all zeros\n", mpi_rank);
    // }






    // printf("mpi_rank: %d after MPI_Allgather %s\n", mpi_rank, ((char*)(all_address_t)));
    // if (ret != 0 /*|| ptr == NULL*/) {
    //     goto err;
    // }
    // Allocate memh
    size_t rdma_alloc_length = nServer * total_mem_alloc_size;
    void* rdma_alloc_address = mem_type_malloc(rdma_alloc_length);
    if(rdma_alloc_address == NULL) {
        printf("mem_type_malloc failed!!\n");
    }
    // if(checkallzeros(rdma_alloc_address, rdma_alloc_length)) {
    //     printf("mpi rank %d\t all zeros\n", mpi_rank);
    // }
    uct_allocated_memory_t alloc_mem;
    ucp_mem_h memh_p;
    ucp_mem_map_params_t mem_map_params;
    mem_map_params.field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS | UCP_MEM_MAP_PARAM_FIELD_LENGTH;
    mem_map_params.length = rdma_alloc_length;
    // mem_map_params.field_mask = UCP_MEM_MAP_PARAM_FIELD_LENGTH | UCP_MEM_MAP_PARAM_FIELD_MEMORY_TYPE | UCP_MEM_MAP_PARAM_FIELD_FLAGS;
    // mem_map_params.length = rdma_alloc_length;
    // mem_map_params.memory_type = UCS_MEMORY_TYPE_HOST;
    // mem_map_params.flags = UCP_MEM_MAP_ALLOCATE;
    mem_map_params.address = rdma_alloc_address;
    status = ucp_mem_map(ucp_context, &mem_map_params,  &memh_p);
    printf("mpi_rank: %d  ucp_mem_map status: %d\n", mpi_rank, status);
    // ucp_mem_attr_t attr;
    // attr.field_mask = UCP_MEM_ATTR_FIELD_ADDRESS | UCP_MEM_ATTR_FIELD_LENGTH;
    // status = ucp_mem_query(memh_p, &attr);
    // printf("mpi_rank: %d address: %p length:%u ucp_mem_query status: %d\n", mpi_rank, attr.address, attr.length, status);
    void *rkey_buffer_p = NULL;
    size_t rkey_buffer_size_p;
    
    status = ucp_rkey_pack(ucp_context, memh_p, &rkey_buffer_p, &rkey_buffer_size_p);
    printf("mpi_rank: %d  ucp_rkey_pack status: %d\n", mpi_rank, status);
    MPI_Barrier(MPI_COMM_WORLD);
    void * all_rkey_buffer_p = malloc(rkey_buffer_size_p * nServer);
    MPI_Allgather(rkey_buffer_p, rkey_buffer_size_p, MPI_CHAR, all_rkey_buffer_p, rkey_buffer_size_p, MPI_CHAR, MPI_COMM_WORLD);
    
    void * all_remote_addr_p = malloc(sizeof(uint64_t) * nServer);
    
    // uint64_t remote_addr = (uint64_t)attr.address;
    uint64_t remote_addr = (uint64_t)(rdma_alloc_address);
    MPI_Allgather(&(remote_addr), sizeof(uint64_t) , MPI_CHAR, all_remote_addr_p, sizeof(uint64_t) , MPI_CHAR, MPI_COMM_WORLD);
    if(mpi_rank == 0) {
        for(int i = 0; i < nServer; i++) { 
            printf("%p\t", *(((uint64_t*)all_remote_addr_p) + i));
        }
        printf("\n");
    }
    // ret = run_server(ucp_context, ucp_worker, listen_addr, send_recv_type);
    // void *buffer_p = NULL;
    // size_t buffer_size_p = 0;
    // ucp_memh_pack_params_t mem_pack_params;
    // mem_pack_params.field_mask = UCP_MEMH_PACK_PARAM_FIELD_FLAGS;
    // mem_pack_params.flags = UCP_MEMH_PACK_FLAG_EXPORT;
    // status = ucp_memh_pack(memh_p, &mem_pack_params, &buffer_p, &buffer_size_p);
    // printf("mpi_rank: %d  buffer_size_p:%d status:%s\n", mpi_rank, buffer_size_p, ucs_status_string(status));


    pthread_t server_progress_id;
    int listener_thread = pthread_create(&server_progress_id, NULL, &server_progress, &ucp_worker);
    MPI_Barrier(MPI_COMM_WORLD);
// err:
    // status = ucp_mem_unmap(ucp_context, memh_p);
    pthread_t server_worker_id[nServer];
    // pthread_t server_progress_id[nServer];
    server_wait_request_param_t server_wait_request_params[nServer];
    // ucp_worker_h     ucp_data_worker[nServer];
    ucp_ep_h         peer_ep[nServer];
    int threads[nServer];
    int progress_threads[nServer];
    struct timeval end, start;
    void* testbuff = malloc(total_mem_alloc_size);
    gettimeofday(&start, NULL);
    for(int i = 0; i < nServer; i++) {
        if(i == mpi_rank) continue;
        int              ret;
        generate_test_string(testbuff, total_mem_alloc_size);
        ret = init_worker(ucp_context, &server_wait_request_params[i].ucp_data_worker);
        status = server_create_ep(server_wait_request_params[i].ucp_data_worker, ((ucp_address_t*)((char*)all_address_t + address_length * i)), &peer_ep[i]);
        printf("mpi_rank: %d iter %d   server_create_ep status: %d\n", mpi_rank, i, status);
        ucp_rkey_h rkey_p;
        status = ucp_ep_rkey_unpack(peer_ep[i], (char*)all_rkey_buffer_p + i * rkey_buffer_size_p, &rkey_p);
        printf("mpi_rank: %d  ucp_ep_rkey_unpack status: %d\n", mpi_rank, status);
        ucp_request_param_t param;
        server_wait_request_params[i].ctx.complete = 0;
        param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                          UCP_OP_ATTR_FIELD_USER_DATA;
        param.user_data    = &server_wait_request_params[i].ctx;
        param.cb.send = send_cb;
        test_req_t *request;
        request = (test_req_t *)ucp_put_nbx(peer_ep[i], testbuff, total_mem_alloc_size, *(((uint64_t*)all_remote_addr_p) + i) + mpi_rank * total_mem_alloc_size, rkey_p,  &param);
        printf("mpi_rank %d iter %d remote_addr %p\n", mpi_rank, i, *(((uint64_t*)all_remote_addr_p) + i) + mpi_rank * total_mem_alloc_size);
        // ucp_worker_destroy(ucp_data_worker);
        // free(testbuff);
        // server_wait_request_params[i].ucp_data_worker = &ucp_data_worker[i];
        server_wait_request_params[i].request = request;
        server_wait_request_params[i].address = *(((uint64_t*)all_remote_addr_p) + i) + mpi_rank * total_mem_alloc_size;
        threads[i] = pthread_create(&server_worker_id[i], NULL, &server_wait_request, &server_wait_request_params[i]);
        // progress_threads[i] = pthread_create(&server_progress_id[i], NULL, &server_progress, &ucp_data_worker[i]);


    }
    // sleep(15);
    while(req_cnt < nServer - 1) {
        // waiting and doing nothing
    }
    
    MPI_Barrier(MPI_COMM_WORLD);
    gettimeofday(&end, NULL);
    float delta_s = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    float bandwidth = (total_mem_alloc_size / (1024 * 1024)) * (nServer - 1) / delta_s * 2;
    printf("mpi rank: %d total transfer size: %ld(MB); delta_s: %f(s), bandwidth: %f MB/s\n", mpi_rank, (total_mem_alloc_size / (1024 * 1024)) * (nServer - 1) * 2, delta_s, bandwidth); 
    for(int i = 0; i < nServer; i++) {
        if(i == mpi_rank) continue;
        // generate_test_string((void*)((char*)rdma_alloc_address + i * total_mem_alloc_size), total_mem_alloc_size);
        if(check_generate_test_string((uint64_t)((char*)rdma_alloc_address + i * total_mem_alloc_size), total_mem_alloc_size)) {
            printf("mpi_rank %d iter %d pass check_generate_test_string\n", mpi_rank, i);
        }
    }
    // float *bandwidth_arr = NULL;
    // if (mpi_rank == 0) {
    //     bandwidth_arr = (float*)malloc(sizeof(float) * nServer);
    // }
    // MPI_Gather(&bandwidth, 1, MPI_FLOAT, bandwidth_arr, 1, MPI_FLOAT, 0, MPI_COMM_WORLD);
    // if (mpi_rank == 0) {
    //     std::ofstream result_file("ucp_rma_example_result.txt");
    //     if (result_file.is_open())
    //     {
    //         result_file << "ID Bandwidth\n";
    //         for(int i = 0; i < nServer; i++) {
    //             result_file << i << " " << bandwidth_arr[i] << std::endl;
    //         }
    //         result_file.close();
    //     }
    // }
    while(true) {}
    // for(int i = 0; i < nServer; i++) {
    //     pthread_join(threads[i], NULL);
    // }
    // for(int i = 0; i < nServer; i++) {
    //     pthread_join(progress_threads[i], NULL);
    // }
    ucp_worker_destroy(ucp_worker);
    MPI_Barrier(MPI_COMM_WORLD);
    
    return ret;

}