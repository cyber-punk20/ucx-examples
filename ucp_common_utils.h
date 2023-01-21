#ifndef UCP_COMMON_UTILS_H
#define UCP_COMMON_UTILS_H

#include <ucs/memory/memory_type.h>
#include <ucp/api/ucp.h>

#include <sys/poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#ifdef HAVE_CUDA
#  include <cuda.h>
#  include <cuda_runtime.h>
#endif

#define CHKERR_ACTION(_cond, _msg, _action) \
    do { \
        if (_cond) { \
            fprintf(stderr, "Failed to %s\n", _msg); \
            _action; \
        } \
    } while (0)


#define CHKERR_JUMP(_cond, _msg, _label) \
    CHKERR_ACTION(_cond, _msg, goto _label)


#define CHKERR_JUMP_RETVAL(_cond, _msg, _label, _retval) \
    do { \
        if (_cond) { \
            fprintf(stderr, "Failed to %s, return value %d\n", _msg, _retval); \
            goto _label; \
        } \
    } while (0)


#define CUDA_FUNC(_func)                                   \
    do {                                                   \
        cudaError_t _result = (_func);                     \
        if (cudaSuccess != _result) {                      \
            fprintf(stderr, "%s failed: %s\n",             \
                    #_func, cudaGetErrorString(_result));  \
        }                                                  \
    } while(0)

int connect_common(const char *server, uint16_t server_port, sa_family_t af);
void print_common_help();
ucs_memory_type_t parse_mem_type(const char *opt_arg);
int check_mem_type_support(ucs_memory_type_t mem_type);
void *mem_type_memset(void *dst, int value, size_t count);

void *mem_type_memcpy(void *dst, const void *src, size_t count);
void mem_type_free(void *address);
void *mem_type_malloc(size_t length);

static inline int
barrier(int oob_sock, void (*progress_cb)(void *arg), void *arg)
{
    struct pollfd pfd;
    int dummy = 0;
    ssize_t res;

    res = send(oob_sock, &dummy, sizeof(dummy), 0);
    if (res < 0) {
        return res;
    }

    pfd.fd      = oob_sock;
    pfd.events  = POLLIN;
    pfd.revents = 0;
    do {
        res = poll(&pfd, 1, 1);
        progress_cb(arg);
    } while (res != 1);

    res = recv(oob_sock, &dummy, sizeof(dummy), MSG_WAITALL);

    /* number of received bytes should be the same as sent */
    return !(res == sizeof(dummy));
}

static inline int generate_test_string(char *str, int size)
{
    char *tmp_str;
    int i;

    tmp_str = (char*)calloc(1, size);
    CHKERR_ACTION(tmp_str == NULL, "allocate memory\n", return -1);

    for (i = 0; i < (size - 1); ++i) {
        tmp_str[i] = 'A' + (i % 26);
    }

    mem_type_memcpy(str, tmp_str, size);

    free(tmp_str);
    return 0;
}

static inline bool check_test_string(char * str, int size) {
    int i;
    for (i = 0; i < (size - 1); ++i) {
        if(str[i] != 'A' + (i % 26)) return false;
    }
    return true;
}
#endif