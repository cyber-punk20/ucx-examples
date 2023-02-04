CXX=g++
OPT=-O2 -g
CXXFLAGS=-Iinclude/ -march=skylake-avx512 -g -I/opt/intel/compilers_and_libraries_2018.6.288/linux/mpi/intel64/include -I$(UCX_INCLUDE_DIRECTORY) -DNCX_PTR_SIZE=8 -pipe -DLOG_LEVEL=4  -DPAGE_MERGE
OBJS=obj/ucp_client.o obj/ucp_server.o obj/ucp_common.o obj/ucp_common_utils.o obj/ucp_rma_example.o
#HEADERS=dict.h qp_common.h qp.h io_queue.h utility.h xxhash.h list.h buddy.h myfs_common.h myfs.h io_ops_common.h io_ops.h ncx_slab.h ncx_core.h ncx_log.h client/qp_client.h
HEADERS=ucp_common.h ucp_common_utils.h
RM=rm -rf

all: server client rma_example
server: $(OBJS)
	$(CXX) -O2 $(CXXFLAGS) -g -o $@ obj/ucp_server.o obj/ucp_common.o  obj/ucp_common_utils.o  -L$(UCX_LIB_DIRECTORY) -L/opt/intel/compilers_and_libraries_2018.6.288/linux/mpi/intel64/lib/release_mt -L/opt/intel/compilers_and_libraries_2018.6.288/linux/mpi/intel64/lib -lpthread -lmpicxx -lmpifort -lmpi -ldl -lucp -lucm -lucs -luct
client: $(OBJS)
	$(CXX) -O2 $(CXXFLAGS) -g -o $@ obj/ucp_client.o obj/ucp_common.o  obj/ucp_common_utils.o  -L$(UCX_LIB_DIRECTORY) -L/opt/intel/compilers_and_libraries_2018.6.288/linux/mpi/intel64/lib/release_mt -L/opt/intel/compilers_and_libraries_2018.6.288/linux/mpi/intel64/lib -lpthread -lmpicxx -lmpifort -lmpi -ldl -lucp -lucm -lucs -luct

rma_example: $(OBJS)
	$(CXX) -O2 $(CXXFLAGS) -g -o $@ obj/ucp_rma_example.o obj/ucp_common.o  obj/ucp_common_utils.o  -L$(UCX_LIB_DIRECTORY) -L/opt/intel/compilers_and_libraries_2018.6.288/linux/mpi/intel64/lib/release_mt -L/opt/intel/compilers_and_libraries_2018.6.288/linux/mpi/intel64/lib -lpthread -lmpicxx -lmpifort -lmpi -ldl -lucp -lucm -lucs -luct

obj/ucp_client.o: ucp_client.c $(HEADERS)
	$(CXX) -O0 $(CXXFLAGS) -c -o obj/ucp_client.o $<

obj/ucp_server.o: ucp_server.c $(HEADERS)
	$(CXX) -O0 $(CXXFLAGS) -c -o obj/ucp_server.o $<

obj/ucp_common.o: ucp_common.c $(HEADERS)
	$(CXX) -O0 $(CXXFLAGS) -c -o obj/ucp_common.o $<

obj/ucp_common_utils.o: ucp_common_utils.c $(HEADERS)
	$(CXX) -O0 $(CXXFLAGS) -c -o obj/ucp_common_utils.o $<

obj/ucp_rma_example.o: ucp_rma_example.c $(HEADERS)
	$(CXX) -O0 $(CXXFLAGS) -c -o obj/ucp_rma_example.o $<

clean:
	$(RM) obj/*.o server client rma_example
