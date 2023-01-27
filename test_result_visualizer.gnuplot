set terminal png size 1200,800 font "Arial,18"
set output 'test_result.png'

set xlabel "ID"
set ylabel "Bandwidth in MB/sec"
set title "Bandwidth of clients"
plot \
     "ucp_client_stram_result.txt" using 1:2 with linespoints
