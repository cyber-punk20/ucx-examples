

// #include <ctpl_stl.h>

// int main (int argc, char *argv[]) {
//     ctpl::thread_pool p(2 /* two threads in the pool */);
//     int arr[4] = {0};
//     std::vector<std::future<void>> results(4);
//     for (int i = 0; i < 8; ++i) { // for 8 iterations,
//         for (int j = 0; j < 4; ++j) {
//             results[j] = p.push([&arr, j](int){ arr[j] +=2; });
//         }
//         for (int j = 0; j < 4; ++j) {
//             results[j].get();
//         }
//         arr[4] = std::min_element(arr, arr + 4);
//     }
// }