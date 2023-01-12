#include "thread_pool.h"
#include <iostream>
int main() {
    ThreadPool pool(4);
    // enqueue and store future
    auto result = pool.enqueue([](int answer, int b) { return answer + b; }, 42, 3);

    // get result from future
    std::cout << result.get() << std::endl;

}