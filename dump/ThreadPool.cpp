#include "ThreadPool.h"

void ThreadPool::ThreadPool():num_threads(std::thread::hardware_concurrency()) {
    threads.resize(num_threads);
}
void ThreadPool::ThreadPool(uint_32t num_threads):num_threads(num_threads) {
    threads.resize(num_threads);
}
void ThreadPool::start() {
    for(uint32_t  i = 0; i < num_threads; i++) {
        threads.at(i) = std::thread(&ThreadPool::loop, this);
    }
}

void ThreadPool::loop() {
    while (true) {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            mutex_condition.wait(lock, [this] {
                return !jobs.empty() || should_terminate;
            });
            if (should_terminate) {
                return;
            }
            job = jobs.front();
            jobs.pop();
        }
        job();
    }
}


void ThreadPool::queue(const std::function<void()>& job) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        jobs.push(job);
    }
    mutex_condition.notify_one();
}

void ThreadPool::busy() {
    bool poolbusy;
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        poolbusy = jobs.empty();
    }
    return poolbusy;
}

void ThreadPool::stop() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        should_terminate = true;
    }
    mutex_condition.notify_all();
    for (std::thread& active_thread : threads) {
        active_thread.join();
    }
    threads.clear();
}

