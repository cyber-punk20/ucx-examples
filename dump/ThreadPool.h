#ifndef THREADPOOL_H
#define THREADPOOL_H
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <queue>
#include <functional>
class ThreadPool {
public:
    void start();
    void queue(const std::function<>& job);
    void stop();
    void busy(); //?
    ThreadPool();
    ThreadPool(uint_32t num_threads);
private:
    void loop();
    bool should_terminate = false;           // Tells threads to stop looking for jobs
    std::mutex queue_mutex;                  // Prevents data races to the job queue
    std::condition_variable mutex_condition; // Allows threads to wait on new jobs or termination 
    std::vector<std::thread> threads;
    std::queue<std::function<void()>> jobs;
    const uint32_t num_threads;

};
#endif