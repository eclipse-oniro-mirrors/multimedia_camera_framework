/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "camera_common_pipeline_unittest.h"

#include <atomic>
#include <chrono>
#include <future>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <utility>

#include "camera_log.h"
#include "unified_pipeline.h"
#include "unified_pipeline_data_consumer.h"
#include "unified_pipeline_manager.h"
#include "unified_pipeline_plugin.h"
#include "unified_pipeline_process_node.h"
#include "unified_pipeline_threadpool.h"
#include "unified_pipeline_worker_thread.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

class UnifiedPipelineThreadpoolTest : public testing::Test {
public:
    void SetUp() override {};
    void TearDown() override {};
};

// Mock回调类
class MockStatusCallback : public WorkerThread::WorkerThreadStatusCallback {
public:
    MOCK_METHOD(void, OnIdle, (), (override));
};

class WorkerThreadTest : public testing::Test {
protected:
    void SetUp() override
    {
        callback_ = std::make_shared<MockStatusCallback>();
        worker_ = std::make_unique<WorkerThread>();
        worker_->SetStatusCallback(callback_);
    };
    void TearDown() override
    {
        if (worker_) {
            worker_->Shutdown();
        }
    };

    std::shared_ptr<MockStatusCallback> callback_;
    std::unique_ptr<WorkerThread> worker_;
};

/*
 * Feature: WorkerThread
 * Function: BasicOperation
 * SubFunction: TaskHandling
 * FunctionPoints: TaskSubmission, PromiseHandling
 * EnvConditions: NA
 * CaseDescription: Validate fundamental worker thread operations including task submission,
 * promise synchronization, and graceful shutdown procedure.
 */
HWTEST_F(WorkerThreadTest, BasicOperation, TestSize.Level0)
{
    // Set expectation for OnIdle callback
    EXPECT_CALL(*callback_, OnIdle()).Times(1);

    // Submit task
    std::promise<void> promise;
    auto future = promise.get_future();
    auto task = std::make_shared<PipelineTask>([&promise]() { promise.set_value(); });

    worker_->SubmitTask(task);
    future.get(); // Wait for task completion

    // Wait idle status
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    worker_->Shutdown();
}

/*
 * Feature: WorkerThread
 * Function: IdleStateDetection
 * SubFunction: CallbackMechanism
 * FunctionPoints: OnIdleTrigger, StateTransition
 * EnvConditions: NA
 * CaseDescription: Verify idle callback triggering mechanism after task completion,
 * ensuring correct state transition to idle when no tasks are pending.
 */
HWTEST_F(WorkerThreadTest, OnIdleTrigger, TestSize.Level0)
{
    // Set expectation for OnIdle callback
    EXPECT_CALL(*callback_, OnIdle()).Times(1);

    // Submit empty task
    auto task = std::make_shared<PipelineTask>([]() {});
    worker_->SubmitTask(task);

    // Wait for task completion and state transition
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    worker_->Shutdown();
}

/*
 * Feature: WorkerThread
 * Function: Test basic state transitions
 * SubFunction: StateManagement
 * FunctionPoints: IdleState, RunningState
 * EnvConditions: NA
 * CaseDescription: Verify worker thread state transitions from idle to running and back to idle after task completion.
 * Checks initial idle state, task submission, execution verification and post-execution state.
 */
HWTEST_F(WorkerThreadTest, BasicStateTransitions, TestSize.Level0)
{
    // Initial state should be IDLE
    EXPECT_TRUE(worker_->IsIdle());

    // Submit task
    auto task = std::make_shared<PipelineTask>();
    std::atomic<bool> taskExecuted(false);
    task->func = [&] { taskExecuted = true; };

    EXPECT_CALL(*callback_, OnIdle()).Times(1);
    EXPECT_TRUE(worker_->SubmitTask(task));

    // Wait for task execution
    int waitCount = 0;
    while (!taskExecuted && waitCount++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(taskExecuted);
    EXPECT_TRUE(worker_->IsIdle());
}

/*
 * Feature: WorkerThread
 * Function: Test task submission in busy state
 * SubFunction: TaskSubmission
 * FunctionPoints: StateValidation
 * EnvConditions: NA
 * CaseDescription: Verify task submission fails when worker thread is not idle.
 *  Creates blocking task to keep thread busy, then attempts to submit second task which should be rejected.
 */
HWTEST_F(WorkerThreadTest, SubmitWhenNotIdle, TestSize.Level0)
{
    std::mutex taskMutex;
    std::condition_variable taskCv;
    bool taskBlock = true;

    // Create blocking task
    auto blockingTask = std::make_shared<PipelineTask>();
    blockingTask->func = [&] {
        std::unique_lock<std::mutex> lock(taskMutex);
        taskCv.wait(lock, [&] { return !taskBlock; });
    };

    EXPECT_CALL(*callback_, OnIdle()).Times(1);
    EXPECT_TRUE(worker_->SubmitTask(blockingTask));

    // Wait for entering running state
    int waitCount = 0;
    while (worker_->threadStatus_ != WorkerThread::ThreadStatus::RUNNING && waitCount++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_FALSE(worker_->IsIdle());

    // Try to submit new task (should fail)
    auto secondTask = std::make_shared<PipelineTask>();
    secondTask->func = [] {};
    EXPECT_FALSE(worker_->SubmitTask(secondTask));

    // Release task
    {
        std::lock_guard<std::mutex> lock(taskMutex);
        taskBlock = false;
        taskCv.notify_one();
    }

    // Wait for entering running state
    waitCount = 0;
    while (worker_->threadStatus_ != WorkerThread::ThreadStatus::IDLE && waitCount++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(worker_->IsIdle());
}

/*
 * Feature: WorkerThread
 * Function: Test shutdown operation
 * SubFunction: LifecycleManagement
 * FunctionPoints: ShutdownProcedure
 * EnvConditions: NA
 * CaseDescription: Verify proper shutdown behavior including task rejection after shutdown and final state transition.
 *  Tests immediate shutdown and validates post-shutdown state and task submission blocking.
 */
HWTEST_F(WorkerThreadTest, ShutdownBehavior, TestSize.Level0)
{
    // Shutdown immediately
    worker_->Shutdown();

    // Submitting task after shutdown should fail
    auto task = std::make_shared<PipelineTask>();
    task->func = [] {};
    EXPECT_FALSE(worker_->SubmitTask(task));

    // State after shutdown should be DONE
    EXPECT_FALSE(worker_->IsIdle());
}

/*
 * Feature: WorkerThread
 * Function: Test shutdown during task execution
 * SubFunction: LifecycleManagement
 * FunctionPoints: ShutdownSafety
 * EnvConditions: NA
 * CaseDescription: Verify safe shutdown during task execution.
 *  Task initiates shutdown internally, validates proper task completion and thread state after shutdown.
 */
HWTEST_F(WorkerThreadTest, ShutdownDuringTask, TestSize.Level0)
{
    std::atomic<bool> taskCompleted(false);
    std::atomic<bool> taskStarted(false);

    auto task = std::make_shared<PipelineTask>();
    task->func = [&] {
        taskStarted = true;
        // Call shutdown inside task
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        taskCompleted = true;
    };

    EXPECT_CALL(*callback_, OnIdle()).Times(0);
    EXPECT_TRUE(worker_->SubmitTask(task));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(taskStarted);

    worker_->Shutdown();
    // Wait for task completion
    int waitCount = 0;
    while (!taskCompleted && waitCount++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_TRUE(taskCompleted);
    // State after shutdown should be DONE
    EXPECT_FALSE(worker_->IsIdle());
}

/*
 * Feature: WorkerThread
 * Function: Test null/empty task handling
 * SubFunction: TaskValidation
 * FunctionPoints: NullTaskHandling
 * EnvConditions: NA
 * CaseDescription: Verify proper handling of null tasks and tasks with empty functions.
 *  Tests submission of nullptr task and task with null function, validates state transitions remain stable.
 */
HWTEST_F(WorkerThreadTest, NullTaskHandling, TestSize.Level0)
{
    // Test nullptr task
    EXPECT_CALL(*callback_, OnIdle()).Times(1);
    EXPECT_TRUE(worker_->SubmitTask(nullptr));

    // Wait for idle state
    int waitCount = 0;
    while (!worker_->IsIdle() && waitCount++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Test empty function task
    auto emptyTask = std::make_shared<PipelineTask>();
    emptyTask->func = nullptr;

    EXPECT_CALL(*callback_, OnIdle()).Times(1);
    EXPECT_TRUE(worker_->SubmitTask(emptyTask));

    // Wait for idle state
    waitCount = 0;
    while (!worker_->IsIdle() && waitCount++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(worker_->IsIdle());
}

/*
 * Feature: WorkerThread
 * Function: Test callback object lifecycle
 * SubFunction: ResourceManagement
 * FunctionPoints: CallbackSafety
 * EnvConditions: NA
 * CaseDescription: Verify thread safety when callback object is destroyed before worker thread.
 *  Creates and destroys callback object, then validates task submission doesn't cause crashes.
 */
HWTEST_F(WorkerThreadTest, CallbackDestruction, TestSize.Level0)
{
    // Create temporary callback
    auto tempCallback = std::make_shared<MockStatusCallback>();
    worker_->SetStatusCallback(tempCallback);

    // Destroy callback object
    tempCallback.reset();

    // Submitting task should not crash
    auto task = std::make_shared<PipelineTask>();
    task->func = [] {};
    EXPECT_TRUE(worker_->SubmitTask(task));

    // Wait for task completion
    int waitCount = 0;
    while (!worker_->IsIdle() && waitCount++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(worker_->IsIdle());
}

/*
 * Feature: WorkerThread
 * Function: Test sequential task submission
 * SubFunction: TaskProcessing
 * FunctionPoints: TaskQueueing
 * EnvConditions: NA
 * CaseDescription: Verify proper execution of multiple sequential tasks.
 *  Submits series of tasks, validates all execute successfully and maintain correct state transitions between tasks.
 */
HWTEST_F(WorkerThreadTest, MultipleTaskSubmission, TestSize.Level0)
{
    constexpr int TASK_COUNT = 5;
    std::atomic<int> taskCounter(0);

    EXPECT_CALL(*callback_, OnIdle()).Times(TASK_COUNT);

    for (int i = 0; i < TASK_COUNT; i++) {
        auto task = std::make_shared<PipelineTask>();
        task->func = [&] { taskCounter++; };

        // Wait for idle state
        int waitCount = 0;
        while (!worker_->IsIdle() && waitCount++ < 50) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        EXPECT_TRUE(worker_->SubmitTask(task));
    }

    // Wait for all tasks completion
    int waitCount = 0;
    while (taskCounter < TASK_COUNT && waitCount++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(taskCounter, TASK_COUNT);
    EXPECT_TRUE(worker_->IsIdle());
}

/*
 * Feature: WorkerThread
 * Function: Test concurrent access
 * SubFunction: ThreadSafety
 * FunctionPoints: ConcurrencyControl
 * EnvConditions: NA
 * CaseDescription: Verify thread safety under concurrent access.
 *  Creates multiple threads attempting to submit tasks simultaneously, validates only one submission succeeds.
 */
HWTEST_F(WorkerThreadTest, ConcurrentAccess, TestSize.Level0)
{
    EXPECT_CALL(*callback_, OnIdle()).Times(1);
    constexpr int THREAD_COUNT = 4;
    std::vector<std::thread> threads;
    std::atomic<int> successCount(0);

    for (int i = 0; i < THREAD_COUNT; i++) {
        threads.emplace_back([&] {
            auto task = std::make_shared<PipelineTask>();
            task->func = [] { std::this_thread::sleep_for(std::chrono::milliseconds(10)); };
            if (worker_->IsIdle() && worker_->SubmitTask(task)) {
                successCount++;
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Wait for idle state
    int waitCount = 0;
    while (!worker_->IsIdle() && waitCount++ < 50) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Only one task should be submitted successfully
    EXPECT_EQ(successCount, 1);
}

/*
 * Feature: UnifiedPipelineThreadpool
 * Function: BasicFunctionality
 * SubFunction: TaskSubmission
 * FunctionPoints: Submit, Wait, Shutdown
 * EnvConditions: NA
 * CaseDescription: Verify basic threadpool operations including task submission, execution synchronization, and
 * shutdown procedure.
 */
HWTEST_F(UnifiedPipelineThreadpoolTest, BasicFunction, TestSize.Level0)
{
    constexpr size_t MIN_THREADS = 1;
    constexpr size_t MAX_THREADS = 4;
    auto threadpool = std::make_shared<UnifiedPipelineThreadpool>(MIN_THREADS, MAX_THREADS);

    // Submit a simple task
    std::promise<void> promise;
    auto future = promise.get_future();
    auto task = [&promise]() {
        MEDIA_INFO_LOG("Task executed");
        promise.set_value();
    };

    // Get task pointer and retrieve future from it
    auto taskPtr = threadpool->Submit(task);
    ASSERT_NE(taskPtr, nullptr);
    taskPtr->get_future().get(); // Wait for task completion
    future.get();                // Verify promise

    threadpool->Shutdown();
}

/*
 * Feature: UnifiedPipelineThreadpool
 * Function: ConcurrentExecution
 * SubFunction: ParallelProcessing
 * FunctionPoints: TaskParallelism, AtomicCounter
 * EnvConditions: NA
 * CaseDescription: Validate concurrent execution of multiple tasks and verify atomic counter increments across threads.
 */
HWTEST_F(UnifiedPipelineThreadpoolTest, ConcurrentTasks, TestSize.Level0)
{
    constexpr size_t MIN_THREADS = 2;
    constexpr size_t MAX_THREADS = 4;
    constexpr int TASK_COUNT = 10;
    auto threadpool = std::make_shared<UnifiedPipelineThreadpool>(MIN_THREADS, MAX_THREADS);

    std::vector<std::future<int>> futures;
    std::atomic<int> counter { 0 };

    // Submit multiple tasks and collect futures
    for (int i = 0; i < TASK_COUNT; i++) {
        auto taskPtr = threadpool->Submit([&counter]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return ++counter;
        });
        ASSERT_NE(taskPtr, nullptr);
        futures.push_back(taskPtr->get_future());
    }

    // Verify all tasks completed
    int total = 0;
    for (auto& f : futures) {
        total += f.get();
    }
    EXPECT_EQ(total, TASK_COUNT * (TASK_COUNT + 1) / 2);

    threadpool->Shutdown();
}

/*
 * Feature: UnifiedPipelineThreadpool
 * Function: DynamicScaling
 * SubFunction: ThreadManagement
 * FunctionPoints: ThreadExpansion, PerformanceMonitoring
 * EnvConditions: NA
 * CaseDescription: Test dynamic thread expansion under load and verify scaling behavior through execution time metrics.
 */
HWTEST_F(UnifiedPipelineThreadpoolTest, ThreadExpansion, TestSize.Level0)
{
    constexpr size_t MIN_THREADS = 1;
    constexpr size_t MAX_THREADS = 10;
    auto threadpool = std::make_shared<UnifiedPipelineThreadpool>(MIN_THREADS, MAX_THREADS);

    // Verify initial thread count
    EXPECT_EQ(threadpool->workers_.size(), 0);

    auto start = std::chrono::high_resolution_clock::now();

    // Submit tasks exceeding minimum threads
    std::vector<std::shared_ptr<std::packaged_task<void()>>> tasks;
    for (int i = 0; i < MAX_THREADS; i++) {
        auto taskPtr = threadpool->Submit([]() { std::this_thread::sleep_for(std::chrono::milliseconds(1000)); });
        ASSERT_NE(taskPtr, nullptr);
        tasks.push_back(taskPtr);
    }
    // Wait for all tasks to complete
    for (auto& task : tasks) {
        task->get_future().get();
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    // Minimum execution time for single thread: 1000ms
    EXPECT_GE(duration.count(), 1000);

    // Maximum execution time for 10 threads (50% tolerance)
    EXPECT_LE(duration.count(), 1500);

    // Verify thread count expanded
    EXPECT_EQ(threadpool->workers_.size(), MAX_THREADS);

    threadpool->Shutdown();
}

/*
 * Feature: UnifiedPipelineThreadpool
 * Function: ShutdownHandling
 * SubFunction: LifecycleManagement
 * FunctionPoints: PostShutdownBehavior, TaskRejection
 * EnvConditions: NA
 * CaseDescription: Verify task submission rejection and proper error handling after threadpool shutdown.
 */
HWTEST_F(UnifiedPipelineThreadpoolTest, SubmitAfterShutdown, TestSize.Level0)
{
    constexpr size_t MIN_THREADS = 1;
    constexpr size_t MAX_THREADS = 1;
    auto threadpool = std::make_shared<UnifiedPipelineThreadpool>(MIN_THREADS, MAX_THREADS);

    threadpool->Shutdown();

    // Attempt to submit task
    auto taskPtr = threadpool->Submit([]() {});

    // Verify null pointer is returned
    EXPECT_EQ(taskPtr, nullptr);
}

/*
 * Feature: UnifiedPipelineThreadpool
 * Function: QueueStressTest
 * SubFunction: ResourceContention
 * FunctionPoints: TaskQueueing, SequentialExecution
 * EnvConditions: NA
 * CaseDescription: Stress test task queueing under single-threaded constraint and validate sequential execution order.
 */
HWTEST_F(UnifiedPipelineThreadpoolTest, SubmitTasksOverThreads, TestSize.Level0)
{
    constexpr size_t MIN_THREADS = 1;
    constexpr size_t MAX_THREADS = 1;
    constexpr int32_t TASK_COUNT = 100;

    auto threadpool = std::make_shared<UnifiedPipelineThreadpool>(MIN_THREADS, MAX_THREADS);

    // Submit tasks and wait for last task completion
    std::shared_ptr<std::packaged_task<int32_t()>> lastTask = nullptr;
    std::atomic<int32_t> countValue = 0;
    for (int32_t i = 0; i < TASK_COUNT; i++) {
        lastTask = threadpool->Submit([&countValue]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return ++countValue;
        });
    }
    ASSERT_NE(lastTask, nullptr);

    // If all 100 tasks execute sequentially, the last task value must be 100
    EXPECT_EQ(lastTask->get_future().get(), TASK_COUNT);

    threadpool->Shutdown();
}

// Mock Data Consumer Class
class MockDataConsumer : public UnifiedPipelineDataConsumer {
public:
    MockDataConsumer()
    {
        isProcessed_ = false;
    }

    void OnBufferArrival(std::unique_ptr<UnifiedPipelineBuffer> pipelineBuffer) override
    {
        isProcessed_ = true;
    }

    void OnCommandArrival(std::unique_ptr<UnifiedPipelineCommand> command) override {}

    bool IsProcessed() const
    {
        return isProcessed_;
    }

private:
    bool isProcessed_;
};

// Test Class Definition
class UnifiedPipelineUnitTest : public testing::Test {
protected:
    void SetUp() override {
        // Test initialization
        pipeline_ = std::make_shared<UnifiedPipeline>(4);  // Default 4 threads
    }

    void TearDown() override {
        // Test cleanup
        pipeline_.reset();
    }

    std::shared_ptr<UnifiedPipeline> pipeline_;
};

/*
 * Feature: UnifiedPipeline
 * Function: GetThreadPool
 * SubFunction: NA
 * FunctionPoints: The first call to GetThreadPool should create a thread pool instance
 * EnvConditions: NA
 * CaseDescription: Test if GetThreadPool correctly creates thread pool instance on first call
 */
HWTEST_F(UnifiedPipelineUnitTest, GetThreadPool_FirstCall, TestSize.Level0)
{
    auto threadPool = pipeline_->GetThreadPool();
    EXPECT_NE(threadPool, nullptr);
}

/*
 * Feature: UnifiedPipeline
 * Function: GetThreadPool
 * SubFunction: NA
 * FunctionPoints: Multiple calls to GetThreadPool should return the same instance
 * EnvConditions: NA
 * CaseDescription: Test if GetThreadPool returns the same thread pool instance on multiple calls
 */
HWTEST_F(UnifiedPipelineUnitTest, GetThreadPool_MultipleCalls, TestSize.Level0)
{
    auto threadPool1 = pipeline_->GetThreadPool();
    auto threadPool2 = pipeline_->GetThreadPool();
    EXPECT_EQ(threadPool1, threadPool2);
}

/*
 * Feature: UnifiedPipeline
 * Function: OnBufferArrival
 * SubFunction: NA
 * FunctionPoints: Buffer arrival processing flow
 * EnvConditions: NA
 * CaseDescription: Test buffer arrival processing flow, including plugin processing and data consumer invocation
 */
HWTEST_F(UnifiedPipelineUnitTest, OnBufferArrival_Normal, TestSize.Level0)
{
    // Create mock data consumer
    auto dataConsumer = std::make_shared<MockDataConsumer>();
    pipeline_->SetDataConsumer(dataConsumer);

    // Create mock plugin
    auto plugin = std::make_shared<UnifiedPipelinePlugin>();
    pipeline_->AddPlugin(1, plugin);

    // Create mock buffer data
    auto buffer = std::make_unique<UnifiedPipelineBuffer>();

    // Trigger buffer arrival
    pipeline_->OnBufferArrival(std::move(buffer));

    // Wait for data processing to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify data consumer was called
    EXPECT_TRUE(dataConsumer->IsProcessed());
}

/*
 * Feature: UnifiedPipeline
 * Function: OnBufferArrival
 * SubFunction: Error Handling
 * FunctionPoints: 
 *     - UnifiedPipeline buffer processing flow
 *     - Null buffer input handling
 * EnvConditions:
 *     - Pipeline initialized with mock plugin
 *     - Data consumer registered
 * CaseDescription: 
 *    1. Test scenario: Verify pipeline behavior when receiving null buffer
 *    2. Precondition:
 *        - Pipeline configured with mock data consumer
 *        - Plugin registered to the pipeline
 *    3. Execution steps:
 *        - Invoke OnBufferArrival with nullptr
 *        - Allow short time for async processing
 *    4. Expected result:
 *        - Pipeline should handle null input gracefully
 *        - Data consumer should not process invalid buffer
 *        - IsProcessed() should return false indicating no processing occurred
 */
HWTEST_F(UnifiedPipelineUnitTest, OnBufferArrival_NullBuffer, TestSize.Level0)
{
    // Create mock data consumer
    auto dataConsumer = std::make_shared<MockDataConsumer>();
    pipeline_->SetDataConsumer(dataConsumer);

    // Create mock plugin
    auto plugin = std::make_shared<UnifiedPipelinePlugin>();
    pipeline_->AddPlugin(1, plugin);

    // Trigger buffer arrival with null input
    pipeline_->OnBufferArrival(nullptr);

    // Wait for data processing to complete (async operation)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify data consumer was not called for invalid input
    EXPECT_FALSE(dataConsumer->IsProcessed());
}

/*
 * Feature: UnifiedPipeline
 * Function: AddPlugin
 * SubFunction: NA
 * FunctionPoints: Plugin adding functionality
 * EnvConditions: NA
 * CaseDescription: Test plugin adding functionality, including plugin order and count
 */
HWTEST_F(UnifiedPipelineUnitTest, AddPlugin_Normal, TestSize.Level0)
{
    auto plugin1 = std::make_shared<UnifiedPipelinePlugin>();
    auto plugin2 = std::make_shared<UnifiedPipelinePlugin>();

    pipeline_->AddPlugin(1, plugin1);
    pipeline_->AddPlugin(2, plugin2);

    // Verify plugin count
    EXPECT_EQ(pipeline_->plugins_.size(), 2);

    // Find plugin1
    auto it1 = pipeline_->plugins_.find(1);
    EXPECT_NE(it1, pipeline_->plugins_.end());
    EXPECT_EQ(it1->second, plugin1);

    // Find plugin2
    auto it2 = pipeline_->plugins_.find(2);
    EXPECT_NE(it2, pipeline_->plugins_.end());
    EXPECT_EQ(it2->second, plugin2);
}

/*
 * Feature: UnifiedPipeline
 * Function: RemovePlugin
 * SubFunction: NA
 * FunctionPoints: Plugin removal functionality
 * EnvConditions: NA
 * CaseDescription: Test plugin removal functionality, including count and state after removal
 */
HWTEST_F(UnifiedPipelineUnitTest, RemovePlugin_Normal, TestSize.Level0)
{
    auto plugin = std::make_shared<UnifiedPipelinePlugin>();
    pipeline_->AddPlugin(1, plugin);

    // Verify initial plugin count
    EXPECT_EQ(pipeline_->plugins_.size(), 1);

    // Remove plugin
    pipeline_->RemovePlugin(plugin);

    // Verify plugin count after removal
    EXPECT_EQ(pipeline_->plugins_.size(), 0);
}

class UnifiedPipelineManagerTest : public testing::Test {
protected:
    void SetUp() override {
        // Initialization if needed
    }
    
    void TearDown() override {
        // Cleanup if needed
    }
};

/*
 * Feature: UnifiedPipelineManager
 * Function: Constructor
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify that UnifiedPipelineManager can be constructed successfully.
 */
HWTEST_F(UnifiedPipelineManagerTest, ConstructorTest, TestSize.Level0)
{
    std::unique_ptr<UnifiedPipelineManager> manager = std::make_unique<UnifiedPipelineManager>();
    EXPECT_NE(manager, nullptr);
}

/*
 * Feature: UnifiedPipelineManager
 * Function: GetPipelineWithProducer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test getting pipeline with a new producer, should create and return a new pipeline.
 */
HWTEST_F(UnifiedPipelineManagerTest, GetPipelineWithProducer_NewProducer, TestSize.Level0)
{
    UnifiedPipelineManager manager;
    auto producer = std::make_shared<UnifiedPipelineDataProducer>();
    auto pipeline = manager.GetPipelineWithProducer(producer);
    
    EXPECT_NE(pipeline, nullptr);
}

/*
 * Feature: UnifiedPipelineManager
 * Function: GetPipelineWithProducer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test getting pipeline with an existing producer, should return the same pipeline.
 */
HWTEST_F(UnifiedPipelineManagerTest, GetPipelineWithProducer_ExistingProducer, TestSize.Level0)
{
    UnifiedPipelineManager manager;
    auto producer = std::make_shared<UnifiedPipelineDataProducer>();
    
    // First call should create new pipeline
    auto pipeline1 = manager.GetPipelineWithProducer(producer);
    
    // Second call should return same pipeline
    auto pipeline2 = manager.GetPipelineWithProducer(producer);
    
    EXPECT_EQ(pipeline1, pipeline2);
}

/*
 * Feature: UnifiedPipelineManager
 * Function: GetPipelineWithProducer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test thread safety when multiple threads request pipelines concurrently.
 */
HWTEST_F(UnifiedPipelineManagerTest, GetPipelineWithProducer_ThreadSafety, TestSize.Level0)
{
    UnifiedPipelineManager manager;
    auto producer = std::make_shared<UnifiedPipelineDataProducer>();
    
    std::vector<std::thread> threads;
    std::vector<std::shared_ptr<UnifiedPipeline>> results(10);
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&, i]() {
            results[i] = manager.GetPipelineWithProducer(producer);
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // All threads should get the same pipeline instance
    for (int i = 1; i < 10; ++i) {
        EXPECT_EQ(results[0], results[i]);
    }
}

/*
 * Feature: UnifiedPipelineManager
 * Function: GetPipelineWithProducer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test getting pipelines with different producers, should return different pipelines.
 */
HWTEST_F(UnifiedPipelineManagerTest, GetPipelineWithProducer_DifferentProducers, TestSize.Level0)
{
    UnifiedPipelineManager manager;
    auto producer1 = std::make_shared<UnifiedPipelineDataProducer>();
    auto producer2 = std::make_shared<UnifiedPipelineDataProducer>();
    
    auto pipeline1 = manager.GetPipelineWithProducer(producer1);
    auto pipeline2 = manager.GetPipelineWithProducer(producer2);
    
    EXPECT_NE(pipeline1, pipeline2);
}

/*
 * Feature: UnifiedPipelineManager
 * Function: GetPipelineWithProducer
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test getting pipeline with different threadMax values, should create separate pipelines.
 */
HWTEST_F(UnifiedPipelineManagerTest, GetPipelineWithProducer_DifferentThreadMax, TestSize.Level0)
{
    UnifiedPipelineManager manager;
    auto producer = std::make_shared<UnifiedPipelineDataProducer>();
    
    auto pipeline1 = manager.GetPipelineWithProducer(producer, 1);
    auto pipeline2 = manager.GetPipelineWithProducer(producer, 2);
    
    // Should return the same pipeline regardless of threadMax parameter
    // since it's the same producer
    EXPECT_EQ(pipeline1, pipeline2);
}

class MockUnifiedPipelineBufferListener : public UnifiedPipelineBufferListener {
public:
    MOCK_METHOD1(OnBufferArrival, void(std::unique_ptr<UnifiedPipelineBuffer>));
    MOCK_METHOD1(OnCommandArrival, void(std::unique_ptr<UnifiedPipelineCommand>));
};

class UnifiedPipelineDataProducerTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/*
 * Feature: UnifiedPipelineDataProducer
 * Function: Constructor
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify that UnifiedPipelineDataProducer can be constructed successfully.
 */
HWTEST_F(UnifiedPipelineDataProducerTest, ConstructorTest, TestSize.Level0)
{
    std::shared_ptr<UnifiedPipelineDataProducer> producer;
    producer = std::make_shared<UnifiedPipelineDataProducer>();
    ASSERT_NE(producer, nullptr);
}

/*
 * Feature: UnifiedPipelineDataProducer
 * Function: SetBufferListener
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test setting buffer listener with valid weak_ptr.
 */
HWTEST_F(UnifiedPipelineDataProducerTest, SetBufferListener_Valid, TestSize.Level0)
{
    auto producer = std::make_shared<UnifiedPipelineDataProducer>();
    auto mockListener = std::make_shared<MockUnifiedPipelineBufferListener>();
    
    producer->SetBufferListener(mockListener);
    
    // Verify the listener was set (we can't directly access bufferListener_,
    // so we'll test it through OnBufferArrival in the next test)
}

/*
 * Feature: UnifiedPipelineDataProducer
 * Function: OnBufferArrival
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test buffer arrival with valid listener.
 */
HWTEST_F(UnifiedPipelineDataProducerTest, OnBufferArrival_WithValidListener, TestSize.Level0)
{
    auto producer = std::make_shared<UnifiedPipelineDataProducer>();
    auto mockListener = std::make_shared<MockUnifiedPipelineBufferListener>();
    
    producer->SetBufferListener(mockListener);
    
    auto testBuffer = std::make_unique<UnifiedPipelineBuffer>();
    EXPECT_CALL(*mockListener, OnBufferArrival(_)).Times(1);
    
    producer->OnBufferArrival(std::move(testBuffer));
}

/*
 * Feature: UnifiedPipelineDataProducer
 * Function: OnBufferArrival
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test buffer arrival with expired listener.
 */
HWTEST_F(UnifiedPipelineDataProducerTest, OnBufferArrival_WithExpiredListener, TestSize.Level0)
{
    auto producer = std::make_shared<UnifiedPipelineDataProducer>();
    std::weak_ptr<UnifiedPipelineBufferListener> expiredListener;
    
    {
        auto tempListener = std::make_shared<MockUnifiedPipelineBufferListener>();
        expiredListener = tempListener;
        producer->SetBufferListener(expiredListener);
    } // tempListener goes out of scope here
    
    auto testBuffer = std::make_unique<UnifiedPipelineBuffer>();
    producer->OnBufferArrival(std::move(testBuffer));
}

/*
 * Feature: UnifiedPipelineDataProducer
 * Function: OnBufferArrival
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test buffer arrival with null buffer (without exception handling).
 */
HWTEST_F(UnifiedPipelineDataProducerTest, OnBufferArrival_NullBuffer, TestSize.Level0)
{
    auto producer = std::make_shared<UnifiedPipelineDataProducer>();
    auto mockListener = std::make_shared<MockUnifiedPipelineBufferListener>();
    
    producer->SetBufferListener(mockListener);
    
    EXPECT_CALL(*mockListener, OnBufferArrival(_)).Times(0);
    producer->OnBufferArrival(nullptr);
}

class UnifiedPiplinePluginTest : public testing::Test {
protected:
    void SetUp() override {
        // Initialization if needed
    }
    
    void TearDown() override {
        // Cleanup if needed
    }
};

class MockUnifiedPiplineProcessNode : public UnifiedPiplineProcessNodeDefault {
public:
    MOCK_METHOD1(ProcessBuffer, std::unique_ptr<UnifiedPipelineBuffer>(std::unique_ptr<UnifiedPipelineBuffer>));
};

/*
 * Feature: UnifiedPipelinePlugin
 * Function: AddProcessNode
 * SubFunction: NA
 * FunctionPoints: Verify process node addition
 * EnvConditions: NA
 * CaseDescription: Test adding process nodes with different orders.
 */
HWTEST_F(UnifiedPiplinePluginTest, AddProcessNode_Normal, TestSize.Level0)
{
    UnifiedPipelinePlugin plugin;
    auto node1 = std::make_shared<MockUnifiedPiplineProcessNode>();
    auto node2 = std::make_shared<MockUnifiedPiplineProcessNode>();
    
    plugin.AddProcessNode(1, node1);
    plugin.AddProcessNode(2, node2);
    
    // Verify nodes were added (would need inspection method)
    EXPECT_EQ(plugin.processNodes_.size(), 2);
}

/*
 * Feature: UnifiedPipelinePlugin
 * Function: AddProcessNode
 * SubFunction: NA
 * FunctionPoints: Boundary condition
 * EnvConditions: NA
 * CaseDescription: Test adding process node with null pointer.
 */
HWTEST_F(UnifiedPiplinePluginTest, AddProcessNode_NullNode, TestSize.Level0)
{
    UnifiedPipelinePlugin plugin;
    std::shared_ptr<UnifiedPiplineProcessNodeDefault> nullNode = nullptr;
    
    plugin.AddProcessNode(1, nullNode);
    
    // Verify null node wasn't added
    EXPECT_EQ(plugin.processNodes_.size(), 0);
}

/*
 * Feature: UnifiedPipelinePlugin
 * Function: RemoveProcessNode
 * SubFunction: NA
 * FunctionPoints: Verify process node removal
 * EnvConditions: NA
 * CaseDescription: Test removing existing process node.
 */
HWTEST_F(UnifiedPiplinePluginTest, RemoveProcessNode_Existing, TestSize.Level0)
{
    UnifiedPipelinePlugin plugin;
    auto node = std::make_shared<MockUnifiedPiplineProcessNode>();
    
    plugin.AddProcessNode(1, node);
    plugin.RemoveProcessNode(node);
    
    // Verify node was removed
    EXPECT_EQ(plugin.processNodes_.size(), 0);
}

/*
 * Feature: UnifiedPipelinePlugin
 * Function: RemoveProcessNode
 * SubFunction: NA
 * FunctionPoints: Boundary condition
 * EnvConditions: NA
 * CaseDescription: Test removing non-existent process node.
 */
HWTEST_F(UnifiedPiplinePluginTest, RemoveProcessNode_NonExistent, TestSize.Level0)
{
    UnifiedPipelinePlugin plugin;
    auto node1 = std::make_shared<MockUnifiedPiplineProcessNode>();
    auto node2 = std::make_shared<MockUnifiedPiplineProcessNode>();
    
    plugin.AddProcessNode(1, node1);
    plugin.RemoveProcessNode(node2); // Not added
    
    // Verify only node1 remains
    EXPECT_EQ(plugin.processNodes_.size(), 1);
}

/*
 * Feature: UnifiedPipelinePlugin
 * Function: RemoveProcessNode
 * SubFunction: NA
 * FunctionPoints: Boundary condition
 * EnvConditions: NA
 * CaseDescription: Test removing null process node.
 */
HWTEST_F(UnifiedPiplinePluginTest, RemoveProcessNode_NullNode, TestSize.Level0)
{
    UnifiedPipelinePlugin plugin;
    auto node = std::make_shared<MockUnifiedPiplineProcessNode>();
    std::shared_ptr<UnifiedPiplineProcessNodeDefault> nullNode = nullptr;
    
    plugin.AddProcessNode(1, node);
    plugin.RemoveProcessNode(nullNode);
    
    // Verify node remains
    EXPECT_EQ(plugin.processNodes_.size(), 1);
}

/*
 * Feature: UnifiedPipelinePlugin
 * Function: ProcessBuffer
 * SubFunction: NA
 * FunctionPoints: Verify buffer processing
 * EnvConditions: NA
 * CaseDescription: Test processing buffer with single process node.
 */
HWTEST_F(UnifiedPiplinePluginTest, ProcessBuffer_SingleNode, TestSize.Level0)
{
    UnifiedPipelinePlugin plugin;
    auto node = std::make_shared<MockUnifiedPiplineProcessNode>();
    auto buffer = std::make_unique<UnifiedPipelineBuffer>();
    
    EXPECT_CALL(*node, ProcessBuffer(_))
        .WillOnce(Return(ByMove(std::make_unique<UnifiedPipelineBuffer>())));
    
    plugin.AddProcessNode(1, node);
    auto result = plugin.ProcessBuffer(std::move(buffer));
    
    EXPECT_NE(result, nullptr);
}

/*
 * Feature: UnifiedPipelinePlugin
 * Function: ProcessBuffer
 * SubFunction: NA
 * FunctionPoints: Verify ordered processing
 * EnvConditions: NA
 * CaseDescription: Test processing buffer with multiple nodes in correct order.
 */
HWTEST_F(UnifiedPiplinePluginTest, ProcessBuffer_MultipleNodesOrder, TestSize.Level0)
{
    UnifiedPipelinePlugin plugin;
    auto node1 = std::make_shared<MockUnifiedPiplineProcessNode>();
    auto node2 = std::make_shared<MockUnifiedPiplineProcessNode>();
    auto buffer = std::make_unique<UnifiedPipelineBuffer>();
    
    // Set expectations for processing order
    testing::InSequence seq;
    EXPECT_CALL(*node1, ProcessBuffer(_))
        .WillOnce(Return(ByMove(std::make_unique<UnifiedPipelineBuffer>())));
    EXPECT_CALL(*node2, ProcessBuffer(_))
        .WillOnce(Return(ByMove(std::make_unique<UnifiedPipelineBuffer>())));
    
    plugin.AddProcessNode(1, node1);
    plugin.AddProcessNode(2, node2);
    auto result = plugin.ProcessBuffer(std::move(buffer));
    
    EXPECT_NE(result, nullptr);
}

/*
 * Feature: UnifiedPipelinePlugin
 * Function: ProcessBuffer
 * SubFunction: NA
 * FunctionPoints: Boundary condition
 * EnvConditions: NA
 * CaseDescription: Test processing buffer with no process nodes.
 */
HWTEST_F(UnifiedPiplinePluginTest, ProcessBuffer_NoNodes, TestSize.Level0)
{
    UnifiedPipelinePlugin plugin;
    auto buffer = std::make_unique<UnifiedPipelineBuffer>();
    auto bufferPtr = buffer.get();
    
    auto result = plugin.ProcessBuffer(std::move(buffer));
    
    // Should return the same buffer when no nodes are present
    EXPECT_EQ(result.get(), bufferPtr);
}

/*
 * Feature: UnifiedPipelinePlugin
 * Function: ProcessBuffer
 * SubFunction: NA
 * FunctionPoints: Boundary condition
 * EnvConditions: NA
 * CaseDescription: Test processing null buffer.
 */
HWTEST_F(UnifiedPiplinePluginTest, ProcessBuffer_NullBuffer, TestSize.Level0)
{
    UnifiedPipelinePlugin plugin;
    auto node = std::make_shared<MockUnifiedPiplineProcessNode>();
    plugin.AddProcessNode(1, node);
    
    // Node shouldn't be called with null buffer
    EXPECT_CALL(*node, ProcessBuffer(_)).Times(0);
    
    auto result = plugin.ProcessBuffer(nullptr);
    
    EXPECT_EQ(result, nullptr);
}
} // namespace CameraStandard
} // namespace OHOS
