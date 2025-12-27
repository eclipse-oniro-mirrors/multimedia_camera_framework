/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CAMERA_WORKER_QUEUE_KEEPER_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CAMERA_WORKER_QUEUE_KEEPER_TAIHE_H

#include <list>
#include <mutex>

namespace Ani {
namespace Camera {
enum CameraTaskId {
    CAMERA_MANAGER_TASKID = 0x01000000,
    CAMERA_INPUT_TASKID = 0x02000000,
    CAMERA_PHOTO_OUTPUT_TASKID = 0x03000000,
    CAMERA_PREVIEW_OUTPUT_TASKID = 0x04000000,
    CAMERA_VIDEO_OUTPUT_TASKID = 0x05000000,
    CAMERA_SESSION_TASKID = 0x06000000,
    MODE_MANAGER_TASKID = 0x07000000,
    CAMERA_PICKER_TASKID = 0x08000000,
    PHOTO_TASKID = 0x09000000,
    DEFERRED_PHOTO_PROXY_TASKID = 0x0A000000,
    CAMERA_DEPTH_DATA_OUTPUT_TASKID = 0x0B000000,
    DEPTH_DATA_TASKID = 0x0C000000,
    CAMERA_METADATA_OUTPUT_TASKID = 0x0D000000,
    CAMERA_MOVIE_FILE_OUTPUT_TASKID = 0x0E000000,
    CAMERA_UNIFY_MOVIE_FILE_OUTPUT_TASKID = 0x0F000000,
};

typedef std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds> TaiheWorkerQueueTaskTimePoint;
enum TaiheWorkerQueueStatus : int32_t { INIT = 0, RUNNING, DONE };
struct TaiheWorkerQueueTask {
    explicit TaiheWorkerQueueTask(std::string taskName) : taskName(taskName)
    {
        createTimePoint = std::chrono::steady_clock::now();
    }

    std::string taskName;
    int32_t waitCount = 0;
    TaiheWorkerQueueTaskTimePoint createTimePoint;
    TaiheWorkerQueueStatus queueStatus = INIT;
};

struct TaiheAsyncContext {
public:
    TaiheAsyncContext() = default;
    TaiheAsyncContext(std::string funcName, int32_t taskId) : funcName(funcName), taskId(taskId) {};

    virtual ~TaiheAsyncContext() = default;
    std::string funcName;
    int32_t taskId = 0;
    int32_t errorCode = 0;
    bool status = false;
    std::shared_ptr<TaiheWorkerQueueTask> queueTask = nullptr;
};
class CameraTaiheWorkerQueueKeeper {
public:
    explicit CameraTaiheWorkerQueueKeeper() = default;
    virtual ~CameraTaiheWorkerQueueKeeper() = default;
    static std::shared_ptr<CameraTaiheWorkerQueueKeeper> GetInstance();

    std::shared_ptr<TaiheWorkerQueueTask> AcquireWorkerQueueTask(const std::string& taskName);
    bool ConsumeWorkerQueueTask(std::shared_ptr<TaiheWorkerQueueTask> queueTask, std::function<void(void)> func);

private:
    void WorkerQueueTasksResetCreateTimeNoLock(TaiheWorkerQueueTaskTimePoint timePoint);
    bool WorkerLockCondition(std::shared_ptr<TaiheWorkerQueueTask> queueTask, bool& isError);

    std::mutex workerQueueMutex_;
    std::condition_variable workerCond_;

    std::mutex workerQueueTaskMutex_;
    std::list<std::shared_ptr<TaiheWorkerQueueTask>> workerQueueTasks_;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_CAMERA_WORKER_QUEUE_KEEPER_TAIHE_H