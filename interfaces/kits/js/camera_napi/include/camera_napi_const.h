/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef CAMERA_NAPI_CONST_UTILS_H
#define CAMERA_NAPI_CONST_UTILS_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi/native_api.h"

namespace OHOS {
namespace CameraStandard {
/* Constants for array index */
const int32_t PARAM0 = 0;
const int32_t PARAM1 = 1;
const int32_t PARAM2 = 2;

/* Constants for array size */
const int32_t ARGS_ZERO = 0;
const int32_t ARGS_ONE = 1;
const int32_t ARGS_TWO = 2;
const int32_t ARGS_THREE = 3;
const size_t ARGS_MAX_SIZE = 20;
const int32_t SIZE = 100;

typedef std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds> NapiWorkerQueueTaskTimePoint;
enum NapiWorkerQueueStatus : int32_t { INIT = 0, RUNNING, DONE };
struct NapiWorkerQueueTask {
    explicit NapiWorkerQueueTask(std::string taskName) : taskName(taskName)
    {
        createTimePoint = std::chrono::steady_clock::now();
    }

    std::string taskName;
    NapiWorkerQueueTaskTimePoint createTimePoint;
    NapiWorkerQueueStatus queueStatus = INIT;
};

struct AsyncContext {
public:
    AsyncContext() = default;
    AsyncContext(std::string funcName, int32_t taskId) : funcName(funcName), taskId(taskId) {};

    virtual ~AsyncContext() = default;

    std::string funcName;
    int32_t taskId = 0;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    bool status = false;

    int32_t errorCode = 0;
    std::shared_ptr<NapiWorkerQueueTask> queueTask;
    std::string errorMsg;
};

struct JSAsyncContextOutput {
    napi_value error;
    napi_value data;
    bool status;
    std::string funcName;
};

enum JSQualityLevel { QUALITY_LEVEL_HIGH = 0, QUALITY_LEVEL_MEDIUM, QUALITY_LEVEL_LOW };

enum JSImageRotation { ROTATION_0 = 0, ROTATION_90 = 90, ROTATION_180 = 180, ROTATION_270 = 270 };

enum JSCameraStatus {
    JS_CAMERA_STATUS_APPEAR = 0,
    JS_CAMERA_STATUS_DISAPPEAR = 1,
    JS_CAMERA_STATUS_AVAILABLE = 2,
    JS_CAMERA_STATUS_UNAVAILABLE = 3
};

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
};

enum JSMetadataObjectType { INVALID = -1, FACE = 0 };

enum CameraSteps {
    CREATE_CAMERA_INPUT_INSTANCE,
    CREATE_PREVIEW_OUTPUT_INSTANCE,
    CREATE_PHOTO_OUTPUT_INSTANCE,
    CREATE_VIDEO_OUTPUT_INSTANCE,
    CREATE_METADATA_OUTPUT_INSTANCE,
    ADD_INPUT,
    REMOVE_INPUT,
    ADD_OUTPUT,
    REMOVE_OUTPUT,
    PHOTO_OUT_CAPTURE,
    PHOTO_OUT_BURST_CAPTURE,
    ADD_DEFERRED_SURFACE,
    CREATE_DEFERRED_PREVIEW_OUTPUT
};
} // namespace CameraStandard
} // namespace OHOS
#endif