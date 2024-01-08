/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEFERRED_PROCESSING_SERVICE_BASIC_DEFINITIONS_H
#define OHOS_DEFERRED_PROCESSING_SERVICE_BASIC_DEFINITIONS_H


namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
enum EventType : int32_t {
    CAMERA_SESSION_STATUS_EVENT = 0,
    HDI_STATUS_EVENT = 1,
    MEDIA_LIBRARY_STATUS_EVENT = 2,
    SYSTEM_PRESSURE_LEVEL_EVENT = 3,
    USER_INITIATED_EVENT = 4,
    AVAILABLE_CONCURRENT_EVENT = 5,
};

enum CameraSessionStatus : int32_t {
    SYSTEM_CAMERA_OPEN = 0,
    NORMAL_CAMERA_OPEN,
    SYSTEM_CAMERA_CLOSED,
    NORMAL_CAMERA_CLOSED
};

enum HdiStatus : int32_t {
    HDI_DISCONNECTED = 0,
    HDI_READY,
    HDI_READY_SPACE_LIMIT_REACHED,
    HDI_NOT_READY_PREEMPTED,
    HDI_NOT_READY_OVERHEAT,
    HDI_NOT_READY_TEMPORARILY
};

enum MediaLibraryStatus : int32_t {
    MEDIA_LIBRARY_DISCONNECTED = 0,
    MEDIA_LIBRARY_AVAILABLE,
};

enum SystemPressureLevel : int32_t {
    NOMINAL = 0,
    FAIR,
    SEVERE
};

enum TrigerMode : int32_t {
    TRIGER_ACTIVE = 0,
    TRIGER_PASSIVE = 1,
};

enum ExceptionCause : int32_t {
    HDI_SERVICE_DIED = 0,
    HDI_JPEG_ERROR,
    HDI_NOT_HANDLE,
    HDI_TIMEOUT,
    HDI_TEMPORARILY_UNAVAILABLE,
    MEDIA_RECODER_EXCEPTION,
    MEDIA_NOT_ADDIMAGE,
    DEFPROCESS_INSUFFICIENT_RESOURCES,
    DEFPROCESS_IMAGE_TIMEOUT,
    DEFPROCESS_NOT_INIT,
};

enum ExceptionSource: int32_t {
    HDI_EXCEPTION = 0,
    APP_EXCEPTION,
    DEFPROCESS_EXCEPTION,
};

enum DpsError : int32_t {
    // session specific error code
    DPS_ERROR_SESSION_SYNC_NEEDED = 0,
    DPS_ERROR_SESSION_NOT_READY_TEMPORARILY = 1,

    // process error code
    DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID = 2,
    DPS_ERROR_IMAGE_PROC_FAILED = 3,
    DPS_ERROR_IMAGE_PROC_TIMEOUT = 4,
    DPS_ERROR_IMAGE_PROC_HIGH_TEMPERATURE = 5,
    DPS_ERROR_IMAGE_PROC_ABNORMAL = 6,
    DPS_ERROR_IMAGE_PROC_INTERRUPTED = 7,
};

enum DpsStatus : int32_t {
    DPS_SESSION_STATE_IDLE = 0,
    DPS_SESSION_STATE_RUNNALBE,
    DPS_SESSION_STATE_RUNNING,
    DPS_SESSION_STATE_SUSPENDED
};

enum SessionType : int32_t {
    PHOTO_SESSION = 0,
    VDIIDEO_SESSION
};
} //namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_DEFERRED_PROCESSING_SERVICE_BASIC_DEFINITIONS_H
