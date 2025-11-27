/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_DPS_BASIC_DEFINITIONS_H
#define OHOS_CAMERA_DPS_BASIC_DEFINITIONS_H

#include <cstdint>

#include "ideferred_photo_processing_session_callback.h"
#include "v1_4/types.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr int32_t DEFAULT_COUNT = 0;
constexpr int64_t DEFAULT_OFFSET = 0;
constexpr uint32_t INVALID_TIMERID = 0;
constexpr uint32_t DEFAULT_TRAILING_TIME = 0;
constexpr int32_t TOTAL_PROCESS_TIME = 10 * 60 * 1000;
constexpr int32_t ONCE_PROCESS_TIME = 5 * 60 * 1000;
constexpr uint32_t DELAY_TIME = 1000;
constexpr int32_t INVALID_TRACK_ID = -1;
inline constexpr char PATH[] = "/data/service/el1/public/camera_service/";
inline constexpr char TEMP_TAG[] = "_vid_temp";
inline constexpr char OUT_TAG[] = "_vid";

enum EventType : int32_t {
    CAMERA_SESSION_STATUS_EVENT = 1,
    PHOTO_HDI_STATUS_EVENT,
    VIDEO_HDI_STATUS_EVENT,
    MEDIA_LIBRARY_STATUS_EVENT,
    SCREEN_STATUS_EVENT,
    CHARGING_STATUS_EVENT,
    BATTERY_STATUS_EVENT,
    BATTERY_LEVEL_STATUS_EVENT,
    THERMAL_LEVEL_STATUS_EVENT,
    PHOTO_PROCESS_STATUS_EVENT,
    TRAILING_STATUS_EVENT,
    USER_INITIATED_EVENT,
    AVAILABLE_CONCURRENT_EVENT,
    PHOTO_CACHE_EVENT,
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
    MEDIA_LIBRARY_BUSY,
    MEDIA_LIBRARY_IDLE,
};

enum ScreenStatus : int32_t {
    SCREEN_ON = 0,
    SCREEN_OFF,
};

enum ChargingStatus : int32_t {
    DISCHARGING = 0,
    CHARGING,
};

enum BatteryStatus : int32_t {
    BATTERY_LOW = 0,
    BATTERY_OKAY,
};

enum BatteryLevel : int32_t {
    BATTERY_LEVEL_LOW = 0, // <= 50
    BATTERY_LEVEL_OKAY,
};

enum PhotoProcessStatus : int32_t {
    BUSY = 0, // > 0
    IDLE,
};

enum PhotoCacheStatus : int32_t {
    CACHED = 0,
    NO_CACHE,
};

enum ThermalLevel : int32_t {
    LEVEL_0 = 0,
    LEVEL_1,
    LEVEL_2,
    LEVEL_3,
    LEVEL_4,
    LEVEL_5,
    LEVEL_6,
    LEVEL_7
};

enum VideoThermalLevel : int8_t {
    HOT = 0,
    COOL
};

enum SystemPressureLevel : int32_t {
    NOMINAL = 0,
    FAIR,
    SEVERE
};

enum TrailingStatus : int32_t {
    CAMERA_ON_STOP_TRAILING = 0,
    SYSTEM_CAMERA_OFF_START_TRAILING,
    NORMAL_CAMERA_OFF_START_TRAILING
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
    DPS_ERROR_UNKNOW = -1,
    DPS_NO_ERROR = 0,
    // session specific error code
    DPS_ERROR_SESSION_SYNC_NEEDED = 1,
    DPS_ERROR_SESSION_NOT_READY_TEMPORARILY = 2,

    // process error code
    DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID = 3,
    DPS_ERROR_IMAGE_PROC_FAILED = 4,
    DPS_ERROR_IMAGE_PROC_TIMEOUT = 5,
    DPS_ERROR_IMAGE_PROC_HIGH_TEMPERATURE = 6,
    DPS_ERROR_IMAGE_PROC_ABNORMAL = 7,
    DPS_ERROR_IMAGE_PROC_INTERRUPTED = 8,

    DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID = 9,
    DPS_ERROR_VIDEO_PROC_FAILED = 10,
    DPS_ERROR_VIDEO_PROC_TIMEOUT = 11,
    DPS_ERROR_VIDEO_PROC_INTERRUPTED = 12,
};

enum DpsStatus : int32_t {
    DPS_SESSION_STATE_IDLE = 0,
    DPS_SESSION_STATE_RUNNABLE,
    DPS_SESSION_STATE_RUNNING,
    DPS_SESSION_STATE_SUSPENDED,
    DPS_SESSION_STATE_PREEMPTED
};

enum SessionType : int32_t {
    PHOTO_SESSION = 0,
    VIDEO_SESSION
};

enum ExecutionMode {
    HIGH_PERFORMANCE = 0,
    LOAD_BALANCE,
    LOW_POWER,
    DUMMY
};

enum SchedulerType : int32_t {
    REMOVE = -1,
    PHOTO_TRAILING_STATE = 0,
    PHOTO_CAMERA_STATE,
    PHOTO_HAL_STATE,
    PHOTO_MEDIA_LIBRARY_STATE,
    PHOTO_THERMAL_LEVEL_STATE,
    PHOTO_CACHE_STATE,
    VIDEO_CAMERA_STATE,
    VIDEO_HAL_STATE,
    VIDEO_MEDIA_LIBRARY_STATE,
    VIDEO_THERMAL_LEVEL_STATE,
    SCREEN_STATE,
    CHARGING_STATE,
    BATTERY_STATE,
    BATTERY_LEVEL_STATE,
    PHOTO_PROCESS_STATE,
    NORMAL_TIME_STATE
};

enum MediaManagerError : int32_t {
    ERROR_TIME_OUT = -3,
    ERROR_DEBUG_INFO = -2,
    ERROR_FAIL = -1,
    OK = 0,
    EOS = 1,
    RECOVER_EOS = 2,
    PAUSE_RECEIVED = 3,
    PAUSE_ABNORMAL = 4
};

enum MediaResult : int32_t {
    FAIL = -1,
    SUCCESS = 0,
    PAUSE = 1
};

enum class CallbackType {
    NONE = -1,
    IMAGE_PROCESS_DONE = 0,
    IMAGE_PROCESS_YUV_DONE,
    IMAGE_ERROR,
    ON_STATE_CHANGED,
    VIDEO_PROCESS_DONE,
    VIDEO_ERROR
};

enum class JobState {
    PENDING = 0,
    FAILED,
    RUNNING,
    COMPLETED,
    ERROR,
    NONE
};

enum class JobPriority {
    LOW = 0,
    NORMAL,
    HIGH,
    NONE
};

enum class PhotoJobType {
    BACKGROUND = 0,
    OFFLINE
};

ErrorCode MapDpsErrorCode(DpsError errorCode);
StatusCode MapDpsStatus(DpsStatus statusCode);
DpsError MapHdiError(HDI::Camera::V1_2::ErrorCode errorCode);
HdiStatus MapHdiStatus(HDI::Camera::V1_2::SessionStatus statusCode);
HDI::Camera::V1_2::ExecutionMode MapToHdiExecutionMode(ExecutionMode executionMode);
SystemPressureLevel ConvertPhotoThermalLevel(int32_t level);
VideoThermalLevel ConvertVideoThermalLevel(int32_t level);
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_BASIC_DEFINITIONS_H
