/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_UTIL_H
#define OHOS_CAMERA_UTIL_H
#define EXPORT_API __attribute__((visibility("default")))

#include <cstdint>
#include <iterator>
#include <limits.h>
#include <malloc.h>
#include <sstream>

#include "camera_metadata_info.h"
#include "display/graphic/common/v1_0/cm_color_space.h"
#include "safe_map.h"
#include "surface_type.h"
#include "v1_0/types.h"
#include "v1_1/types.h"
#include "v1_2/types.h"
#include "v1_3/types.h"

namespace OHOS {
namespace CameraStandard {
class HStreamCommon;
static constexpr int32_t HDI_VERSION_1 = 1;
static constexpr int32_t HDI_VERSION_2 = 2;
static constexpr int32_t HDI_VERSION_3 = 3;
static const int32_t STREAM_ROTATE_0 = 0;
static const int32_t STREAM_ROTATE_90 = 90;
static const int32_t STREAM_ROTATE_180 = 180;
static const int32_t STREAM_ROTATE_270 = 270;
static const int32_t STREAM_ROTATE_360 = 360;
static const int32_t DISPALY_ROTATE_0 = 0;
static const int32_t DISPALY_ROTATE_1 = 1;
static const int32_t DISPALY_ROTATE_2 = 2;
static const int32_t DISPALY_ROTATE_3 = 3;
static const std::string OHOS_PERMISSION_CAMERA = "ohos.permission.CAMERA";
static const std::string OHOS_PERMISSION_MANAGE_CAMERA_CONFIG = "ohos.permission.MANAGE_CAMERA_CONFIG";
static const std::string OHOS_PERMISSION_CAMERA_CONTROL = "ohos.permission.CAMERA_CONTROL";
static const std::string SYSTEM_CAMERA = "com.huawei.hmos.camera";
static const std::string CLIENT_USER_ID = "clientUserId";
static const std::string CAMERA_ID = "cameraId";
static const std::string CAMERA_STATE = "cameraState";
static const std::string IS_SYSTEM_CAMERA = "isSystemCamera";
// event
static const std::string COMMON_EVENT_CAMERA_STATUS = "usual.event.CAMERA_STATUS";

enum CamType {
    SYSTEM = 0,
    OTHER
};

enum CamStatus {
    CAMERA_OPEN = 0,
    CAMERA_CLOSE
};

enum CamServiceError {
    CAMERA_OK = 0,
    CAMERA_ALLOC_ERROR,
    CAMERA_INVALID_ARG,
    CAMERA_UNSUPPORTED,
    CAMERA_DEVICE_BUSY,
    CAMERA_DEVICE_CLOSED,
    CAMERA_DEVICE_REQUEST_TIMEOUT,
    CAMERA_STREAM_BUFFER_LOST,
    CAMERA_INVALID_SESSION_CFG,
    CAMERA_CAPTURE_LIMIT_EXCEED,
    CAMERA_INVALID_STATE,
    CAMERA_UNKNOWN_ERROR,
    CAMERA_DEVICE_PREEMPTED,
    CAMERA_OPERATION_NOT_ALLOWED,
    CAMERA_DEVICE_ERROR,
    CAMERA_NO_PERMISSION,
    CAMERA_DEVICE_CONFLICT,
    CAMERA_DEVICE_FATAL_ERROR,
    CAMERA_DEVICE_DRIVER_ERROR,
    CAMERA_DEVICE_DISCONNECT,
    CAMERA_DEVICE_SENSOR_DATA_ERROR,
    CAMERA_DCAMERA_ERROR_BEGIN,
    CAMERA_DCAMERA_ERROR_DEVICE_IN_USE,
    CAMERA_DCAMERA_ERROR_NO_PERMISSION,
};

enum ClientPriorityLevels {
    PRIORITY_LEVEL_SAME = 0,
    PRIORITY_LEVEL_LOWER,
    PRIORITY_LEVEL_HIGHER
};

enum DeviceType {
    FALLING_TYPE = 1,
    FOLD_TYPE
};

enum FallingState {
    FALLING_STATE = 1008,
};

extern std::unordered_map<int32_t, int32_t> g_cameraToPixelFormat;
extern std::map<int, std::string> g_cameraPos;
extern std::map<int, std::string> g_cameraType;
extern std::map<int, std::string> g_cameraConType;
extern std::map<int, std::string> g_cameraFormat;
extern std::map<int, std::string> g_cameraFocusMode;
extern std::map<int, std::string> g_cameraExposureMode;
extern std::map<int, std::string> g_cameraFlashMode;
extern std::map<int, std::string> g_cameraVideoStabilizationMode;
extern std::map<int, std::string> g_cameraPrelaunchAvailable;
extern std::map<int, std::string> g_cameraQuickThumbnailAvailable;
extern bool g_cameraDebugOn;

inline void DisableJeMalloc()
{
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_DISABLE);
    mallopt(M_DELAYED_FREE, M_DELAYED_FREE_DISABLE);
    mallopt(M_FLUSH_THREAD_CACHE, 0);
#endif
}

int32_t HdiToCameraErrorType(OHOS::HDI::Camera::V1_3::ErrorType type);

EXPORT_API int32_t HdiToServiceError(OHOS::HDI::Camera::V1_0::CamRetCode ret);

int32_t HdiToServiceErrorV1_2(HDI::Camera::V1_2::CamRetCode ret);

EXPORT_API std::string CreateMsg(const char* format, ...);

bool IsHapTokenId(uint32_t tokenId);

int32_t GetVersionId(uint32_t major, uint32_t minor);

bool IsValidMode(int32_t opMode, std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility);

void DumpMetadata(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraSettings);

std::string GetClientBundle(int uid);

int32_t JudgmentPriority(const pid_t& pid, const pid_t& pidCompared);

bool IsSameClient(const pid_t& pid, const pid_t& pidCompared);

bool IsInForeGround(const uint32_t callerToken);

EXPORT_API bool IsCameraNeedClose(const uint32_t callerToken, const pid_t& pid, const pid_t& pidCompared);

EXPORT_API int32_t CheckPermission(std::string permissionName, uint32_t callerToken);

void AddCameraPermissionUsedRecord(const uint32_t callingTokenId, const std::string permissionName);

bool IsVerticalDevice();

int32_t GetStreamRotation(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition, int& disPlayRotation,
    std::string& deviceClass);

bool CheckSystemApp();

inline bool IsCameraDebugOn()
{
    return g_cameraDebugOn;
}

inline void SetCameraDebugValue(bool value)
{
    g_cameraDebugOn = value;
}

template<typename T>
sptr<T> CastStream(sptr<HStreamCommon> streamCommon)
{
    if (streamCommon == nullptr) {
        return nullptr;
    }
    return static_cast<T*>(streamCommon.GetRefPtr());
}

template<typename Iter>
using return_container_iter_string_value =
    typename std::enable_if<std::is_convertible<typename std::iterator_traits<Iter>::value_type,
                                typename std::iterator_traits<Iter>::value_type>::value,
        std::string>::type;

template<typename Iter>
return_container_iter_string_value<Iter> Container2String(Iter first, Iter last)
{
    std::stringstream stringStream;
    stringStream << "[";
    bool isFirstElement = true;
    while (first != last) {
        if (isFirstElement) {
            stringStream << *first;
            isFirstElement = false;
        } else {
            stringStream << "," << *first;
        }
        first++;
    }
    stringStream << "]";
    return stringStream.str();
}
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_UTIL_H
