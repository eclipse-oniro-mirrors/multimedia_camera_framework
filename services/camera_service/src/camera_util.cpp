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
#include "camera_util.h"
#include <cstdint>
#include <securec.h>
#include <parameter.h>
#include <parameters.h>
#include "camera_log.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "display.h"
#include "display_manager.h"
#include "display/composer/v1_1/display_composer_type.h"
#include "iservice_registry.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Composer::V1_1;
static bool g_tablet = false;

std::unordered_map<int32_t, int32_t> g_cameraToPixelFormat = {
    {OHOS_CAMERA_FORMAT_RGBA_8888, GRAPHIC_PIXEL_FMT_RGBA_8888},
    {OHOS_CAMERA_FORMAT_YCBCR_420_888, GRAPHIC_PIXEL_FMT_YCBCR_420_SP},
    {OHOS_CAMERA_FORMAT_YCRCB_420_SP, GRAPHIC_PIXEL_FMT_YCRCB_420_SP}, // NV21
    {OHOS_CAMERA_FORMAT_JPEG, GRAPHIC_PIXEL_FMT_BLOB},
    {OHOS_CAMERA_FORMAT_YCBCR_P010, GRAPHIC_PIXEL_FMT_YCBCR_P010},
    {OHOS_CAMERA_FORMAT_YCRCB_P010, GRAPHIC_PIXEL_FMT_YCRCB_P010},
    {OHOS_CAMERA_FORMAT_YCBCR_420_SP, GRAPHIC_PIXEL_FMT_YCBCR_420_SP},
    {OHOS_CAMERA_FORMAT_422_YUYV, GRAPHIC_PIXEL_FMT_YUYV_422_PKG},
    {OHOS_CAMERA_FORMAT_DEPTH_16, GRAPHIC_PIXEL_FMT_RGBA16_FLOAT},
    {OHOS_CAMERA_FORMAT_DNG, GRAPHIC_PIXEL_FMT_BLOB},
};

std::map<int, std::string> g_cameraPos = {
    {0, "Front"},
    {1, "Back"},
    {2, "Other"},
};

std::map<int, std::string> g_cameraType = {
    {0, "Wide-Angle"},
    {1, "Ultra-Wide"},
    {2, "TelePhoto"},
    {3, "TrueDepth"},
    {4, "Logical"},
    {5, "Unspecified"},
};

std::map<int, std::string> g_cameraConType = {
    {0, "Builtin"},
    {1, "USB-Plugin"},
    {2, "Remote"},
};

std::map<int, std::string> g_cameraFormat = {
    {1, "RGBA_8888"},
    {2, "YCBCR_420_888"},
    {3, "YCRCB_420_SP"},
    {4, "YCBCR_420_SP"},
    {5, "JPEG"},
    {6, "YCBCR_P010"},
    {7, "YCRCB_P010"},
    {8, "DNG"},
    {9, "422_YUYV"},
};

std::map<int, std::string> g_cameraFocusMode = {
    {0, "Manual"},
    {1, "Continuous-Auto"},
    {2, "Auto"},
    {3, "Locked"},
};

std::map<int, std::string> g_cameraExposureMode = {
    {0, "Manual"},
    {1, "Continuous-Auto"},
    {2, "Locked"},
    {3, "Auto"},
};

std::map<int, std::string> g_cameraFlashMode = {
    {0, "Close"},
    {1, "Open"},
    {2, "Auto"},
    {3, "Always-Open"},
};

std::map<int, std::string> g_cameraVideoStabilizationMode = {
    {0, "Off"},
    {1, "Low"},
    {2, "Middle"},
    {3, "High"},
    {4, "Auto"},
};

std::map<int, std::string> g_cameraPrelaunchAvailable = {
    {0, "False"},
    {1, "True"},
};

std::map<int, std::string> g_cameraQuickThumbnailAvailable = {
    {0, "False"},
    {1, "True"},
};

bool g_cameraDebugOn = false;

int32_t HdiToCameraErrorType(OHOS::HDI::Camera::V1_3::ErrorType type)
{
    enum CamServiceError err = CAMERA_UNKNOWN_ERROR;

    switch (type) {
        case HDI::Camera::V1_3::FATAL_ERROR:
            err = CAMERA_DEVICE_FATAL_ERROR;
            break;
        case HDI::Camera::V1_3::REQUEST_TIMEOUT:
            err = CAMERA_DEVICE_REQUEST_TIMEOUT;
            break;
        case HDI::Camera::V1_3::DRIVER_ERROR:
            err = CAMERA_DEVICE_DRIVER_ERROR;
            break;
        case HDI::Camera::V1_3::DEVICE_PREEMPT:
            err = CAMERA_DEVICE_PREEMPTED;
            break;
        case HDI::Camera::V1_3::DEVICE_DISCONNECT:
            err = CAMERA_DEVICE_DISCONNECT;
            break;
        case HDI::Camera::V1_3::SENSOR_DATA_ERROR:
            err = CAMERA_DEVICE_SENSOR_DATA_ERROR;
            break;
        case HDI::Camera::V1_3::DCAMERA_ERROR_BEGIN:
            err = CAMERA_DCAMERA_ERROR_BEGIN;
            break;
        case HDI::Camera::V1_3::DCAMERA_ERROR_DEVICE_IN_USE:
            err = CAMERA_DCAMERA_ERROR_DEVICE_IN_USE;
            break;
        case HDI::Camera::V1_3::DCAMERA_ERROR_NO_PERMISSION:
            err = CAMERA_DCAMERA_ERROR_NO_PERMISSION;
            break;
        default:
            MEDIA_ERR_LOG("HdiToCameraType() error type from hdi: %{public}d", type);
            break;
    }
    return err;
}

int32_t HdiToServiceError(OHOS::HDI::Camera::V1_0::CamRetCode ret)
{
    enum CamServiceError err = CAMERA_UNKNOWN_ERROR;

    switch (ret) {
        case HDI::Camera::V1_0::NO_ERROR:
            err = CAMERA_OK;
            break;
        case HDI::Camera::V1_0::CAMERA_BUSY:
            err = CAMERA_DEVICE_BUSY;
            break;
        case HDI::Camera::V1_0::INVALID_ARGUMENT:
            err = CAMERA_INVALID_ARG;
            break;
        case HDI::Camera::V1_0::CAMERA_CLOSED:
            err = CAMERA_DEVICE_CLOSED;
            break;
        default:
            MEDIA_ERR_LOG("HdiToServiceError() error code from hdi: %{public}d", ret);
            break;
    }
    return err;
}

int32_t HdiToServiceErrorV1_2(HDI::Camera::V1_2::CamRetCode ret)
{
    enum CamServiceError err = CAMERA_UNKNOWN_ERROR;

    switch (ret) {
        case HDI::Camera::V1_2::NO_ERROR:
            err = CAMERA_OK;
            break;
        case HDI::Camera::V1_2::CAMERA_BUSY:
            err = CAMERA_DEVICE_BUSY;
            break;
        case HDI::Camera::V1_2::INVALID_ARGUMENT:
            err = CAMERA_INVALID_ARG;
            break;
        case HDI::Camera::V1_2::CAMERA_CLOSED:
            err = CAMERA_DEVICE_CLOSED;
            break;
        case HDI::Camera::V1_2::DEVICE_ERROR:
            err = CAMERA_DEVICE_ERROR;
            break;
        case HDI::Camera::V1_2::NO_PERMISSION:
            err = CAMERA_NO_PERMISSION;
            break;
        case HDI::Camera::V1_2::DEVICE_CONFLICT:
            err = CAMERA_DEVICE_CONFLICT;
            break;
        default:
            MEDIA_ERR_LOG("HdiToServiceErrorV1_2() error code from hdi: %{public}d", ret);
            break;
    }
    return err;
}

std::string CreateMsg(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    char msg[MAX_STRING_SIZE] = {0};
    if (vsnprintf_s(msg, sizeof(msg), sizeof(msg) - 1, format, args) < 0) {
        MEDIA_ERR_LOG("failed to call vsnprintf_s");
        va_end(args);
        return "";
    }
    va_end(args);
    return msg;
}

bool IsHapTokenId(uint32_t tokenId)
{
    return Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId) ==
        Security::AccessToken::ATokenTypeEnum::TOKEN_HAP;
}

bool IsValidMode(int32_t opMode, std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    if (opMode == 0) { // 0 is normal mode
        MEDIA_INFO_LOG("operationMode:%{public}d", opMode);
        return true;
    }
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_CAMERA_MODES, &item);
    if (ret != CAM_META_SUCCESS || item.count == 0) {
        MEDIA_ERR_LOG("Failed to find stream extend configuration in camera ability with return code %{public}d", ret);
        ret = Camera::FindCameraMetadataItem(cameraAbility->get(),
                                             OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
        if (ret == CAM_META_SUCCESS && item.count != 0) {
            MEDIA_INFO_LOG("basic config no need valid mode");
            return true;
        }
        return false;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        if (opMode == item.data.u8[i]) {
            MEDIA_INFO_LOG("operationMode:%{public}d found in supported streams", opMode);
            return true;
        }
    }
    MEDIA_ERR_LOG("operationMode:%{public}d not found in supported streams", opMode);
    return false;
}

void DumpMetadata(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraSettings)
{
    if (cameraSettings == nullptr) {
        return;
    }
    auto srcHeader = cameraSettings->get();
    CHECK_ERROR_RETURN(srcHeader == nullptr);
    auto srcItemCount = srcHeader->item_count;
    camera_metadata_item_t item;
    for (uint32_t index = 0; index < srcItemCount; index++) {
        int ret = OHOS::Camera::GetCameraMetadataItem(srcHeader, index, &item);
        CHECK_ERROR_RETURN_LOG(ret != CAM_META_SUCCESS, "Failed to get metadata item at index: %{public}d", index);
        const char *name = OHOS::Camera::GetCameraMetadataItemName(item.item);
        CHECK_ERROR_RETURN_LOG(name == nullptr, "U8ItemToString: get u8 item name fail!");
        if (item.data_type == META_TYPE_BYTE) {
            for (size_t k = 0; k < item.count; k++) {
                MEDIA_DEBUG_LOG("tag index:%d, name:%s, value:%d", item.index, name, (uint8_t)(item.data.u8[k]));
            }
        } else if (item.data_type == META_TYPE_INT32) {
            for (size_t k = 0; k < item.count; k++) {
                MEDIA_DEBUG_LOG("tag index:%d, name:%s, value:%d", item.index, name, (int32_t)(item.data.i32[k]));
            }
        } else if (item.data_type == META_TYPE_UINT32) {
            for (size_t k = 0; k < item.count; k++) {
                MEDIA_DEBUG_LOG("tag index:%d, name:%s, value:%d", item.index, name, (uint32_t)(item.data.ui32[k]));
            }
        } else if (item.data_type == META_TYPE_FLOAT) {
            for (size_t k = 0; k < item.count; k++) {
                MEDIA_DEBUG_LOG("tag index:%d, name:%s, value:%f", item.index, name, (float)(item.data.f[k]));
            }
        } else if (item.data_type == META_TYPE_INT64) {
            for (size_t k = 0; k < item.count; k++) {
                MEDIA_DEBUG_LOG("tag index:%d, name:%s, value:%lld", item.index, name, (long long)(item.data.i64[k]));
            }
        } else if (item.data_type == META_TYPE_DOUBLE) {
            for (size_t k = 0; k < item.count; k++) {
                MEDIA_DEBUG_LOG("tag index:%d, name:%s, value:%lf", item.index, name, (double)(item.data.d[k]));
            }
        } else {
            MEDIA_DEBUG_LOG("tag index:%d, name:%s", item.index, name);
        }
    }
}

std::string GetClientBundle(int uid)
{
    std::string bundleName = "";
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_RET_LOG(samgr == nullptr, bundleName, "GetClientBundle Get ability manager failed");

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHECK_ERROR_RETURN_RET_LOG(object == nullptr, bundleName, "GetClientBundle object is NULL.");

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    CHECK_ERROR_RETURN_RET_LOG(bms == nullptr, bundleName, "GetClientBundle bundle manager service is NULL.");

    auto result = bms->GetNameForUid(uid, bundleName);
    CHECK_ERROR_RETURN_RET_LOG(result != ERR_OK, "", "GetClientBundle GetBundleNameForUid fail");
    MEDIA_INFO_LOG("bundle name is %{public}s ", bundleName.c_str());

    return bundleName;
}

int32_t JudgmentPriority(const pid_t& pid, const pid_t& pidCompared)
{
    return PRIORITY_LEVEL_SAME;
}

bool IsSameClient(const pid_t& pid, const pid_t& pidCompared)
{
    return (pid == pidCompared);
}

bool IsInForeGround(const uint32_t callerToken)
{
    bool isAllowed = true;
    if (IPCSkeleton::GetCallingUid() == 0) {
        MEDIA_DEBUG_LOG("HCameraService::IsInForeGround isAllowed!");
        return isAllowed;
    }
    if (IsHapTokenId(callerToken)) {
        isAllowed = Security::AccessToken::PrivacyKit::IsAllowedUsingPermission(callerToken, OHOS_PERMISSION_CAMERA);
    }
    return isAllowed;
}

bool IsCameraNeedClose(const uint32_t callerToken, const pid_t& pid, const pid_t& pidCompared)
{
    bool needClose = !(IsInForeGround(callerToken) && (JudgmentPriority(pid, pidCompared) != PRIORITY_LEVEL_HIGHER));
    if (Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken) ==
        Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        needClose = true;
    }
    MEDIA_INFO_LOG("IsCameraNeedClose pid = %{public}d, IsInForeGround = %{public}d, TokenType = %{public}d, "
                   "needClose = %{public}d",
                   pid, IsInForeGround(callerToken),
                   Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken), needClose);
    return needClose;
}

int32_t CheckPermission(const std::string permissionName, uint32_t callerToken)
{
    int permissionResult
        = OHOS::Security::AccessToken::TypePermissionState::PERMISSION_DENIED;
    Security::AccessToken::ATokenTypeEnum tokenType
        = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if ((tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE)
        || (tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_HAP)) {
        permissionResult = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(
            callerToken, permissionName);
    } else {
        MEDIA_ERR_LOG("HCameraService::CheckPermission: Unsupported Access Token Type");
        return CAMERA_INVALID_ARG;
    }

    if (permissionResult != OHOS::Security::AccessToken::TypePermissionState::PERMISSION_GRANTED) {
        MEDIA_ERR_LOG("HCameraService::CheckPermission: Permission to Access Camera Denied!!!!");
        return CAMERA_OPERATION_NOT_ALLOWED;
    } else {
        MEDIA_DEBUG_LOG("HCameraService::CheckPermission: Permission to Access Camera Granted!!!!");
    }
    return CAMERA_OK;
}

int32_t GetVersionId(uint32_t major, uint32_t minor)
{
    const uint32_t offset = 8;
    return static_cast<int32_t>((major << offset) | minor);
}

void AddCameraPermissionUsedRecord(const uint32_t callingTokenId, const std::string permissionName)
{
    int32_t successCout = 1;
    int32_t failCount = 0;
    int32_t ret = Security::AccessToken::PrivacyKit::AddPermissionUsedRecord(callingTokenId, permissionName,
        successCout, failCount);
    MEDIA_INFO_LOG("AddPermissionUsedRecord");
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("AddPermissionUsedRecord failed.");
    }
}

bool IsVerticalDevice()
{
    bool isVerticalDevice = true;
    auto display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay();

    CHECK_ERROR_RETURN_RET_LOG(display == nullptr, isVerticalDevice, "IsVerticalDevice GetDefaultDisplay failed");
    MEDIA_INFO_LOG("GetDefaultDisplay:W(%{public}d),H(%{public}d),Orientation(%{public}d),Rotation(%{public}d)",
                   display->GetWidth(), display->GetHeight(), display->GetOrientation(), display->GetRotation());
    bool isScreenVertical = display->GetRotation() == OHOS::Rosen::Rotation::ROTATION_0 ||
                            display->GetRotation() == OHOS::Rosen::Rotation::ROTATION_180;
    bool isScreenHorizontal = display->GetRotation() == OHOS::Rosen::Rotation::ROTATION_90 ||
                              display->GetRotation() == OHOS::Rosen::Rotation::ROTATION_270;
    isVerticalDevice = (isScreenVertical && (display->GetWidth() < display->GetHeight())) ||
                            (isScreenHorizontal && (display->GetWidth() > display->GetHeight()));
    return isVerticalDevice;
}

int32_t GetStreamRotation(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition, int& disPlayRotation,
    std::string& deviceClass)
{
    int32_t streamRotation = sensorOrientation;
    int degrees = 0;

    switch (disPlayRotation) {
        case DISPALY_ROTATE_0: degrees = STREAM_ROTATE_0; break;
        case DISPALY_ROTATE_1: degrees = STREAM_ROTATE_90; break;
        case DISPALY_ROTATE_2: degrees = STREAM_ROTATE_180; break;
        case DISPALY_ROTATE_3: degrees = STREAM_ROTATE_270; break; // 逆时针转90
    }

    g_tablet = (deviceClass == "tablet");
    if (cameraPosition == OHOS_CAMERA_POSITION_FRONT) {
        sensorOrientation = g_tablet ? sensorOrientation + STREAM_ROTATE_90 : sensorOrientation;
        streamRotation = (STREAM_ROTATE_360 + sensorOrientation - degrees) % STREAM_ROTATE_360;
    } else {
        sensorOrientation = g_tablet ? sensorOrientation - STREAM_ROTATE_90 : sensorOrientation;
        streamRotation = (sensorOrientation + degrees) % STREAM_ROTATE_360;
        streamRotation = (STREAM_ROTATE_360 - streamRotation) % STREAM_ROTATE_360;
    }
    MEDIA_DEBUG_LOG("HStreamRepeat::SetStreamTransform filp streamRotation %{public}d, rotate %{public}d",
        streamRotation, disPlayRotation);
    return streamRotation;
}

bool CheckSystemApp()
{
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::ATokenTypeEnum tokenType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType !=  Security::AccessToken::TOKEN_HAP) {
        MEDIA_DEBUG_LOG("Caller is not a application.");
        return true;
    }
    uint64_t accessTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool isSystemApplication = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenId);
    MEDIA_DEBUG_LOG("isSystemApplication:%{public}d", isSystemApplication);
    return isSystemApplication;
}
} // namespace CameraStandard
} // namespace OHOS
