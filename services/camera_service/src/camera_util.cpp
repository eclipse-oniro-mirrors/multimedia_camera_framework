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

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Composer::V1_1;

std::unordered_map<int32_t, int32_t> g_cameraToPixelFormat = {
    {OHOS_CAMERA_FORMAT_RGBA_8888, GRAPHIC_PIXEL_FMT_RGBA_8888},
    {OHOS_CAMERA_FORMAT_YCBCR_420_888, GRAPHIC_PIXEL_FMT_YCBCR_420_SP},
    {OHOS_CAMERA_FORMAT_YCRCB_420_SP, GRAPHIC_PIXEL_FMT_YCRCB_420_SP},
    {OHOS_CAMERA_FORMAT_JPEG, GRAPHIC_PIXEL_FMT_YCRCB_420_SP},
    {OHOS_CAMERA_FORMAT_YCBCR_P010, GRAPHIC_PIXEL_FMT_YCBCR_P010},
    {OHOS_CAMERA_FORMAT_YCRCB_P010, GRAPHIC_PIXEL_FMT_YCRCB_P010},
    {OHOS_CAMERA_FORMAT_YCBCR_420_SP, GRAPHIC_PIXEL_FMT_YCBCR_420_SP},
    {OHOS_CAMERA_FORMAT_422_YUYV, GRAPHIC_PIXEL_FMT_YUYV_422_PKG}
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
    {4, "JPEG"},
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

bool IsValidTokenId(uint32_t tokenId)
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
    if (srcHeader == nullptr) {
        return;
    }
    auto srcItemCount = srcHeader->item_count;
    camera_metadata_item_t item;
    for (uint32_t index = 0; index < srcItemCount; index++) {
        int ret = OHOS::Camera::GetCameraMetadataItem(srcHeader, index, &item);
        if (ret != CAM_META_SUCCESS) {
            MEDIA_ERR_LOG("Failed to get metadata item at index: %{public}d", index);
            return;
        }
        const char *name = OHOS::Camera::GetCameraMetadataItemName(item.item);
        if (name == nullptr) {
            MEDIA_DEBUG_LOG("U8ItemToString: get u8 item name fail!");
            return;
        }
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
    if (samgr == nullptr) {
        MEDIA_ERR_LOG("Get ability manager failed");
        return bundleName;
    }

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        MEDIA_DEBUG_LOG("object is NULL.");
        return bundleName;
    }

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    if (bms == nullptr) {
        MEDIA_DEBUG_LOG("bundle manager service is NULL.");
        return bundleName;
    }

    auto result = bms->GetNameForUid(uid, bundleName);
    if (result != ERR_OK) {
        MEDIA_ERR_LOG("GetBundleNameForUid fail");
        return "";
    }
    MEDIA_INFO_LOG("bundle name is %{public}s ", bundleName.c_str());

    return bundleName;
}

bool IsValidSize(
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility, int32_t format, int32_t width, int32_t height)
{
    bool isExtendConfig = false;
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(cameraAbility->get(),
                                             OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &item);
    if (ret == CAM_META_SUCCESS && item.count != 0) {
        isExtendConfig = true;
    } else {
        ret = Camera::FindCameraMetadataItem(cameraAbility->get(),
                                             OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
        if (ret != CAM_META_SUCCESS || item.count == 0) {
            MEDIA_ERR_LOG("Failed to find stream basic configuration in camera ability with return code %{public}d",
                          ret);
            return false;
        }
    }
    MEDIA_INFO_LOG("Success to find stream configuration isExtendConfig = %{public}d", isExtendConfig);
    uint32_t param2 = 2;
    for (uint32_t index = 0; index < item.count; index++) {
        if (item.data.i32[index] == format) {
            if (((index + 1) < item.count) && ((index + param2) < item.count) &&
                item.data.i32[index + 1] == width && item.data.i32[index + param2] == height) {
                MEDIA_INFO_LOG("Format:%{public}d, width:%{public}d, height:%{public}d found in supported streams",
                               format, width, height);
                return true;
            } else {
                continue;
            }
        } else {
            continue;
        }
    }
    MEDIA_ERR_LOG("Format:%{public}d, width:%{public}d, height:%{public}d not found in supported streams",
                  format, width, height);
    return false;
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
    if (IsValidTokenId(callerToken)) {
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
    MEDIA_INFO_LOG("AddPermissionUsedRecord tokenId:%{public}d", callingTokenId);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("AddPermissionUsedRecord failed.");
    }
}

bool IsVerticalDevice()
{
    bool isVerticalDevice = true;
    auto display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    if (display == nullptr) {
        MEDIA_ERR_LOG("IsVerticalDevice GetDefaultDisplay failed");
        return isVerticalDevice;
    }
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
} // namespace CameraStandard
} // namespace OHOS
