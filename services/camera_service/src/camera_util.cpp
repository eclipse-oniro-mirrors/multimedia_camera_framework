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
#include <fstream>
#include <regex>
#include <securec.h>
#include <string>
#include <sys/stat.h>
#include <exception>
#include <parameter.h>
#include <parameters.h>
#include "camera_log.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "display_manager_lite.h"
#include "applist_manager/camera_applist_manager.h"
#include "display/composer/v1_1/display_composer_type.h"
#include "iservice_registry.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Display::Composer::V1_1;
using namespace OHOS::Security::AccessToken;
static bool g_tablet = true;
std::unordered_map<int32_t, int32_t> g_cameraToPixelFormat = {
    {OHOS_CAMERA_FORMAT_RGBA_8888, GRAPHIC_PIXEL_FMT_RGBA_8888},
    {OHOS_CAMERA_FORMAT_YCBCR_420_888, GRAPHIC_PIXEL_FMT_YCBCR_420_SP},
    {OHOS_CAMERA_FORMAT_YCRCB_420_SP, GRAPHIC_PIXEL_FMT_YCRCB_420_SP}, // NV21
    {OHOS_CAMERA_FORMAT_JPEG, GRAPHIC_PIXEL_FMT_BLOB},
    {OHOS_CAMERA_FORMAT_YCBCR_P010, GRAPHIC_PIXEL_FMT_YCBCR_P010},
    {OHOS_CAMERA_FORMAT_YCRCB_P010, GRAPHIC_PIXEL_FMT_YCRCB_P010},
    {OHOS_CAMERA_FORMAT_YCBCR_420_SP, GRAPHIC_PIXEL_FMT_YCBCR_420_SP},
    {OHOS_CAMERA_FORMAT_422_YUYV, GRAPHIC_PIXEL_FMT_YUYV_422_PKG},
    {OHOS_CAMERA_FORMAT_422_UYVY, GRAPHIC_PIXEL_FMT_UYVY_422_PKG},
    {OHOS_CAMERA_FORMAT_DEPTH_16, GRAPHIC_PIXEL_FMT_RGBA16_FLOAT},
    {OHOS_CAMERA_FORMAT_DNG, GRAPHIC_PIXEL_FMT_BLOB},
    {OHOS_CAMERA_FORMAT_DNG_XDRAW, GRAPHIC_PIXEL_FMT_BLOB},
    {OHOS_CAMERA_FORMAT_MJPEG, GRAPHIC_PIXEL_FMT_BLOB},
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

std::map<int, std::string> g_cameraQualityPrioritization = {
    {0, "HighQuality"},
    {1, "PowerBalance"},
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
        MEDIA_DEBUG_LOG("failed to call vsnprintf_s");
        va_end(args);
        return "";
    }
    va_end(args);
    return msg;
}

bool IsHapTokenId(uint32_t tokenId)
{
    return AccessTokenKit::GetTokenTypeFlag(tokenId) == ATokenTypeEnum::TOKEN_HAP;
}

bool IsValidMode(int32_t opMode, std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    // 0 is normal mode, 1 is capture mode, 2 is video mode, TODO: remove this stub || opMode == 24
    CHECK_RETURN_RET_ILOG(opMode == 0 || opMode == 1 || opMode == 2, true, "operationMode:%{public}d", opMode);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_ABILITY_CAMERA_MODES, &item);
    bool isFindMetadata = ret != CAM_META_SUCCESS || item.count == 0;
    if (isFindMetadata) {
        MEDIA_ERR_LOG("Failed to find stream extend configuration in camera ability with return code %{public}d", ret);
        ret = Camera::FindCameraMetadataItem(cameraAbility->get(),
                                             OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
        CHECK_RETURN_RET_ILOG(ret == CAM_META_SUCCESS && item.count != 0, true, "basic config no need valid mode");
        return false;
    }

    for (uint32_t i = 0; i < item.count; i++) {
        CHECK_RETURN_RET_ILOG(
            opMode == item.data.u8[i], true, "operationMode:%{public}d found in supported streams", opMode);
    }
    MEDIA_ERR_LOG("operationMode:%{public}d not found in supported streams", opMode);
    return false;
}

void DumpMetadata(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraSettings)
{
    CHECK_RETURN(cameraSettings == nullptr);
    auto srcHeader = cameraSettings->get();
    CHECK_RETURN(srcHeader == nullptr);
    auto srcItemCount = srcHeader->item_count;
    camera_metadata_item_t item;
    for (uint32_t index = 0; index < srcItemCount; index++) {
        int ret = OHOS::Camera::GetCameraMetadataItem(srcHeader, index, &item);
        CHECK_RETURN_ELOG(ret != CAM_META_SUCCESS, "Failed to get metadata item at index: %{public}d", index);
        const char *name = OHOS::Camera::GetCameraMetadataItemName(item.item);
        CHECK_RETURN_ELOG(name == nullptr, "U8ItemToString: get u8 item name fail!");
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
    CHECK_RETURN_RET_ELOG(samgr == nullptr, bundleName, "GetClientBundle Get ability manager failed");

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHECK_RETURN_RET_ELOG(object == nullptr, bundleName, "GetClientBundle object is NULL.");

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    CHECK_RETURN_RET_ELOG(bms == nullptr, bundleName, "GetClientBundle bundle manager service is NULL.");

    auto result = bms->GetNameForUid(uid, bundleName);
    CHECK_RETURN_RET_DLOG(result != ERR_OK, "", "GetClientBundle GetBundleNameForUid fail");
    MEDIA_INFO_LOG("bundle name is %{public}s ", bundleName.c_str());

    return bundleName;
}

std::string GetClientNameByToken(int tokenIdNum)
{
    using namespace Security::AccessToken;
    AccessTokenID tokenId = static_cast<AccessTokenID>(tokenIdNum);
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenType(tokenId);
    if (tokenType == TOKEN_HAP) {
        HapTokenInfo hapTokenInfo = {};
        int32_t ret = AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
        CHECK_RETURN_RET_ELOG(ret != 0, "unknown", "GetHapTokenInfo fail, ret %{public}d", ret);
        return hapTokenInfo.bundleName;
    } else if (tokenType == TOKEN_NATIVE) {
        NativeTokenInfo nativeTokenInfo = {};
        int ret = AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
        CHECK_RETURN_RET_ELOG(ret != 0, "unknown", "GetNativeTokenInfo fail, ret %{public}d", ret);
        return nativeTokenInfo.processName;
    } else {
        MEDIA_ERR_LOG("unexpected token type %{public}d", tokenType);
        return "unknown";
    }
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
    CHECK_RETURN_RET_DLOG(IPCSkeleton::GetCallingUid() == 0, isAllowed, "HCameraService::IsInForeGround isAllowed!");
    if (IsHapTokenId(callerToken)) {
        isAllowed = PrivacyKit::IsAllowedUsingPermission(callerToken, OHOS_PERMISSION_CAMERA);
    }
    return isAllowed;
}

bool IsCameraNeedClose(const uint32_t callerToken, const pid_t& pid, const pid_t& pidCompared)
{
    bool needClose = !(IsInForeGround(callerToken) && (JudgmentPriority(pid, pidCompared) != PRIORITY_LEVEL_HIGHER));
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == ATokenTypeEnum::TOKEN_NATIVE) {
        needClose = true;
    }
    MEDIA_INFO_LOG("IsCameraNeedClose pid = %{public}d, IsInForeGround = %{public}d, TokenType = %{public}d, "
                   "needClose = %{public}d", pid, IsInForeGround(callerToken), tokenType, needClose);
    return needClose;
}

int32_t CheckPermission(const std::string permissionName, uint32_t callerToken)
{
    int permissionResult = TypePermissionState::PERMISSION_DENIED;
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == ATokenTypeEnum::TOKEN_NATIVE || tokenType == ATokenTypeEnum::TOKEN_HAP) {
        permissionResult = AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    } else {
        MEDIA_ERR_LOG("HCameraService::CheckPermission: Unsupported Access Token Type");
        return CAMERA_INVALID_ARG;
    }

    if (permissionResult != TypePermissionState::PERMISSION_GRANTED) {
        MEDIA_ERR_LOG("HCameraService::CheckPermission: Permission to Access Camera Denied!!!!");
        return CAMERA_NO_PERMISSION;
    } else {
        MEDIA_DEBUG_LOG("HCameraService::CheckPermission: Permission to Access Camera Granted!!!!");
    }
    return CAMERA_OK;
}

void AddCameraPermissionUsedRecord(const uint32_t callingTokenId, const std::string permissionName)
{
    int32_t successCout = 1;
    int32_t failCount = 0;
    int32_t ret = PrivacyKit::AddPermissionUsedRecord(callingTokenId, permissionName, successCout, failCount);
    MEDIA_INFO_LOG("AddPermissionUsedRecord");
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "AddPermissionUsedRecord failed.");
}
bool IsVerticalDevice()
{
    bool isVerticalDevice = true;
    sptr<OHOS::Rosen::DisplayLite> display;
    int32_t displayId = -1;
    auto ret = GetDisplayId(displayId);
    if (ret == CAMERA_OK && displayId != -1) {
        auto innerDisplayId = static_cast<OHOS::Rosen::DisplayId>(displayId);
        display = OHOS::Rosen::DisplayManagerLite::GetInstance().GetDisplayById(innerDisplayId);
    }
    CHECK_RETURN_RET_ELOG(display == nullptr, isVerticalDevice, "IsVerticalDevice display is nullptr");
    MEDIA_DEBUG_LOG("GetDefaultDisplay:W(%{public}d),H(%{public}d),Rotation(%{public}d)",
        display->GetWidth(), display->GetHeight(), display->GetRotation());
    bool isScreenVertical = display->GetRotation() == OHOS::Rosen::Rotation::ROTATION_0 ||
        display->GetRotation() == OHOS::Rosen::Rotation::ROTATION_180;
    bool isScreenHorizontal = display->GetRotation() == OHOS::Rosen::Rotation::ROTATION_90 ||
        display->GetRotation() == OHOS::Rosen::Rotation::ROTATION_270;
    isVerticalDevice = (isScreenVertical && (display->GetWidth() < display->GetHeight())) ||
        (isScreenHorizontal && (display->GetWidth() > display->GetHeight()));
    return isVerticalDevice;
}

int32_t GetStreamRotation(int32_t& sensorOrientation, camera_position_enum_t& cameraPosition, int& displayRotation,
    std::string& deviceClass)
{
    int32_t streamRotation = sensorOrientation;
    int degrees = 0;

    switch (displayRotation) {
        case DISPLAY_ROTATE_0: degrees = STREAM_ROTATE_0; break;
        case DISPLAY_ROTATE_1: degrees = STREAM_ROTATE_90; break;
        case DISPLAY_ROTATE_2: degrees = STREAM_ROTATE_180; break;
        case DISPLAY_ROTATE_3: degrees = STREAM_ROTATE_270; break; // 逆时针转90
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
        streamRotation, displayRotation);
    return streamRotation;
}

bool CheckSystemApp()
{
    AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(callerToken);
    CHECK_RETURN_RET_DLOG(tokenType != TOKEN_HAP, true, "Caller is not a application.");
    uint64_t accessTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool isSystemApplication = TokenIdKit::IsSystemAppByFullTokenID(accessTokenId);
    MEDIA_DEBUG_LOG("isSystemApplication:%{public}d", isSystemApplication);
    return isSystemApplication;
}

std::vector<std::string> SplitString(const std::string& input, char delimiter)
{
    std::vector<std::string> result;
    std::stringstream ss(input);
    std::string token;

    while (std::getline(ss, token, delimiter)) {
        result.push_back(token);
    }
    return result;
}

int64_t GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return duration.count();
}

std::string GetFileStream(const std::string &filepath)
{
    char *canonicalPath = realpath(filepath.c_str(), nullptr);
    CHECK_RETURN_RET(canonicalPath == nullptr, "");
    std::ifstream file(canonicalPath, std::ios::in | std::ios::binary);
    free(canonicalPath);
    // 文件流的异常处理，不能用try catch的形式
    CHECK_RETURN_RET_ILOG(!file, "", "Failed to open the file!");
    std::stringstream infile;
    infile << file.rdbuf();
    const std::string fileString = infile.str();
    CHECK_RETURN_RET(fileString.empty(), "");
    return fileString;
}
 
std::vector<std::string> SplitStringWithPattern(const std::string &str, const char& pattern)
{
    std::stringstream iss(str);
    std::vector<std::string> result;
    std::string token;
    while (getline(iss, token, pattern)) {
        result.emplace_back(token);
    }
    return result;
}
 
void TrimString(std::string &inputStr)
{
    inputStr.erase(inputStr.begin(),
        std::find_if(inputStr.begin(), inputStr.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    inputStr.erase(
        std::find_if(inputStr.rbegin(), inputStr.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(),
        inputStr.end());
}
 
bool RemoveFile(const std::string& path)
{
    char *canonicalPath = realpath(path.c_str(), nullptr);
    CHECK_RETURN_RET(canonicalPath == nullptr, false);
    if (remove(canonicalPath) == 0) {
        free(canonicalPath);
        MEDIA_INFO_LOG("File removed successfully.");
        return true;
    }
    free(canonicalPath);
    return false;
}

bool CheckPathExist(const char *path)
{
    char *canonicalPath = realpath(path, nullptr);
    CHECK_RETURN_RET_ELOG(canonicalPath == nullptr, false, "CheckPathExist path is nullptr");
    std::ifstream profileStream(canonicalPath);
    free(canonicalPath);
    return profileStream.good();
}

bool isIntegerRegex(const std::string& input)
{
    size_t start = 0;
    CHECK_RETURN_RET(input.empty(), false);
    if (input[0] == '-' && input.size() > 1) {
        start = 1; // deal negative sign
    }
    for (size_t i = start; i < input.size(); ++i) {
        CHECK_RETURN_RET(!std::isdigit(input[i]), false);
    }
    return true;
}

bool IsDoubleRegex(const std::string& input)
{
    std::istringstream iss(input);
    double val;
    iss >> val;
    return iss.eof() && !iss.fail();
}

bool IsUint8Regex(const std::string& input)
{
    CHECK_RETURN_RET(!isIntegerRegex(input), false);
    int number = std::stoi(input);
    return (number >= MIN_UINT8) && (number <= MAX_UINT8);
}

std::string GetValidCameraId(std::string& cameraId)
{
    std::string cameraIdTemp = cameraId;
    size_t pos = cameraId.find('/');
    CHECK_RETURN_RET(pos == std::string::npos, cameraId);
    cameraIdTemp = cameraId.substr(pos + 1);
    return cameraIdTemp;
}

std::string ControlCenterMapToString(const std::map<std::string, std::array<float, CONTROL_CENTER_DATA_SIZE>> &data)
{
    std::ostringstream oss;
    bool first_entry = true;
    for (const auto& [key, arr] : data) {
        if (!first_entry) oss << ';';
        first_entry = false;
        oss << key << ':'
            << std::setprecision(CONTROL_CENTER_DATA_PRECISION) << arr[CONTROL_CENTER_STATUS_INDEX] << ','
            << std::setprecision(CONTROL_CENTER_DATA_PRECISION) << arr[CONTROL_CENTER_BEAUTY_INDEX] << ','
            << std::setprecision(CONTROL_CENTER_DATA_PRECISION) << arr[CONTROL_CENTER_APERTURE_INDEX];
    }
    return oss.str();
}

std::map<std::string, std::array<float, CONTROL_CENTER_DATA_SIZE>> StringToControlCenterMap(const std::string& str)
{
    std::map<std::string, std::array<float, CONTROL_CENTER_DATA_SIZE>> result;
    std::istringstream iss(str);
    std::string entry;
    
    while (std::getline(iss, entry, ';')) {
        if (entry.empty()){
            continue;
        } 
        size_t colon_pos = entry.find(':');
        if (colon_pos == std::string::npos) {
            continue;
        }
        std::string key = entry.substr(0, colon_pos);
        std::string values_str = entry.substr(colon_pos + 1);
        
        std::istringstream vss(values_str);
        std::array<float, CONTROL_CENTER_DATA_SIZE> arr;
        std::string num_str;
        int index = 0;
        bool conversion_failed = false;
        while (std::getline(vss, num_str, ',') && index < CONTROL_CENTER_DATA_SIZE) {
            char* endptr;
            errno = 0;
            float value = std::strtof(num_str.c_str(), &endptr);
            
            if (endptr != num_str.c_str() + num_str.size() || errno == ERANGE) {
                MEDIA_ERR_LOG("Conversion failed");
                conversion_failed = true;
                break;
            }
            arr[index++] = value;
        }
        
        if (!conversion_failed && index == CONTROL_CENTER_DATA_SIZE && vss.eof()) {
            result[key] = arr;
        }
    }
    return result;
}

int32_t DisplayModeToFoldStatus(int32_t displayMode)
{
    int32_t foldStatus = static_cast<int32_t>(OHOS::Rosen::FoldStatus::UNKNOWN);
    switch (displayMode) {
        case static_cast<int32_t>(OHOS::Rosen::FoldDisplayMode::MAIN): {
            foldStatus = static_cast<int32_t>(OHOS::Rosen::FoldStatus::FOLDED);
            break;
        }
        case static_cast<int32_t>(OHOS::Rosen::FoldDisplayMode::COORDINATION):
        case static_cast<int32_t>(OHOS::Rosen::FoldDisplayMode::FULL): {
            foldStatus = static_cast<int32_t>(OHOS::Rosen::FoldStatus::EXPAND);
            break;
        }
        case static_cast<int32_t>(OHOS::Rosen::FoldDisplayMode::GLOBAL_FULL): {
            foldStatus = static_cast<int32_t>(OHOS::Rosen::FoldStatus::FOLD_STATE_EXPAND_WITH_SECOND_EXPAND);
            break;
        }
        default: {
            foldStatus = static_cast<int32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldStatus());
            break;
        }
    }
    MEDIA_DEBUG_LOG("DisplayModeToFoldStatus, displayMode: %{public}d , foldStatus: %{public}d",
        displayMode, foldStatus);
    return foldStatus;
}

int32_t GetPhysicalOrientationByFoldAndDirection(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility,
    int32_t& sensorOrientation, int32_t foldStatus, std::string clientName)
{
    camera_metadata_item item;

    int32_t ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(),
        OHOS_FOLD_STATE_AND_NATURAL_DIRECTION_SENSOR_ORIENTATION_MAP, &item);
    CHECK_RETURN_RET_DLOG(ret != CAMERA_OK, ret,
        "GetPhysicalOrientationByFoldAndDirection FindCameraMetadataItem Failed");
    int32_t count = item.count;
    CHECK_RETURN_RET_ELOG(count % MAP_STEP_NINE, CAMERA_INVALID_STATE,
        "GetPhysicalOrientationByFoldAndDirection FindCameraMetadataItem Count 9 Error");
    int32_t unitLength = count / MAP_STEP_NINE;
    int32_t targetNaturalDirection = 0;
    CameraApplistManager::GetInstance()->GetAppNaturalDirectionByBundleName(clientName, targetNaturalDirection);

    for (int32_t index = 0; index < unitLength; index++) {
        int32_t innerFoldState = item.data.i32[index * MAP_STEP_NINE];
        CHECK_CONTINUE(innerFoldState != foldStatus);
        std::vector<int32_t> orientationWithNaturalDirection = {};
        for (int32_t i = 1; i <= MAP_STEP_FOUR * MAP_STEP_TWO; i++) {
            orientationWithNaturalDirection.emplace_back(item.data.i32[index * MAP_STEP_NINE + i]);
        }
        CHECK_RETURN_RET_ELOG(orientationWithNaturalDirection.size() != MAP_STEP_FOUR * MAP_STEP_TWO,
            CAMERA_INVALID_STATE, "GetPhysicalOrientationByFoldAndDirection vector size error");
        for (int32_t index = 0; index < MAP_STEP_FOUR; index++) {
            int32_t innerNaturalDirection = orientationWithNaturalDirection[index * MAP_STEP_TWO];
            CHECK_CONTINUE(innerNaturalDirection != targetNaturalDirection);
            sensorOrientation = orientationWithNaturalDirection[index * MAP_STEP_TWO + MAP_STEP_ONE];
            MEDIA_DEBUG_LOG("GetPhysicalOrientationByFoldAndDirection naturalDirection: %{public}d, foldStatus: "
                "%{public}d, orientation: %{public}d", targetNaturalDirection, foldStatus, sensorOrientation);
            return CAMERA_OK;
        }
    }
    MEDIA_ERR_LOG("GetPhysicalOrientationByFoldAndDirection failed");
    return CAMERA_INVALID_STATE;
}

int32_t GetPhysicalCameraOrientation(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility,
    int32_t& sensorOrientation, std::string clientName, int32_t displayMode)
{
    camera_metadata_item item;
    displayMode = displayMode >= 0 ? displayMode :
        static_cast<int32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldDisplayMode());
    int32_t curFoldStatus = DisplayModeToFoldStatus(displayMode);
    int32_t ret = GetPhysicalOrientationByFoldAndDirection(cameraAbility, sensorOrientation, curFoldStatus, clientName);
    CHECK_RETURN_RET(ret == CAMERA_OK, CAMERA_OK);
    ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_FOLD_STATE_SENSOR_ORIENTATION_MAP,
        &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || !item.count, ret, "CameraUtil::GetPhysicalCameraOrientation "
        "FindCameraMetadataItem Error");
    uint32_t count = item.count;
    CHECK_RETURN_RET_ELOG(count % MAP_STEP_TWO, ret, "CameraUtil::GetPhysicalCameraOrientation FindCameraMetadataItem "
        "Count Error");
    ret = CAM_META_FAILURE;
    for (uint32_t index = 0; index < count / MAP_STEP_TWO; index++) {
        int32_t innerFoldState = static_cast<int32_t>(item.data.i32[MAP_STEP_TWO * index]);
        int32_t innerOrientation = item.data.i32[MAP_STEP_TWO * index + MAP_STEP_ONE];
        if (curFoldStatus == innerFoldState) {
            sensorOrientation = innerOrientation;
            ret = CAM_META_SUCCESS;
            break;
        }
    }
    return ret;
}

int32_t GetCorrectedCameraOrientation(bool usePhysicalCameraOrientation,  int32_t& sensorOrientation,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility, std::string clientName, int32_t displayMode)
{
    int32_t ret = CAM_META_FAILURE;
    CHECK_RETURN_RET(cameraAbility == nullptr, ret);
    CHECK_EXECUTE(usePhysicalCameraOrientation, ret =
        GetPhysicalCameraOrientation(cameraAbility, sensorOrientation, clientName, displayMode));
    CHECK_RETURN_RET(ret == CAM_META_SUCCESS, CAM_META_SUCCESS);

    camera_metadata_item item;
    ret = OHOS::Camera::FindCameraMetadataItem(cameraAbility->get(), OHOS_SENSOR_ORIENTATION, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || !item.count, ret, "CameraUtil::GetCameraOrientation get "
        "sensor orientation failed");
    sensorOrientation = item.data.i32[0];
    return ret;
}

int32_t GetDisplayId(int32_t& displayId)
{
    auto displayIds = OHOS::Rosen::DisplayManagerLite::GetInstance().GetAllDisplayIds();
    MEDIA_DEBUG_LOG("GetDisplayId displayIds: %{public}s",
        Container2String(displayIds.begin(), displayIds.end()).c_str());
    for (auto innerDisplayId : displayIds) {
        MEDIA_DEBUG_LOG("GetDisplayId displayId: %{public}" PRIu64 "", innerDisplayId);
        bool isOnboardDisplay = false;
        auto retCode = OHOS::Rosen::DisplayManagerLite::GetInstance().IsOnboardDisplay(innerDisplayId,
            isOnboardDisplay);
        MEDIA_DEBUG_LOG("GetDisplayId IsOnboardDisplay retCode: %{public}d, isOnboardDisplay: %{public}d",
            retCode, isOnboardDisplay);
        CHECK_CONTINUE(retCode != OHOS::Rosen::DMError::DM_OK || !isOnboardDisplay);
        displayId = static_cast<int32_t>(innerDisplayId);
        return CAMERA_OK;
    }
    MEDIA_ERR_LOG("GetDisplayId Get Display Failed");
    return CAMERA_INVALID_STATE;
}

int32_t GetDisplayRotation(int32_t& displayRotation)
{
    auto displayIds = OHOS::Rosen::DisplayManagerLite::GetInstance().GetAllDisplayIds();
    MEDIA_DEBUG_LOG("GetDisplayRotation displayIds: %{public}s",
        Container2String(displayIds.begin(), displayIds.end()).c_str());
    for (auto displayId : displayIds) {
        MEDIA_DEBUG_LOG("GetDisplayRotation displayId: %{public}" PRIu64 "", displayId);
        bool isOnboardDisplay = false;
        auto retCode = OHOS::Rosen::DisplayManagerLite::GetInstance().IsOnboardDisplay(displayId, isOnboardDisplay);
        MEDIA_DEBUG_LOG("GetDisplayRotation IsOnboardDisplay retCode: %{public}d, isOnboardDisplay: %{public}d",
            retCode, isOnboardDisplay);
        CHECK_CONTINUE(retCode != OHOS::Rosen::DMError::DM_OK || !isOnboardDisplay);
        auto display = OHOS::Rosen::DisplayManagerLite::GetInstance().GetDisplayById(displayId);
        CHECK_RETURN_RET_ELOG(
            display == nullptr, CAMERA_INVALID_STATE, "GetDisplayRotation display is nullptr");
        displayRotation = static_cast<int32_t>(display->GetRotation());
        return CAMERA_OK;
    }
    MEDIA_ERR_LOG("GetDisplayRotation Get Display Failed");
    return CAMERA_INVALID_STATE;
}
} // namespace CameraStandard
} // namespace OHOS
