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

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include "camera_app_manager_utils.h"
#include "camera_privacy.h"
#include "camera_log.h"
#include "hcamera_device.h"
#include "hcapture_session.h"
#include "ipc_skeleton.h"
#include "types.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::Security::AccessToken::PrivacyKit;
using OHOS::Security::AccessToken::AccessTokenKit;

static const int32_t WAIT_RELEASE_STREAM_MS = 500; // 500ms
std::condition_variable g_canClose;
std::mutex g_mutex;

sptr<HCaptureSession> CastToSession(sptr<IStreamOperatorCallback> streamOpCb)
{
    if (streamOpCb == nullptr) {
        return nullptr;
    }
    return static_cast<HCaptureSession*>(streamOpCb.GetRefPtr());
}

void PermissionStatusChangeCb::PermStateChangeCallback(Security::AccessToken::PermStateChangeInfo& result)
{
    MEDIA_INFO_LOG("enter PermissionStatusChangeNotify permStateChangeType:%{public}d"
        " permissionName:%{public}s", result.permStateChangeType, result.permissionName.c_str());
    auto device = cameraDevice_.promote();
    if ((result.permStateChangeType == 0) && (device != nullptr)) {
        auto session = CastToSession(device->GetStreamOperatorCallback());
        if (session) {
            session->ReleaseStreams();
            session->StopMovingPhoto();
        }
        device->CloseDevice();
        device->OnError(DEVICE_PREEMPT, 0);
    }
}

void CameraUseStateChangeCb::StateChangeNotify(Security::AccessToken::AccessTokenID tokenId, bool isShowing)
{
    MEDIA_INFO_LOG("enter CameraUseStateChangeNotify");
    auto device = cameraDevice_.promote();
    if ((isShowing == true) || (device == nullptr)) {
        MEDIA_ERR_LOG("abnormal callback from privacy.");
        return;
    }
    std::cv_status waitStatus;
    {
        std::unique_lock<std::mutex> lock(g_mutex);
        waitStatus = g_canClose.wait_for(lock, std::chrono::milliseconds(WAIT_RELEASE_STREAM_MS));
    }
    if (waitStatus == std::cv_status::timeout) {
        MEDIA_INFO_LOG("CameraUseStateChangeCb::StateChangeNotify wait timeout");
        device = cameraDevice_.promote();
        bool isForeground = CameraAppManagerUtils::IsForegroundApplication(tokenId);
        if ((isShowing == false) && (device != nullptr) && !isForeground) {
            auto session = CastToSession(device->GetStreamOperatorCallback());
            if (session) {
                session->ReleaseStreams();
                session->StopMovingPhoto();
            }
            device->CloseDevice();
        }
    }
}

CameraPrivacy::~CameraPrivacy()
{
    cameraUseCallbackPtr_ = nullptr;
    permissionCallbackPtr_ = nullptr;
}

bool CameraPrivacy::IsAllowUsingCamera()
{
    return PrivacyKit::IsAllowedUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA);
}

bool CameraPrivacy::RegisterPermissionCallback()
{
    Security::AccessToken::PermStateChangeScope scopeInfo;
    scopeInfo.permList = {OHOS_PERMISSION_CAMERA};
    scopeInfo.tokenIDs = {callerToken_};
    permissionCallbackPtr_ = std::make_shared<PermissionStatusChangeCb>(cameraDevice_, scopeInfo);
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(permissionCallbackPtr_);
    MEDIA_INFO_LOG("CameraPrivacy::RegisterPermissionCallback res:%{public}d", res);
    CHECK_ERROR_PRINT_LOG(res != CAMERA_OK, "RegisterPermissionCallback failed.");
    return res == CAMERA_OK;
}

void CameraPrivacy::UnregisterPermissionCallback()
{
    CHECK_ERROR_RETURN_LOG(permissionCallbackPtr_ == nullptr, "permissionCallbackPtr_ is null.");
    MEDIA_DEBUG_LOG("UnregisterPermissionCallback unregister");
    int32_t res = AccessTokenKit::UnRegisterPermStateChangeCallback(permissionCallbackPtr_);
    MEDIA_INFO_LOG("CameraPrivacy::UnregisterPermissionCallback res:%{public}d", res);
    CHECK_ERROR_PRINT_LOG(res != CAMERA_OK, "UnregisterPermissionCallback failed.");
    permissionCallbackPtr_ = nullptr;
}

bool CameraPrivacy::AddCameraPermissionUsedRecord()
{
    int32_t successCout = 1;
    int32_t failCount = 0;
    int32_t res = PrivacyKit::AddPermissionUsedRecord(callerToken_, OHOS_PERMISSION_CAMERA, successCout, failCount);
    MEDIA_INFO_LOG("CameraPrivacy::AddCameraPermissionUsedRecord res:%{public}d", res);
    CHECK_ERROR_PRINT_LOG(res != CAMERA_OK, "AddCameraPermissionUsedRecord failed.");
    return res == CAMERA_OK;
}

bool CameraPrivacy::StartUsingPermissionCallback()
{
    CHECK_ERROR_RETURN_RET_LOG(cameraUseCallbackPtr_, true, "has StartUsingPermissionCallback!");
    cameraUseCallbackPtr_ = std::make_shared<CameraUseStateChangeCb>(cameraDevice_);
    int32_t res = PrivacyKit::StartUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA, cameraUseCallbackPtr_, pid_);
    MEDIA_INFO_LOG("CameraPrivacy::StartUsingPermissionCallback res:%{public}d", res);
    CHECK_ERROR_PRINT_LOG(res != CAMERA_OK, "StartUsingPermissionCallback failed.");
    return res == CAMERA_OK;
}

void CameraPrivacy::StopUsingPermissionCallback()
{
    int32_t res = PrivacyKit::StopUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA, pid_);
    MEDIA_INFO_LOG("CameraPrivacy::StopUsingPermissionCallback res:%{public}d", res);
    CHECK_ERROR_PRINT_LOG(res != CAMERA_OK, "StopUsingPermissionCallback failed.");
    cameraUseCallbackPtr_ = nullptr;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_canClose.notify_one();
}
} // namespace CameraStandard
} // namespace OHOS