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
#include "hcamera_device_manager.h"
#include "hcapture_session.h"
#include "hstream_operator.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::Security::AccessToken::PrivacyKit;
using OHOS::Security::AccessToken::AccessTokenKit;

sptr<HStreamOperator> CastToSession(wptr<IStreamOperatorCallback> streamOpCb)
{
    CHECK_RETURN_RET_ELOG(streamOpCb == nullptr, nullptr, "streamOpCb is nullptr");
    auto streamOpCbSptr = streamOpCb.promote();
    CHECK_RETURN_RET_ELOG(streamOpCbSptr == nullptr, nullptr, "streamOpCbWptr is nullptr");

    return static_cast<HStreamOperator*>(streamOpCbSptr.GetRefPtr());
}

void PermissionStatusChangeCb::PermStateChangeCallback(Security::AccessToken::PermStateChangeInfo& result)
{
    MEDIA_INFO_LOG("enter CameraUseStateChangeNotify permStateChangeType:%{public}d"
        " permissionName:%{public}s", result.permStateChangeType, result.permissionName.c_str());
    std::vector<sptr<HCameraDeviceHolder>> holders = HCameraDeviceManager::GetInstance()->GetActiveCameraHolders();
    for (auto holder : holders) {
        if (holder->GetAccessTokenId() != result.tokenID) {
            MEDIA_INFO_LOG("PermissionStatusChangeCb::PermStateChangeCallback not current tokenId, checking continue");
            continue;
        }
        auto device = holder->GetDevice();
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
}

void CameraUseStateChangeCb::StateChangeNotify(Security::AccessToken::AccessTokenID tokenId, bool isShowing)
{
    MEDIA_INFO_LOG("CameraUseStateChangeCb::StateChangeNotify is called, isShowing: %{public}d", isShowing);
    std::vector<sptr<HCameraDeviceHolder>> holders = HCameraDeviceManager::GetInstance()->GetActiveCameraHolders();
    for (auto holder : holders) {
        if (holder->GetAccessTokenId() != tokenId) {
            MEDIA_INFO_LOG("CameraUseStateChangeCb::StateChangeNotify not current tokenId, checking continue");
            continue;
        }
        auto device = holder->GetDevice();
        CHECK_RETURN_ELOG((isShowing == true) || (device == nullptr), "abnormal callback from privacy.");
        auto cameraPrivacy = device->GetCameraPrivacy();
        CHECK_RETURN_ELOG(cameraPrivacy == nullptr, "cameraPrivacy is nullptr.");
        bool isSystemCamera = (cameraPrivacy->GetClientName().find(CAMERA_TAG) != std::string::npos)
            && CheckSystemApp();
        MEDIA_INFO_LOG("CameraUseStateChangeCb::StateChangeNotify ClientName: %{public}s, isSystemCamera: %{public}d",
            cameraPrivacy->GetClientName().c_str(), isSystemCamera);
        if (cameraPrivacy->WaitFor(isSystemCamera) == std::cv_status::timeout) {
            MEDIA_INFO_LOG("CameraUseStateChangeCb::StateChangeNotify wait timeout");
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

void CameraPrivacy::SetClientName(std::string clientName)
{
    clientName_ = clientName;
}

bool CameraPrivacy::RegisterPermissionCallback()
{
    Security::AccessToken::PermStateChangeScope scopeInfo;
    scopeInfo.permList = {OHOS_PERMISSION_CAMERA};
    scopeInfo.tokenIDs = {callerToken_};
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(permissionCbMutex_);
        permissionCallbackPtr_ = std::make_shared<PermissionStatusChangeCb>(scopeInfo);
        res = AccessTokenKit::RegisterPermStateChangeCallback(permissionCallbackPtr_);
    }
    MEDIA_INFO_LOG("CameraPrivacy::RegisterPermissionCallback res:%{public}d", res);
    CHECK_PRINT_ELOG(res != CAMERA_OK, "RegisterPermissionCallback failed.");
    return res == CAMERA_OK;
}

void CameraPrivacy::UnregisterPermissionCallback()
{
    std::lock_guard<std::mutex> lock(permissionCbMutex_);
    CHECK_RETURN_ELOG(permissionCallbackPtr_ == nullptr, "permissionCallbackPtr_ is null.");
    MEDIA_DEBUG_LOG("UnregisterPermissionCallback unregister");
    int32_t res = AccessTokenKit::UnRegisterPermStateChangeCallback(permissionCallbackPtr_);
    MEDIA_INFO_LOG("CameraPrivacy::UnregisterPermissionCallback res:%{public}d", res);
    CHECK_PRINT_ELOG(res != CAMERA_OK, "UnregisterPermissionCallback failed.");
    permissionCallbackPtr_ = nullptr;
}

bool CameraPrivacy::AddCameraPermissionUsedRecord()
{
    int32_t successCout = 1;
    int32_t failCount = 0;
    int32_t res = PrivacyKit::AddPermissionUsedRecord(callerToken_, OHOS_PERMISSION_CAMERA, successCout, failCount);
    MEDIA_INFO_LOG("CameraPrivacy::AddCameraPermissionUsedRecord res:%{public}d", res);
    CHECK_PRINT_ELOG(res != CAMERA_OK, "AddCameraPermissionUsedRecord failed.");
    return res == CAMERA_OK;
}

bool CameraPrivacy::StartUsingPermissionCallback()
{
    int32_t res;
    {
        std::lock_guard<std::mutex> lock(cameraUseCbMutex_);
        CHECK_RETURN_RET_ELOG(cameraUseCallbackPtr_, true, "has StartUsingPermissionCallback!");
        cameraUseCallbackPtr_ = std::make_shared<CameraUseStateChangeCb>();
        res = PrivacyKit::StartUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA, cameraUseCallbackPtr_, pid_);
    }
    MEDIA_INFO_LOG("CameraPrivacy::StartUsingPermissionCallback res:%{public}d", res);
    bool ret = (res == CAMERA_OK || res == Security::AccessToken::ERR_EDM_POLICY_CHECK_FAILED ||
        res == Security::AccessToken::ERR_PRIVACY_POLICY_CHECK_FAILED);
    CHECK_PRINT_ELOG(!ret, "StartUsingPermissionCallback failed.");
    return ret;
}

void CameraPrivacy::StopUsingPermissionCallback()
{
    MEDIA_INFO_LOG("CameraPrivacy::StopUsingPermissionCallback is called, pid_: %{public}d", pid_);
    {
        std::lock_guard<std::mutex> lock(cameraUseCbMutex_);
        int32_t res = PrivacyKit::StopUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA, pid_);
        MEDIA_INFO_LOG("CameraPrivacy::StopUsingPermissionCallback res:%{public}d", res);
        CHECK_PRINT_ELOG(res != CAMERA_OK, "StopUsingPermissionCallback failed.");
        cameraUseCallbackPtr_ = nullptr;
    }
    Notify();
}
} // namespace CameraStandard
} // namespace OHOS