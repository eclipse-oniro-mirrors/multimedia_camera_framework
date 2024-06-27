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

#include "camera_privacy.h"
#include "camera_log.h"
#include "hcamera_device.h"

namespace OHOS {
namespace CameraStandard {
using OHOS::Security::AccessToken::PrivacyKit;
using OHOS::Security::AccessToken::AccessTokenKit;

void PermissionStatusChangeCb::PermStateChangeCallback(Security::AccessToken::PermStateChangeInfo& result)
{
    auto device = cameraDevice_.promote();
    if ((result.permStateChangeType == 0) && (device != nullptr)) {
        device->Close();
    }
}

void CameraUseStateChangeCb::StateChangeNotify(Security::AccessToken::AccessTokenID tokenId, bool isShowing)
{
    MEDIA_INFO_LOG("enter CameraUseStateChangeNotify tokenId:%{public}d", tokenId);
    auto device = cameraDevice_.promote();
    if ((isShowing == false) && (device != nullptr)) {
        device->Close();
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

void CameraPrivacy::RegisterPermissionCallback()
{
    Security::AccessToken::PermStateChangeScope scopeInfo;
    scopeInfo.permList = {OHOS_PERMISSION_CAMERA};
    scopeInfo.tokenIDs = {callerToken_};
    permissionCallbackPtr_ = std::make_shared<PermissionStatusChangeCb>(cameraDevice_, scopeInfo);
    MEDIA_DEBUG_LOG("RegisterPermissionCallback tokenId:%{public}d register", callerToken_);
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(permissionCallbackPtr_);
    if (res != CAMERA_OK) {
        MEDIA_ERR_LOG("RegisterPermissionCallback failed.");
    }
}

void CameraPrivacy::UnregisterPermissionCallback()
{
    if (permissionCallbackPtr_ == nullptr) {
        MEDIA_ERR_LOG("permissionCallbackPtr_ is null.");
        return;
    }
    MEDIA_DEBUG_LOG("UnregisterPermissionCallback tokenId:%{public}d unregister", callerToken_);
    int32_t res = AccessTokenKit::UnRegisterPermStateChangeCallback(permissionCallbackPtr_);
    if (res != CAMERA_OK) {
        MEDIA_ERR_LOG("UnregisterPermissionCallback failed.");
    }
    permissionCallbackPtr_ = nullptr;
}

void CameraPrivacy::AddCameraPermissionUsedRecord()
{
    int32_t successCout = 1;
    int32_t failCount = 0;
    int32_t ret = PrivacyKit::AddPermissionUsedRecord(callerToken_, OHOS_PERMISSION_CAMERA, successCout, failCount);
    MEDIA_DEBUG_LOG("AddCameraPermissionUsedRecord tokenId:%{public}d", callerToken_);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("AddCameraPermissionUsedRecord failed.");
    }
}

void CameraPrivacy::StartUsingPermissionCallback()
{
    if (cameraUseCallbackPtr_) {
        MEDIA_ERR_LOG("has StartUsingPermissionCallback!");
        return;
    }
    cameraUseCallbackPtr_ = std::make_shared<CameraUseStateChangeCb>(cameraDevice_);
    int32_t res = PrivacyKit::StartUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA, cameraUseCallbackPtr_);
    MEDIA_DEBUG_LOG("after StartUsingPermissionCallback tokenId:%{public}d", callerToken_);
    if (res != CAMERA_OK) {
        MEDIA_ERR_LOG("StartUsingPermissionCallback failed.");
    }
}

void CameraPrivacy::StopUsingPermissionCallback()
{
    MEDIA_DEBUG_LOG("enter StopUsingPermissionCallback tokenId:%{public}d", callerToken_);
    int32_t res = PrivacyKit::StopUsingPermission(callerToken_, OHOS_PERMISSION_CAMERA);
    if (res != CAMERA_OK) {
        MEDIA_ERR_LOG("StopUsingPermissionCallback failed.");
    }
    cameraUseCallbackPtr_ = nullptr;
}
} // namespace CameraStandard
} // namespace OHOS