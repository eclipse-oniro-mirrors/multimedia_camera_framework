/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "hmech_session.h"

#include "camera_log.h"
#include "camera_util.h"
#include "hcamera_session_manager.h"
#include "hcapture_session.h"

namespace OHOS {
namespace CameraStandard {

HMechSession::HMechSession(int32_t userId) : userId_(userId)
{
    MEDIA_INFO_LOG("HMechSession::HMechSession enter, userId:%{public}d", userId);
}

HMechSession::~HMechSession()
{
    MEDIA_INFO_LOG("HMechSession::~HMechSession enter");
}

int32_t HMechSession::EnableMechDelivery(bool isEnableMech)
{
    MEDIA_INFO_LOG("HMechSession::EnableMechDelivery enter, isEnableMech:%{public}d", isEnableMech);
    std::lock_guard<std::mutex> lock(enableLock_);
    this->isEnableMech_ = isEnableMech;
    auto &sessionManager = HCameraSessionManager::GetInstance();
    std::vector<sptr<HCaptureSession>> userSessions = sessionManager.GetUserSessions(userId_);
    for (size_t i = 0; i < userSessions.size(); i++) {
        sptr<HCaptureSession> captureSession = userSessions[i];
        captureSession->EnableMechDelivery(isEnableMech);
    }
    return CAMERA_OK;
}

int32_t HMechSession::SetCallback(const sptr<IMechSessionCallback>& callback)
{
    MEDIA_INFO_LOG("HMechSession::SetCallback enter");
    std::lock_guard<std::mutex> lock(callbackLock_);
    callback_ = callback;
    HandleCameraAppInfo(callback);
    return CAMERA_OK;
}

int32_t HMechSession::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_INFO_LOG("start, code:%{public}u", code);
    return CAMERA_OK;
}

int32_t HMechSession::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_INFO_LOG("leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}

int32_t HMechSession::Release()
{
    MEDIA_INFO_LOG("HMechSession::Release enter");
    sptr<IMechSessionCallback> emptyCallback = nullptr;
    SetCallback(emptyCallback);
    EnableMechDelivery(false);
    auto &sessionManager = HCameraSessionManager::GetInstance();
    sessionManager.RemoveMechSession(userId_);
    return CAMERA_OK;
}

int32_t HMechSession::OnFocusTrackingInfo(int32_t streamId, bool isNeedMirror, bool isNeedFlip,
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (callback_ != nullptr) {
        callback_->OnFocusTrackingInfo(streamId, isNeedMirror, isNeedFlip, result);
    }
    return CAMERA_OK;
}

int32_t HMechSession::OnCameraAppInfo(const std::vector<CameraAppInfo>& cameraAppInfos)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (callback_ != nullptr) {
        callback_->OnCameraAppInfo(cameraAppInfos);
    }
    return CAMERA_OK;
}

sptr<IMechSessionCallback> HMechSession::GetCallback()
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    return callback_;
}

bool HMechSession::IsEnableMech()
{
    return isEnableMech_;
}

void HMechSession::HandleCameraAppInfo(const sptr<IMechSessionCallback>& callback)
{
    if (callback == nullptr) {
        return;
    }
    auto &sessionManager = HCameraSessionManager::GetInstance();
    std::vector<sptr<HCaptureSession>> userSessions = sessionManager.GetUserSessions(userId_);
    std::vector<CameraAppInfo> cameraAppInfos = {};
    for (size_t i = 0; i < userSessions.size(); i++) {
        sptr<HCaptureSession> captureSession = userSessions[i];
        CameraAppInfo appInfo;
        if (captureSession->GetCameraAppInfo(appInfo)) {
            cameraAppInfos.emplace_back(appInfo);
        }
    }
    callback->OnCameraAppInfo(cameraAppInfos);
}
} // namespace CameraStandard
} // namespace OHOS
