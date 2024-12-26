/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#ifndef CAMERA_PRIVACY_H
#define CAMERA_PRIVACY_H

#include <refbase.h>
#include <memory>
#include "camera_util.h"
#include "accesstoken_kit.h"
#include "perm_state_change_callback_customize.h"
#include "privacy_error.h"
#include "privacy_kit.h"
#include "state_customized_cbk.h"

namespace OHOS {
namespace CameraStandard {
static const int32_t WAIT_RELEASE_STREAM_MS = 500; // 500ms
class HCameraDevice;
class PermissionStatusChangeCb : public Security::AccessToken::PermStateChangeCallbackCustomize {
public:
    explicit PermissionStatusChangeCb(
        wptr<HCameraDevice> device, const Security::AccessToken::PermStateChangeScope& scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo), cameraDevice_(device)
    {}
    virtual ~PermissionStatusChangeCb() = default;
    void PermStateChangeCallback(Security::AccessToken::PermStateChangeInfo& result) override;

private:
    wptr<HCameraDevice> cameraDevice_;
};

class CameraUseStateChangeCb : public Security::AccessToken::StateCustomizedCbk {
public:
    explicit CameraUseStateChangeCb(wptr<HCameraDevice> device) : cameraDevice_(device) {}
    virtual ~CameraUseStateChangeCb() = default;
    void StateChangeNotify(Security::AccessToken::AccessTokenID tokenId, bool isShowing) override;

private:
    wptr<HCameraDevice> cameraDevice_;
};

class CameraPrivacy : public RefBase {
public:
    explicit CameraPrivacy(wptr<HCameraDevice> device, uint32_t callingTokenId, int32_t pid)
        : pid_(pid), callerToken_(callingTokenId), cameraDevice_(device) {}
    ~CameraPrivacy();
    bool RegisterPermissionCallback();
    void UnregisterPermissionCallback();
    bool StartUsingPermissionCallback();
    void StopUsingPermissionCallback();
    bool AddCameraPermissionUsedRecord();
    bool IsAllowUsingCamera();

    inline std::cv_status WaitFor()
    {
        std::unique_lock<std::mutex> lock(canCloseMutex_);
        return canClose_.wait_for(lock, std::chrono::milliseconds(WAIT_RELEASE_STREAM_MS));
    }

    inline void Notify()
    {
        std::lock_guard<std::mutex> lock(canCloseMutex_);
        canClose_.notify_one();
    }

private:
    int32_t pid_;
    uint32_t callerToken_;
    wptr<HCameraDevice> cameraDevice_;
    std::condition_variable canClose_;
    std::mutex canCloseMutex_;
    std::mutex permissionCbMutex_;
    std::mutex cameraUseCbMutex_;
    std::shared_ptr<PermissionStatusChangeCb> permissionCallbackPtr_;
    std::shared_ptr<CameraUseStateChangeCb> cameraUseCallbackPtr_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_PRIVACY_H