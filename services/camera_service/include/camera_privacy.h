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

#define CAMERA_TAG ".camera"

namespace OHOS {
namespace CameraStandard {
static const int32_t WAIT_RELEASE_STREAM_MS = 500; // 500ms
static const int32_t WAIT_RELEASE_STREAM_MS_FOR_SYSTEM_CAMERA = 1500; // 1500ms
class HCameraDevice;

class DisablePolicyChangeCb : public Security::AccessToken::DisablePolicyChangeCallback {
public:
    explicit DisablePolicyChangeCb(const std::vector<std::string> &permList)
        : DisablePolicyChangeCallback(permList) {}
    virtual ~DisablePolicyChangeCb() = default;
    void PermDisablePolicyCallback(const Security::AccessToken::PermDisablePolicyInfo& info) override;
};

class PermissionStatusChangeCb : public Security::AccessToken::PermStateChangeCallbackCustomize {
public:
    explicit PermissionStatusChangeCb(const Security::AccessToken::PermStateChangeScope& scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo) {}
    virtual ~PermissionStatusChangeCb() = default;
    void PermStateChangeCallback(Security::AccessToken::PermStateChangeInfo& result) override;
};

class CameraUseStateChangeCb : public Security::AccessToken::StateCustomizedCbk {
public:
    explicit CameraUseStateChangeCb() {}
    virtual ~CameraUseStateChangeCb() = default;
    void StateChangeNotify(Security::AccessToken::AccessTokenID tokenId, bool isShowing) override;
};

class CameraPrivacy : public RefBase {
public:
    explicit CameraPrivacy(uint32_t callingTokenId, int32_t pid) : pid_(pid), callerToken_(callingTokenId) {}
    ~CameraPrivacy();
    bool RegisterPermissionCallback();
    void UnregisterPermissionCallback();
    bool StartUsingPermissionCallback();
    void StopUsingPermissionCallback();
    bool AddCameraPermissionUsedRecord();
    bool IsAllowUsingCamera();
    void SetClientName(const std::string& clientName);

    inline std::string GetClientName()
    {
        std::lock_guard<std::mutex> lock(clientNameMutex_);
        return clientName_;
    }

    inline std::cv_status WaitFor(bool isSystemCamera)
    {
        std::unique_lock<std::mutex> lock(canCloseMutex_);
        int32_t waitReleaseStreamMs = isSystemCamera ? WAIT_RELEASE_STREAM_MS_FOR_SYSTEM_CAMERA :
            WAIT_RELEASE_STREAM_MS;
        return canClose_.wait_for(lock, std::chrono::milliseconds(waitReleaseStreamMs));
    }

    inline void Notify()
    {
        std::lock_guard<std::mutex> lock(canCloseMutex_);
        canClose_.notify_one();
    }

private:
    int32_t pid_;
    uint32_t callerToken_;
    std::string clientName_;
    std::condition_variable canClose_;
    std::mutex canCloseMutex_;
    std::mutex permissionCbMutex_;
    std::mutex cameraUseCbMutex_;
    std::mutex clientNameMutex_;
    std::shared_ptr<PermissionStatusChangeCb> permissionCallbackPtr_;
    std::shared_ptr<CameraUseStateChangeCb> cameraUseCallbackPtr_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // CAMERA_PRIVACY_H