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

#ifndef OHOS_CAMERA_H_MECH_SESSION_H
#define OHOS_CAMERA_H_MECH_SESSION_H

#include <mutex>
#include <refbase.h>

#include "mech_session_callback_stub.h"
#include "mech_session_stub.h"

namespace OHOS {
namespace CameraStandard {

class HMechSession : public MechSessionStub {
public:
    HMechSession(int32_t userId);
    ~HMechSession();
    int32_t EnableMechDelivery(bool isEnableMech) override;
    int32_t SetCallback(const sptr<IMechSessionCallback>& callback) override;
    int32_t Release() override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;
    int32_t OnFocusTrackingInfo(int32_t streamId, bool isNeedMirror, bool isNeedFlip,
        const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);
    int32_t OnCameraAppInfo(const std::vector<CameraAppInfo>& cameraAppInfos);
    sptr<IMechSessionCallback> GetCallback();
    bool IsEnableMech();

private:
    void HandleCameraAppInfo(const sptr<IMechSessionCallback>& callback);
    int32_t userId_;
    bool isEnableMech_ = false;
    sptr<IMechSessionCallback> callback_;
    std::mutex enableLock_;
    std::mutex callbackLock_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_MECH_SESSION_H
