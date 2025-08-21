/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_SECURE_SESSION_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_SECURE_SESSION_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "session/camera_session_taihe.h"
#include "session/secure_camera_session.h"
#include "taihe/runtime.hpp"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class SecureSessionImpl : public SessionImpl, public FlashImpl, public ZoomImpl, public FocusImpl,
                          public AutoExposureImpl, public WhiteBalanceImpl {
public:
    explicit SecureSessionImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : SessionImpl(obj)
    {
        if (obj != nullptr) {
            secureCameraSession_ = static_cast<OHOS::CameraStandard::SecureCameraSession*>(obj.GetRefPtr());
        }
    }
    ~SecureSessionImpl() = default;
    void AddSecureOutput(weak::PreviewOutput previewOutput) {}
private:
    sptr<OHOS::CameraStandard::SecureCameraSession> secureCameraSession_ = nullptr;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_SECURE_SESSION_TAIHE_H