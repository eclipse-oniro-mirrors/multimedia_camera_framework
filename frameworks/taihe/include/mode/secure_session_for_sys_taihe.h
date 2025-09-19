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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_SECURE_SESSION_FOR_SYS_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_SECURE_SESSION_FOR_SYS_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "session/camera_session_taihe.h"
#include "session/secure_camera_session_for_sys.h"
#include "taihe/runtime.hpp"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class SecureSessionForSysImpl : public SessionImpl, public FlashImpl, public ZoomImpl, public FocusImpl,
                          public AutoExposureImpl, public WhiteBalanceImpl {
public:
    explicit SecureSessionForSysImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : SessionImpl(obj)
    {
        if (obj != nullptr) {
            secureCameraSessionForSys_ = static_cast<OHOS::CameraStandard::SecureCameraSessionForSys*>(obj.GetRefPtr());
        }
    }
    ~SecureSessionForSysImpl() = default;
    void AddSecureOutput(weak::PreviewOutput previewOutput) {}
    inline int64_t GetSpecificImplPtr()
    {
        return reinterpret_cast<uintptr_t>(this);
    }

    sptr<OHOS::CameraStandard::SecureCameraSessionForSys> GetSecureCameraSession()
    {
        return secureCameraSessionForSys_;
    }
private:
    sptr<OHOS::CameraStandard::SecureCameraSessionForSys> secureCameraSessionForSys_ = nullptr;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_SECURE_SESSION_FOR_SYS_TAIHE_H