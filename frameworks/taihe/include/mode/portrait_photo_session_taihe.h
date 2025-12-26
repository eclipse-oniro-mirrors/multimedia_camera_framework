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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_PORTRAIT_PHOTO_SESSION_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_PORTRAIT_PHOTO_SESSION_TAIHE_H

#include "session/camera_session_taihe.h"
#include "session/portrait_session.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class PortraitPhotoSessionImpl : public SessionImpl, public FlashImpl, public ZoomImpl, public FocusImpl,
                                 public BeautyImpl, public AutoExposureImpl, public ColorManagementImpl,
                                 public ColorEffectImpl, public ApertureImpl, public PortraitImpl {
public:
    explicit PortraitPhotoSessionImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : SessionImpl(obj)
    {
        if (obj != nullptr) {
            portraitSession_ = static_cast<OHOS::CameraStandard::PortraitSession*>(obj.GetRefPtr());
        }
    }
    ~PortraitPhotoSessionImpl() = default;
    array<PortraitEffect> GetSupportedPortraitEffects() override;
    void SetPortraitEffect(PortraitEffect effect) override;
    PortraitEffect GetPortraitEffect() override;
    taihe::array<PortraitPhotoFunctions> GetSessionFunctions(CameraOutputCapability const& outputCapability);
    taihe::array<PortraitPhotoConflictFunctions> GetSessionConflictFunctions();
private:
    sptr<OHOS::CameraStandard::PortraitSession> portraitSession_ = nullptr;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_PORTRAIT_PHOTO_SESSION_TAIHE_H