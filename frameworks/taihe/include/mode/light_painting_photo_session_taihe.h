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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_LIGHT_PAINTING_PHOTO_SESSION_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_LIGHT_PAINTING_PHOTO_SESSION_TAIHE_H

#include "session/camera_session_taihe.h"
#include "session/light_painting_session.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class LightPaintingPhotoSessionImpl : public SessionImpl, public FlashImpl, public ZoomImpl,
                                      public FocusImpl, public ColorEffectImpl {
public:
    explicit LightPaintingPhotoSessionImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : SessionImpl(obj)
    {
        if (obj != nullptr) {
            lightPaintingSession_ = static_cast<OHOS::CameraStandard::LightPaintingSession*>(obj.GetRefPtr());
        }
    }
    ~LightPaintingPhotoSessionImpl() = default;
    array<LightPaintingType> GetSupportedLightPaintingTypes();
    void SetLightPaintingType(LightPaintingType type);
    LightPaintingType GetLightPaintingType();
private:
    sptr<OHOS::CameraStandard::LightPaintingSession> lightPaintingSession_ = nullptr;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_LIGHT_PAINTING_PHOTO_SESSION_TAIHE_H