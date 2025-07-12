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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_PHOTO_SESSION_FOR_SYS_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_PHOTO_SESSION_FOR_SYS_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "session/camera_session_taihe.h"
#include "session/photo_session.h"
#include "taihe/runtime.hpp"
#include "photo_session_taihe.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;
class PhotoSessionForSysImpl : public PhotoSessionImpl, public SceneDetectionImpl, public ColorEffectImpl,
                               public BeautyImpl, public EffectSuggestionImpl, public MacroImpl,
                               public DepthFusionImpl {
public:
    explicit PhotoSessionForSysImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : PhotoSessionImpl(obj) {}
    ~PhotoSessionForSysImpl() = default;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_PHOTO_SESSION_FOR_SYS_TAIHE_H