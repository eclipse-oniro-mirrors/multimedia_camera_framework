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

#ifndef CAMERA_ABILITY_TAIHE_H
#define CAMERA_ABILITY_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "ability/camera_ability.h"
#include "camera_query_taihe.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class FunctionsImpl : virtual public FunctionBase {
public:
    explicit FunctionsImpl(sptr<OHOS::CameraStandard::CameraAbility> obj)
    {
        if (obj != nullptr) {
            cameraAbility_ = obj;
            isFunctionBase_ = true;
        }
    }
    virtual ~FunctionsImpl() = default;
};

class PortraitPhotoFunctionsImpl : public FunctionsImpl, public AutoExposureQueryImpl, public FocusQueryImpl,
                                   public ZoomQueryImpl, public BeautyQueryImpl, public ColorEffectQueryImpl,
                                   public ColorManagementImpl, public PortraitQueryImpl, public ApertureQueryImpl,
                                   public SceneDetectionQueryImpl, public FlashQueryImpl {
public:
    explicit PortraitPhotoFunctionsImpl(sptr<OHOS::CameraStandard::CameraAbility> obj) : FunctionsImpl(obj) {}
    virtual ~PortraitPhotoFunctionsImpl() = default;
};

class PhotoFunctionsImpl : public FunctionsImpl, public AutoExposureQueryImpl, public ManualExposureQueryImpl,
                           public FocusQueryImpl, public ZoomQueryImpl, public BeautyQueryImpl,
                           public ColorEffectQueryImpl, public ColorManagementImpl, public MacroQueryImpl,
                           public SceneDetectionQueryImpl, public FlashQueryImpl {
public:
    explicit PhotoFunctionsImpl(sptr<OHOS::CameraStandard::CameraAbility> obj) : FunctionsImpl(obj) {}
    virtual ~PhotoFunctionsImpl() = default;
};

class VideoFunctionsImpl : public FunctionsImpl, public AutoExposureQueryImpl, public ManualExposureQueryImpl,
                           public FocusQueryImpl, public ZoomQueryImpl, public StabilizationQueryImpl,
                           public BeautyQueryImpl, public ColorEffectQueryImpl, public ColorManagementImpl,
                           public MacroQueryImpl, public SceneDetectionQueryImpl, public FlashQueryImpl {
public:
    explicit VideoFunctionsImpl(sptr<OHOS::CameraStandard::CameraAbility> obj) : FunctionsImpl(obj) {}
    virtual ~VideoFunctionsImpl() = default;
};

class PhotoConflictFunctionsImpl : public FunctionsImpl, public ZoomQueryImpl, public MacroQueryImpl {
public:
    explicit PhotoConflictFunctionsImpl(sptr<OHOS::CameraStandard::CameraAbility> obj) : FunctionsImpl(obj) {}
    virtual ~PhotoConflictFunctionsImpl() = default;
};

class VideoConflictFunctionsImpl : public FunctionsImpl, public ZoomQueryImpl, public MacroQueryImpl {
public:
    explicit VideoConflictFunctionsImpl(sptr<OHOS::CameraStandard::CameraAbility> obj) : FunctionsImpl(obj) {}
    virtual ~VideoConflictFunctionsImpl() = default;
};

class PortraitPhotoConflictFunctionsImpl : public FunctionsImpl, public ZoomQueryImpl, public PortraitQueryImpl,
                                           public ApertureQueryImpl {
public:
    explicit PortraitPhotoConflictFunctionsImpl(sptr<OHOS::CameraStandard::CameraAbility> obj) : FunctionsImpl(obj) {}
    virtual ~PortraitPhotoConflictFunctionsImpl() = default;
};
}
}
#endif /* CAMERA_ABILITY_TAIHE_H */