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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_CAMERA_OUTPUT_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_CAMERA_OUTPUT_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "taihe/runtime.hpp"
#include "camera_output_capability.h"
#include "capture_output.h"

#include "refbase.h"

namespace Ani {
namespace Camera {

class CameraOutputImpl {
public:
    CameraOutputImpl(OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output) : cameraOutput_(output) {}
    virtual ~CameraOutputImpl() = default;

    OHOS::sptr<OHOS::CameraStandard::CaptureOutput> GetCameraOutput();

    virtual void ReleaseSync() {}

    virtual inline int64_t GetSpecificImplPtr() final
    {
        return reinterpret_cast<uintptr_t>(this);
    }
private:
    OHOS::sptr<OHOS::CameraStandard::CaptureOutput> cameraOutput_ = nullptr;
};
} // namespace Camera
} // namespace Ani
#endif // FRAMEWORKS_TAIHE_INCLUDE_OUTPUT_CAMERA_OUTPUT_TAIHE_H