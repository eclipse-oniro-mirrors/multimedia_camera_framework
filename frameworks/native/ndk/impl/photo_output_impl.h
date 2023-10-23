/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_PHOTO_OUTPUT_IMPL_H
#define OHOS_PHOTO_OUTPUT_IMPL_H

#include "kits/native/include/camera/camera.h"
#include "kits/native/include/camera/photo_output.h"
#include "output/photo_output.h"

struct Camera_PhotoOutput {
public:
    explicit Camera_PhotoOutput(OHOS::sptr<OHOS::CameraStandard::PhotoOutput> &innerPhotoOutput);
    ~Camera_PhotoOutput();

    Camera_ErrorCode RegisterCallback(PhotoOutput_Callbacks* callback);

    Camera_ErrorCode UnregisterCallback(PhotoOutput_Callbacks* callback);

    Camera_ErrorCode Capture();

    Camera_ErrorCode Capture_WithCaptureSetting(Camera_PhotoCaptureSetting setting);

    Camera_ErrorCode Release();

    Camera_ErrorCode IsMirrorSupported(bool* isSupported);

    OHOS::sptr<OHOS::CameraStandard::PhotoOutput> GetInnerPhotoOutput();

private:
    OHOS::sptr<OHOS::CameraStandard::PhotoOutput> innerPhotoOutput_;
};
#endif // OHOS_PHOTO_OUTPUT_IMPL_H