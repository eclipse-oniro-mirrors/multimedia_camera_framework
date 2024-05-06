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

#ifndef OHOS_CAMERA_INPUT_IMPL_H
#define OHOS_CAMERA_INPUT_IMPL_H

#include "kits/native/include/camera/camera.h"
#include "kits/native/include/camera/camera_input.h"
#include "input/camera_input.h"

struct Camera_Input {
public:
    explicit Camera_Input(OHOS::sptr<OHOS::CameraStandard::CameraInput> &innerCameraInput);
    ~Camera_Input();

    Camera_ErrorCode RegisterCallback(CameraInput_Callbacks* callback);

    Camera_ErrorCode UnregisterCallback(CameraInput_Callbacks* callback);

    Camera_ErrorCode Open();

    Camera_ErrorCode OpenSecureCamera(uint64_t* secureSeqId);

    Camera_ErrorCode Close();

    Camera_ErrorCode Release();

    OHOS::sptr<OHOS::CameraStandard::CameraInput> GetInnerCameraInput();

private:
    OHOS::sptr<OHOS::CameraStandard::CameraInput> innerCameraInput_;
};
#endif // OHOS_CAMERA_INPUT_IMPL_H