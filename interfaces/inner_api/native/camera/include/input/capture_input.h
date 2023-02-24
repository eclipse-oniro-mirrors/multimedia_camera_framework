/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_CAPTURE_INPUT_H
#define OHOS_CAMERA_CAPTURE_INPUT_H

#include <refbase.h>
#include "camera_device.h"
#include "camera_info.h"

namespace OHOS {
namespace CameraStandard {
class CaptureSession;
class CaptureInput : public RefBase {
public:
    CaptureInput();
    virtual ~CaptureInput()
    {
        session_ = nullptr;
    }

    /**
    * @brief open camera.
    */
    virtual int Open() = 0;

    /**
    * @brief close camera.
    */
    virtual int Close() = 0;

    /**
    * @brief Release camera input.
    */
    virtual int Release() = 0;

    /**
    * @brief get the camera info associated with the device.
    *
    * @return Returns camera info.
    */
    virtual sptr<CameraDevice> GetCameraDeviceInfo() = 0;

    CaptureSession* GetSession();
    void SetSession(CaptureSession* captureSession);

private:
    CaptureSession* session_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CAPTURE_INPUT_H
