/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_H_CAMERA_SERVICE_H
#define OHOS_CAMERA_H_CAMERA_SERVICE_H

#include "camera_host_callback_stub.h"
#include "hcamera_device.h"
#include "hcamera_host_manager.h"
#include "hcamera_service_stub.h"
#include "hcapture_session.h"
#include "hstream_capture.h"
#include "hstream_repeat.h"
#include "iremote_stub.h"
#include "system_ability.h"

#include <iostream>

namespace OHOS {
namespace CameraStandard {
class CameraHostCallback;
class HCameraService : public SystemAbility, public HCameraServiceStub {
    DECLARE_SYSTEM_ABILITY(HCameraService);

public:
    DISALLOW_COPY_AND_MOVE(HCameraService);

    HCameraService(int32_t systemAbilityId, bool runOnCreate = true);
    ~HCameraService();

    int32_t GetCameras(std::vector<std::string> &cameraIds,
        std::vector<std::shared_ptr<CameraMetadata>> &cameraAbilityList) override;
    int32_t CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService> &device) override;
    int32_t CreateCaptureSession(sptr<ICaptureSession> &session) override;
    int32_t CreatePhotoOutput(const sptr<OHOS::IBufferProducer> &producer, sptr<IStreamCapture> &photoOutput) override;
    int32_t CreatePreviewOutput(const sptr<OHOS::IBufferProducer> &producer,
                                sptr<IStreamRepeat> &previewOutput) override;
    int32_t CreateCustomPreviewOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t width, int32_t height,
                                sptr<IStreamRepeat> &previewOutput) override;
    int32_t CreateVideoOutput(const sptr<OHOS::IBufferProducer> &producer, sptr<IStreamRepeat> &videoOutput) override;
    int32_t SetCallback(sptr<ICameraServiceCallback> &callback) override;
    void OnDump() override;
    void OnStart() override;
    void OnStop() override;

private:
    sptr<HCameraHostManager> cameraHostManager_;
    sptr<Camera::ICameraHostCallback> cameraHostCallback_;
    sptr<CameraDeviceCallback> cameraDeviceCallback_;
    sptr<StreamOperatorCallback> streamOperatorCallback_;
};

class CameraHostCallback : public Camera::CameraHostCallbackStub {
public:
    CameraHostCallback(sptr<ICameraServiceCallback> &callback);
    virtual ~CameraHostCallback() = default;
    virtual void OnCameraStatus(const std::string &cameraId, Camera::CameraStatus status) override;
    virtual void OnFlashlightStatus(const std::string &cameraId, Camera::FlashlightStatus status) override;

private:
    sptr<ICameraServiceCallback> cameraServiceCallback;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_SERVICE_H
