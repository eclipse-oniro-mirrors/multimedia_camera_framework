/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_H_SWITCH_SESSION_H
#define OHOS_CAMERA_H_SWITCH_SESSION_H

#include <mutex>
#include <refbase.h>

#include "camera_switch_session_callback_stub.h"
#include "camera_switch_session_stub.h"
#include "hcamera_device.h"
#include "hcapture_session.h"


namespace OHOS {
namespace CameraStandard {

class HCameraSwitchSession : public CameraSwitchSessionStub {
public:
    HCameraSwitchSession();
    ~HCameraSwitchSession();
    int32_t OnCameraActive(
        const std::string &cameraId, bool isRegisterCameraSwitchCallback, const CaptureSessionInfo &sessionInfo);
    int32_t OnCameraUnactive(const std::string &cameraId);
    int32_t OnCameraSwitch(const std::string &oriCameraId, const std::string &destCameraId, bool status);
    int32_t SetCallback(const sptr<ICameraSwitchSessionCallback> &callback) override;
    int32_t SwitchCamera(const std::string &oriCameraId, const std::string &destCameraId) override;
    int32_t SwitchSetService(const sptr<ICameraDeviceService> &cameraDevice) override;
    int32_t SwitchCameraUpdateSetting(const sptr<HCameraDevice> cameraDevice_, int32_t sensorOrientation);
    sptr<HCaptureSession> GetAppCameraSwitchSession();
    sptr<HCaptureSession> GetNotRegistCameraSwitchSession();
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::list<sptr<ICameraSwitchSessionCallback>> setSwitchCallbackList_;
    sptr<HCameraDevice> switchSetService_;
    sptr<HCaptureSession> captureSession_ = nullptr;
    sptr<HCaptureSession> notRegisterCaptureSession_ = nullptr;
    std::mutex switchEnableLock_;
    std::mutex switchCallbackLock_;
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // OHOS_CAMERA_H_SWITCH_SESSION_H