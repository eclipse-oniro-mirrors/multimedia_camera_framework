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

#ifndef OHOS_CAMERA_SWITCH_PHOTO_PROCESSOR_H
#define OHOS_CAMERA_SWITCH_PHOTO_PROCESSOR_H

#include <refbase.h>

#include "camera_switch_session_callback_stub.h"
#include "icamera_switch_session.h"
#include "input/camera_death_recipient.h"

namespace OHOS {
namespace CameraStandard {

class CameraSwitchCallback : public RefBase {
public:
    CameraSwitchCallback() = default;
    virtual ~CameraSwitchCallback() = default;
    virtual void OnCameraActive(
        const std::string &cameraId, bool isRegisterCameraSwitchCallback, const CaptureSessionInfo &sessionInfo) = 0;
    virtual void OnCameraUnactive(const std::string &cameraId) = 0;
    virtual void OnCameraSwitch(const std::string &oriCameraId, const std::string &destCameraId, bool status) = 0;
};

class CameraSwitchSession : public RefBase {
public:
    CameraSwitchSession(sptr<ICameraSwitchSession> session);
    virtual ~CameraSwitchSession();

    /**
     * @brief Set the session callback for the CameraSwitchSession.
     *
     * @param callback pointer to be triggered.
     */
    void SetCallback(std::shared_ptr<CameraSwitchCallback> callback);

    /**
     * @brief Switch the Camera ID.
     *
     * @param oriCameraId Original Camera ID.
     * @param destCameraId Target Camera ID.
     */
    int32_t SwitchCamera(const std::string &oriCameraId, const std::string &destCameraId);

    /**
     * @brief Switch SetDevice.
     *
     * @param cameraDevice Camera Device.
     */
    int32_t SwitchSetService(const sptr<ICameraDeviceService> &cameraDevice);

    /**
     * @brief Get the Callback.
     *
     * @return Returns the pointer to Callback.
     */
    std::shared_ptr<CameraSwitchCallback> GetCameraSwitchCallback();

private:
    sptr<ICameraSwitchSession> GetRemoteSwitchSession();
    void SetRemoteSwitchSession(sptr<ICameraSwitchSession> remoteSession);
    void RemoveSwitchDeathRecipient();
    void CameraServerSwitchDied(pid_t pid);

    std::mutex callbackCameraSwitchMutex_;
    std::shared_ptr<CameraSwitchCallback> appSwitchCallback_;
    std::mutex remoteCameraSwitchSessionMutex_;
    sptr<ICameraSwitchSession> remoteSwitchSession_ = nullptr;
    sptr<CameraDeathRecipient> deathRecipient_ = nullptr;
};

class CameraSwitchCallbackImpl : public CameraSwitchSessionCallbackStub {
public:
    explicit CameraSwitchCallbackImpl(sptr<CameraSwitchSession> cameraSwitchSession)
        : cameraSwitchSession_(cameraSwitchSession)
    {}
    ~CameraSwitchCallbackImpl()
    {
        cameraSwitchSession_ = nullptr;
    }
    ErrCode OnCameraActive(const std::string &cameraId, bool isRegisterCameraSwitchCallback,
        const CaptureSessionInfo &sessionInfo) override;
    ErrCode OnCameraUnactive(const std::string &cameraId) override;
    ErrCode OnCameraSwitch(const std::string &oriCameraId, const std::string &destCameraId, bool status) override;

private:
    wptr<CameraSwitchSession> cameraSwitchSession_;
};
}  // namespace CameraStandard
}  // namespace OHOS
#endif  // OHOS_CAMERA_SWITCH_PHOTO_PROCESSOR_H