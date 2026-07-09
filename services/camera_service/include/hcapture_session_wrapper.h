/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_H_CAPTURE_SESSION_WRAPPER_H
#define OHOS_CAMERA_H_CAPTURE_SESSION_WRAPPER_H

#include <string>
#include <vector>
#include <utility>
#include <mutex>
#include <refbase.h>

#include "hcapture_session.h"
#include "capture_session_stub.h"

namespace OHOS {
namespace CameraStandard {

class HSharedCameraDevice;
class HSharedCaptureSession;

class HCaptureSessionWrapper : public CaptureSessionStub {
public:
    using SharedSessionReadyCallback = std::function<void(const std::string&, const sptr<HSharedCameraDevice>&,
        const sptr<HSharedCaptureSession>&, pid_t)>;

    explicit HCaptureSessionWrapper(
        int32_t opMode,
        pid_t ownerPid,
        bool isPrivilegeApp,
        const sptr<HCaptureSession>& session);

    ~HCaptureSessionWrapper();

    pid_t GetOwnerPid() const;

    std::string GetCameraId() const;

    bool IsSharedMode() const;

    void SetSharedSessionReadyCallback(SharedSessionReadyCallback callback);

    // Get the real HCaptureSession
    sptr<HCaptureSession> GetRealSession() const;

    // Switch to shared mode (normal app → privileged app scenario)
    void SwitchShareSession(const sptr<HSharedCaptureSession>& sharedSession);

    int32_t BeginConfig() override;
    int32_t CommitConfig() override;
    int32_t CanAddInput(const sptr<ICameraDeviceService>& cameraDevice, bool& result) override;
    int32_t AddInput(const sptr<ICameraDeviceService>& cameraDevice) override;
    int32_t AddOutput(StreamType streamType, const sptr<IRemoteObject>& stream) override;
    int32_t AddMultiStreamOutput(const sptr<IRemoteObject>& multiStreamOutput, int32_t opMode) override;
    int32_t RemoveMultiStreamOutput(const sptr<IRemoteObject>& multiStreamOutput) override;
    int32_t RemoveInput(const sptr<ICameraDeviceService>& cameraDevice) override;
    int32_t RemoveOutput(StreamType streamType, const sptr<IRemoteObject>& stream) override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t Release() override;
    int32_t SetCallback(const sptr<ICaptureSessionCallback>& callback) override;
    int32_t UnSetCallback() override;
    int32_t SetPressureCallback(const sptr<IPressureStatusCallback>& callback) override;
    int32_t UnSetPressureCallback() override;
    int32_t GetSessionState(CaptureSessionState& sessionState) override;
    int32_t GetActiveColorSpace(int32_t& curColorSpace) override;
    int32_t SetColorSpace(int32_t curColorSpace, bool isNeedUpdate) override;
    int32_t SetSmoothZoom(int32_t smoothZoomType, int32_t operationMode,
        float targetZoomRatio, float& duration) override;
    int32_t SetFeatureMode(int32_t featureMode) override;
    int32_t EnableMovingPhoto(bool isEnable) override;
    int32_t EnableMovingPhotoMirror(bool isMirror, bool isConfig) override;
    int32_t SetPreviewRotation(const std::string& deviceClass) override;
    int32_t SetCommitConfigFlag(bool isNeedCommitting) override;
    int32_t SetHasFitedRotation(bool isHasFitedRotation) override;
    int32_t CreateRecorder(const sptr<IRemoteObject>& stream, sptr<ICameraRecorder>& recorder) override;
    int32_t GetVirtualApertureMetadata(std::vector<float>& virtualApertureMetadata) override;
    int32_t GetVirtualApertureValue(float& value) override;
    int32_t SetVirtualApertureValue(float value, bool needPersist) override;
    int32_t GetBeautyMetadata(std::vector<int32_t>& beautyApertureMetadata) override;
    int32_t GetBeautyRange(std::vector<int32_t>& range, int32_t type) override;
    int32_t GetBeautyValue(int32_t type, int32_t& value) override;
    int32_t SetBeautyValue(int32_t type, int32_t value, bool needPersist) override;
    int32_t GetColorEffectsMetadata(std::vector<int32_t>& colorEffectMetadata) override;
    int32_t GetColorEffect(int32_t& colourEffect) override;
    int32_t SetColorEffect(int32_t colourEffect) override;
    int32_t EnableKeyFrameReport(bool isKeyFrameReportEnabled) override;
    int32_t SetXtStyleStatus(bool status) override;
    int32_t SetCameraSwitchRequestCallback(const sptr<ICameraSwitchSessionCallback>& callback) override;
    int32_t UnSetCameraSwitchRequestCallback() override;
    int32_t GetCompositionStream(sptr<IRemoteObject>& compositionStreamRemote) override;
    int32_t GetSensorRotationOnce(int32_t& sensorRotation) override;
    int32_t IsAutoFramingSupported(bool& support) override;
    int32_t GetAutoFramingStatus(bool& status) override;
    int32_t EnableAutoFraming(bool enable, bool needPersist) override;
    int32_t SetControlCenterEffectStatusCallback(const sptr<IControlCenterEffectStatusCallback>& callback) override;
    int32_t UnSetControlCenterEffectStatusCallback() override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    pid_t ownerPid_;
    int32_t opMode_;
    bool isPrivilegeApp_;
    bool isSharedMode_;
    sptr<HCaptureSession> session_; // Shared mode: HSharedCaptureSession; Independent mode: HCaptureSession
    SharedSessionReadyCallback sharedSessionReadyCallback_;
    std::mutex mutex_;

    int32_t HandleSharedInput(const std::string& cameraId,
        SharedSessionReadyCallback& readyCallback, std::string& readyCameraId,
        sptr<HSharedCameraDevice>& readySharedDevice, sptr<HSharedCaptureSession>& readySharedSession);
    void RestoreOutputsToSharedSession();
    void RemoveSavedOutputsFromSharedSession();

    // Tracks outputs added by this wrapper, used for restoring after migrating to shared session
    std::vector<std::pair<StreamType, sptr<IRemoteObject>>> savedOutputs_;
};

} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAPTURE_SESSION_WRAPPER_H
