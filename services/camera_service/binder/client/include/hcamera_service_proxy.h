/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_HCAMERA_SERVICE_PROXY_H
#define OHOS_CAMERA_HCAMERA_SERVICE_PROXY_H

#include "icamera_service.h"
#include "icamera_service_callback.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace CameraStandard {
class HCameraProxy : public IRemoteProxy<ICameraBroker> {
public:
    explicit HCameraProxy(const sptr<IRemoteObject> &impl);
    ~HCameraProxy() = default;

    int32_t NotifyCloseCamera(std::string cameraId) override;
    int32_t NotifyMuteCamera(bool muteMode) override;
private:
    static inline BrokerDelegator<HCameraProxy> delegator_;
};

class HCameraServiceProxy : public IRemoteProxy<ICameraService> {
public:
    explicit HCameraServiceProxy(const sptr<IRemoteObject> &impl);

    virtual ~HCameraServiceProxy() = default;

    int32_t CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService>& device) override;

    int32_t SetCameraCallback(sptr<ICameraServiceCallback>& callback) override;
    int32_t UnSetCameraCallback() override;

    int32_t SetMuteCallback(sptr<ICameraMuteServiceCallback>& callback) override;
    int32_t UnSetMuteCallback() override;

    int32_t SetTorchCallback(sptr<ITorchServiceCallback>& callback) override;
    int32_t UnSetTorchCallback() override;

    int32_t SetFoldStatusCallback(sptr<IFoldServiceCallback>& callback, bool isInnerCallback = false) override;
    int32_t UnSetFoldStatusCallback() override;

    int32_t GetCameras(std::vector<std::string> &cameraIds,
        std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> &cameraAbilityList) override;

    int32_t GetCameraIds(std::vector<std::string>& cameraIds) override;

    int32_t GetCameraAbility(std::string& cameraId,
        std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility) override;

    int32_t CreateCaptureSession(sptr<ICaptureSession>& session, int32_t operationMode = 0) override;

    int32_t CreateDeferredPhotoProcessingSession(int32_t userId,
        sptr<DeferredProcessing::IDeferredPhotoProcessingSessionCallback>& callback,
        sptr<DeferredProcessing::IDeferredPhotoProcessingSession>& session) override;
    
    int32_t CreateDeferredVideoProcessingSession(int32_t userId,
        sptr<DeferredProcessing::IDeferredVideoProcessingSessionCallback>& callback,
        sptr<DeferredProcessing::IDeferredVideoProcessingSession>& session) override;

    int32_t CreatePhotoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                              int32_t width, int32_t height, sptr<IStreamCapture> &photoOutput) override;

    int32_t CreatePreviewOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                int32_t width, int32_t height, sptr<IStreamRepeat> &previewOutput) override;

    int32_t CreateDeferredPreviewOutput(int32_t format, int32_t width, int32_t height,
                                        sptr<IStreamRepeat> &previewOutput) override;

    int32_t CreateDepthDataOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                  int32_t width, int32_t height, sptr<IStreamDepthData> &depthDataOutput) override;
                                  
    int32_t CreateMetadataOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                 std::vector<int32_t> metadataTypes,
                                 sptr<IStreamMetadata>& metadataOutput) override;

    int32_t CreateVideoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                              int32_t width, int32_t height, sptr<IStreamRepeat> &videoOutput) override;

    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override;

    int32_t MuteCamera(bool muteMode) override;

    int32_t MuteCameraPersist(PolicyType policyType, bool isMute) override;

    int32_t PrelaunchCamera() override;

    int32_t PreSwitchCamera(const std::string cameraId) override;

    int32_t SetPrelaunchConfig(std::string cameraId, RestoreParamTypeOhos restoreParamType, int activeTime,
        EffectParam effectParam) override;

    int32_t IsTorchSupported(bool &isTorchSupported) override;

    int32_t IsCameraMuteSupported(bool &isCameraMuteSupported) override;

    int32_t IsCameraMuted(bool &muteMode) override;

    int32_t GetTorchStatus(int32_t &status) override;

    int32_t SetTorchLevel(float level) override;

    int32_t AllowOpenByOHSide(std::string cameraId, int32_t state, bool &canOpenCamera) override;

    int32_t NotifyCameraState(std::string cameraId, int32_t state) override;

    int32_t SetPeerCallback(sptr<ICameraBroker>& callback) override;

    int32_t UnsetPeerCallback() override;

    int32_t DestroyStubObj() override;

    int32_t ProxyForFreeze(const std::set<int32_t>& pidList, bool isProxy) override;

    int32_t ResetAllFreezeStatus() override;

    int32_t GetDmDeviceInfo(std::vector<std::string> &deviceInfos) override;
    
    int32_t GetCameraOutputStatus(int32_t pid, int32_t &status) override;

    int32_t RequireMemorySize(int32_t memSize) override;

    int32_t GetIdforCameraConcurrentType(int32_t cameraPosition, std::string &cameraId) override;

    int32_t GetConcurrentCameraAbility(std::string& cameraId,
        std::shared_ptr<OHOS::Camera::CameraMetadata>& cameraAbility) override;

    int32_t CheckWhiteList(bool &isInWhiteList) override;
private:
    static inline BrokerDelegator<HCameraServiceProxy> delegator_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_HCAMERA_SERVICE_PROXY_H
