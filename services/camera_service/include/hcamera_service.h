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

#ifndef OHOS_CAMERA_H_CAMERA_SERVICE_H
#define OHOS_CAMERA_H_CAMERA_SERVICE_H
#include <set>
#include <shared_mutex>
#include <iostream>

#include "camera_util.h"
#include "hcamera_device.h"
#include "hcamera_host_manager.h"
#include "hcamera_service_stub.h"
#include "hcapture_session.h"
#include "hstream_capture.h"
#include "hstream_metadata.h"
#include "hstream_repeat.h"
#include "iremote_stub.h"
#include "privacy_kit.h"
#include "system_ability.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
class HCameraService : public SystemAbility, public HCameraServiceStub, public HCameraHostManager::StatusCallback,
                       public IDeviceOperatorsCallback {
    DECLARE_SYSTEM_ABILITY(HCameraService);

public:
    DISALLOW_COPY_AND_MOVE(HCameraService);

    explicit HCameraService(int32_t systemAbilityId, bool runOnCreate = true);
    ~HCameraService() override;
    int32_t GetCameras(std::vector<std::string> &cameraIds,
        std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>> &cameraAbilityList) override;
    int32_t CreateCameraDevice(std::string cameraId, sptr<ICameraDeviceService> &device) override;
    int32_t CreateCaptureSession(sptr<ICaptureSession> &session, int32_t opMode) override;
    int32_t CreatePhotoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                              int32_t width, int32_t height,
                              sptr<IStreamCapture> &photoOutput) override;
    int32_t CreateDeferredPreviewOutput(int32_t format, int32_t width, int32_t height,
                                        sptr<IStreamRepeat> &previewOutput) override;
    int32_t CreatePreviewOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                int32_t width, int32_t height,
                                sptr<IStreamRepeat> &previewOutput) override;
    int32_t CreateMetadataOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                                 sptr<IStreamMetadata> &metadataOutput) override;
    int32_t CreateVideoOutput(const sptr<OHOS::IBufferProducer> &producer, int32_t format,
                              int32_t width, int32_t height,
                              sptr<IStreamRepeat> &videoOutput) override;
    int32_t SetCallback(sptr<ICameraServiceCallback> &callback) override;
    int32_t UnSetCallback(pid_t pid) override;
    int32_t CloseCameraForDestory(pid_t pid) override;
    int32_t SetMuteCallback(sptr<ICameraMuteServiceCallback> &callback) override;
    int32_t MuteCamera(bool muteMode) override;
    int32_t PrelaunchCamera() override;
    int32_t SetPrelaunchConfig(std::string cameraId) override;
    int32_t IsCameraMuted(bool &muteMode) override;
    void OnDump() override;
    void OnStart() override;
    void OnStop() override;
    int32_t Dump(int fd, const std::vector<std::u16string>& args) override;

    // HCameraHostManager::StatusCallback
    void OnCameraStatus(const std::string& cameraId, CameraStatus status) override;
    void OnFlashlightStatus(const std::string& cameraId, FlashStatus status) override;
    // IDeviceOperatorsCallback
    int32_t DeviceOpen(const std::string& cameraId) override;
    int32_t DeviceClose(const std::string& cameraId, pid_t pidFromSession = 0) override;
    std::vector<sptr<HCameraDevice>> CameraConflictDetection(const std::string& cameraId, bool& isPermisson) override;

protected:
    explicit HCameraService(sptr<HCameraHostManager> cameraHostManager) : cameraHostManager_(cameraHostManager),
        streamOperatorCallback_(nullptr),
        muteMode_(false) {}

private:
    void CameraSummary(std::vector<std::string> cameraIds, std::string& dumpString);
    void CameraDumpAbility(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpStreaminfo(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpZoom(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpFlash(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpAF(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpAE(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpSensorInfo(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpVideoStabilization(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpVideoFrameRateRange(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpPrelaunch(common_metadata_header_t* metadataEntry, std::string& dumpString);
    void CameraDumpThumbnail(common_metadata_header_t* metadataEntry, std::string& dumpString);
    bool IsCameraMuteSupported(std::string cameraId);
    bool IsPrelaunchSupported(std::string cameraId);
    int32_t UpdateMuteSetting(sptr<HCameraDevice> cameraDevice, bool muteMode);
    int32_t UnSetMuteCallback(pid_t pid);
    bool IsDeviceAlreadyOpen(pid_t& tempPid, std::string& tempCameraId, sptr<HCameraDevice> &tempDevice);
    int32_t DeviceClose(sptr<HCameraDevice> cameraDevice);
    std::mutex mutex_;
    std::mutex cbMutex_;
    std::mutex muteCbMutex_;
    sptr<HCameraHostManager> cameraHostManager_;
    sptr<StreamOperatorCallback> streamOperatorCallback_;
    std::map<uint32_t, sptr<ICameraMuteServiceCallback>> cameraMuteServiceCallbacks_;
    std::map<uint32_t, sptr<ICameraServiceCallback>> cameraServiceCallbacks_;
    SafeMap<std::string, sptr<HCameraDevice>> devicesManager_;
    std::map<uint32_t, std::set<std::string>> camerasForPid_;
    bool muteMode_;
    std::mutex mapOperatorsLock_;
    std::string preCameraId_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_SERVICE_H
