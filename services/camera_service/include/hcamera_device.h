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

#ifndef OHOS_CAMERA_H_CAMERA_DEVICE_H
#define OHOS_CAMERA_H_CAMERA_DEVICE_H

#include <cstdint>
#include <iostream>
#include <atomic>
#include <mutex>

#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "v1_0/icamera_device_callback.h"
#include "camera_metadata_info.h"
#include "camera_util.h"
#include "hcamera_device_stub.h"
#include "hcamera_host_manager.h"
#include "v1_0/icamera_device.h"
#include "v1_1/icamera_device.h"
#include "v1_2/icamera_device.h"
#include "v1_3/icamera_device.h"
#include "v1_0/icamera_host.h"

namespace OHOS {
namespace CameraStandard {
constexpr int32_t HDI_STREAM_ID_INIT = 1;
using OHOS::HDI::Camera::V1_0::CaptureEndedInfo;
using OHOS::HDI::Camera::V1_0::CaptureErrorInfo;
using OHOS::HDI::Camera::V1_0::ICameraDeviceCallback;
using OHOS::HDI::Camera::V1_3::IStreamOperatorCallback;
class HCameraDevice : public HCameraDeviceStub, public ICameraDeviceCallback, public IStreamOperatorCallback {
public:
    explicit HCameraDevice(
        sptr<HCameraHostManager>& cameraHostManager, std::string cameraID, const uint32_t callingTokenId);
    ~HCameraDevice();

    int32_t Open() override;
    int32_t OpenSecureCamera(uint64_t* secureSeqId) override;
    int32_t Close() override;
    int32_t Release() override;
    int32_t UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings) override;
    int32_t UpdateSettingOnce(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    int32_t GetStatus(std::shared_ptr<OHOS::Camera::CameraMetadata> &metaIn,
            std::shared_ptr<OHOS::Camera::CameraMetadata> &metaOut) override;
    int32_t GetEnabledResults(std::vector<int32_t>& results) override;
    int32_t EnableResult(std::vector<int32_t>& results) override;
    int32_t DisableResult(std::vector<int32_t>& results) override;
    int32_t ReleaseStreams(std::vector<int32_t>& releaseStreamIds);
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> GetStreamOperator();
    int32_t SetCallback(sptr<ICameraDeviceServiceCallback>& callback) override;
    int32_t OnError(OHOS::HDI::Camera::V1_0::ErrorType type, int32_t errorCode) override;
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override;
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetDeviceAbility();
    std::shared_ptr<OHOS::Camera::CameraMetadata> CloneCachedSettings();
    std::string GetCameraId();
    bool IsOpenedCameraDevice();
    int32_t GetCallerToken();
    int32_t CreateAndCommitStreams(std::vector<HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos,
        std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode);
    int32_t UpdateStreams(std::vector<StreamInfo_V1_1>& streamInfos);

    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;

    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds) override;
    int32_t OnCaptureStarted_V1_2(
        int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_2::CaptureStartedInfo>& infos) override;
    int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos) override;
    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override;
    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnFrameShutterEnd(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnCaptureReady(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t ResetDeviceSettings();
    int32_t DispatchDefaultSettingToHdi();
    void SetDeviceMuteMode(bool muteMode);

    inline void SetStreamOperatorCallback(wptr<IStreamOperatorCallback> operatorCallback)
    {
        std::lock_guard<std::mutex> lock(proxyStreamOperatorCallbackMutex_);
        proxyStreamOperatorCallback_ = operatorCallback;
    }

    inline sptr<IStreamOperatorCallback> GetStreamOperatorCallback()
    {
        std::lock_guard<std::mutex> lock(proxyStreamOperatorCallbackMutex_);
        return proxyStreamOperatorCallback_.promote();
    }

    inline int32_t GenerateHdiStreamId()
    {
        return hdiStreamIdGenerator_.fetch_add(1);
    }

    inline void ResetHdiStreamId()
    {
        hdiStreamIdGenerator_ = HDI_STREAM_ID_INIT;
    }
    
    void NotifyCameraSessionStatus(bool running);

    void RemoveResourceWhenHostDied();

    int64_t GetSecureCameraSeq(uint64_t* secureSeqId);

private:
    class FoldScreenListener;
    std::mutex opMutex_; // Lock the operations updateSettings_, streamOperator_, and hdiCameraDevice_.
    std::shared_ptr<OHOS::Camera::CameraMetadata> updateSettings_;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator_;
    sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> hdiCameraDevice_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cachedSettings_;

    sptr<HCameraHostManager> cameraHostManager_;
    std::string cameraID_;
    std::atomic<bool> isOpenedCameraDevice_;
    std::mutex deviceSvcCbMutex_;
    std::mutex cachedSettingsMutex_;
    static std::mutex g_deviceOpenCloseMutex_;
    sptr<ICameraDeviceServiceCallback> deviceSvcCallback_;
    std::map<int32_t, wptr<ICameraServiceCallback>> statusSvcCallbacks_;

    uint32_t callerToken_;

    std::mutex proxyStreamOperatorCallbackMutex_;
    wptr<IStreamOperatorCallback> proxyStreamOperatorCallback_;

    std::mutex deviceAbilityMutex_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceAbility_;

    std::mutex deviceOpenLifeCycleMutex_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceOpenLifeCycleSettings_;

    std::string clientName_;
    int clientUserId_;

    std::mutex unPrepareZoomMutex_;
    uint32_t zoomTimerId_;
    std::atomic<bool> inPrepareZoom_;
    std::atomic<bool> deviceMuteMode_;
    bool isHasOpenSecure = false;
    uint64_t mSecureCameraSeqId = 0L;

    std::atomic<int32_t> hdiStreamIdGenerator_ = HDI_STREAM_ID_INIT;
    void UpdateDeviceOpenLifeCycleSettings(std::shared_ptr<OHOS::Camera::CameraMetadata> changedSettings);
    void ResetDeviceOpenLifeCycleSettings();

    sptr<ICameraDeviceServiceCallback> GetDeviceServiceCallback();
    void ResetCachedSettings();
    int32_t InitStreamOperator();
    void ReportMetadataDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void RegisterFoldStatusListener();
    void UnRegisterFoldStatusListener();
    void CheckOnResultData(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult);
    int32_t CreateStreams(std::vector<HDI::Camera::V1_1::StreamInfo_V1_1>& streamInfos);
    int32_t CommitStreams(std::shared_ptr<OHOS::Camera::CameraMetadata>& deviceSettings, int32_t operationMode);
    bool CanOpenCamera();
    void ResetZoomTimer();
    void CheckZoomChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    void UnPrepareZoom();
    int32_t OpenDevice(bool isEnableSecCam = false);
    int32_t CloseDevice();
    void OpenDeviceNext();
    void DebugLogForZoom(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForSmoothZoom(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForVideoStabilizationMode(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
        uint32_t tag);
    void DebugLogForFilter(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForBeautySkinSmooth(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForBeautyFaceSlender(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForBeautySkinTone(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForPortraitEffect(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);

    void DebugLogForFocusMode(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForAfRegions(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForExposureMode(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForExposureTime(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForAeRegions(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForAeExposureCompensation(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
        uint32_t tag);
    void DebugLogForBeautyAuto(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void UpdateMuteSetting();
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_DEVICE_H
