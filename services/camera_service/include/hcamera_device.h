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
#define EXPORT_API __attribute__((visibility("default")))

#include <cstdint>
#include <functional>
#include <iostream>
#include <atomic>
#include <mutex>
#include <set>

#include "camera_privacy.h"
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
#include "dfx/camera_report_uitls.h"

namespace OHOS {
namespace CameraStandard {
constexpr int32_t HDI_STREAM_ID_INIT = 1;
using OHOS::HDI::Camera::V1_0::CaptureEndedInfo;
using OHOS::HDI::Camera::V1_0::CaptureErrorInfo;
using OHOS::HDI::Camera::V1_0::ICameraDeviceCallback;
using OHOS::HDI::Camera::V1_3::IStreamOperatorCallback;
class EXPORT_API HCameraDevice
    : public HCameraDeviceStub, public ICameraDeviceCallback, public IStreamOperatorCallback {
public:
    explicit HCameraDevice(
        sptr<HCameraHostManager>& cameraHostManager, std::string cameraID, const uint32_t callingTokenId);
    ~HCameraDevice();

    int32_t Open() override;
    int32_t OpenSecureCamera(uint64_t* secureSeqId) override;
    int32_t Close() override;
    int32_t closeDelayed() override;
    int32_t Release() override;
    int32_t UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata>& settings) override;
    int32_t SetUsedAsPosition(uint8_t value) override;
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
    int32_t OnResult(int32_t streamId, const std::vector<uint8_t>& result) override;
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetDeviceAbility();
    std::shared_ptr<OHOS::Camera::CameraMetadata> CloneCachedSettings();
    std::string GetCameraId();
    int32_t GetCameraType();
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
    int32_t OnCaptureEndedExt(
        int32_t captureId, const std::vector<OHOS::HDI::Camera::V1_3::CaptureEndedInfoExt>& infos) override;
    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override;
    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnFrameShutterEnd(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t OnCaptureReady(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
    int32_t ResetDeviceSettings();
    int32_t DispatchDefaultSettingToHdi();
    void SetDeviceMuteMode(bool muteMode);
    uint8_t GetUsedAsPosition();
    bool GetDeviceMuteMode();
    void EnableMovingPhoto(bool isMovingPhotoEnabled);

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

    inline void SetCameraPrivacy(sptr<CameraPrivacy> cameraPrivacy)
    {
        std::lock_guard<std::mutex> lock(cameraPrivacyMutex_);
        cameraPrivacy_ = cameraPrivacy;
    }

    inline sptr<CameraPrivacy> GetCameraPrivacy()
    {
        std::lock_guard<std::mutex> lock(cameraPrivacyMutex_);
        return cameraPrivacy_;
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

    bool CheckMovingPhotoSupported(int32_t mode);

    void NotifyCameraStatus(int32_t state, int32_t msg = 0);

    bool GetCameraResourceCost(int32_t &cost, std::set<std::string> &conflicting);

    int32_t CloseDevice();

    int32_t closeDelayedDevice();

    void SetMovingPhotoStartTimeCallback(std::function<void(int64_t, int64_t)> callback);

    void SetMovingPhotoEndTimeCallback(std::function<void(int64_t, int64_t)> callback);

private:
    class FoldScreenListener;
    static const std::vector<std::tuple<uint32_t, std::string, DFX_UB_NAME>> reportTagInfos_;

    std::mutex opMutex_; // Lock the operations streamOperator_, and hdiCameraDevice_.
    std::mutex settingsMutex_; // Lock the operation updateSettings_.
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
    std::mutex cameraPrivacyMutex_;
    sptr<CameraPrivacy> cameraPrivacy_;
    int32_t cameraPid_;

    std::mutex proxyStreamOperatorCallbackMutex_;
    wptr<IStreamOperatorCallback> proxyStreamOperatorCallback_;

    std::mutex deviceAbilityMutex_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceAbility_;

    std::mutex deviceOpenLifeCycleMutex_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> deviceOpenLifeCycleSettings_;

    std::string clientName_;
    int clientUserId_;
    uint8_t usedAsPosition_ = OHOS_CAMERA_POSITION_OTHER;
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
    void HandleFoldableDevice();
    int32_t CheckPermissionBeforeOpenDevice();
    bool HandlePrivacyBeforeOpenDevice();
    void HandlePrivacyWhenOpenDeviceFail();
    void HandlePrivacyAfterCloseDevice();
    void DebugLogForSmoothZoom(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForAfRegions(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogForAeRegions(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings, uint32_t tag);
    void DebugLogTag(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings,
                     uint32_t tag, std::string tagName, DFX_UB_NAME dfxUbStr);
    void CreateMuteSetting(std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    int32_t UpdateDeviceSetting();
#ifdef MEMMGR_OVERRID
    int32_t RequireMemory(const std::string& reason);
#endif
    void GetMovingPhotoStartAndEndTime(std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult);
    bool isMovingPhotoEnabled_ = false;
    std::mutex movingPhotoStartTimeCallbackLock_;
    std::mutex movingPhotoEndTimeCallbackLock_;
    std::function<void(int32_t, int64_t)> movingPhotoStartTimeCallback_;
    std::function<void(int32_t, int64_t)> movingPhotoEndTimeCallback_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_DEVICE_H
