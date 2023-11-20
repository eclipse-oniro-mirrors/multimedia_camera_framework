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

#include <iostream>
#include <atomic>

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
#include "v1_0/icamera_host.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
class IDeviceOperatorsCallback;


class HCameraDevice : public HCameraDeviceStub, public ICameraDeviceCallback {
public:
    HCameraDevice(sptr<HCameraHostManager> &cameraHostManager, std::string cameraID, const uint32_t callingTokenId);
    ~HCameraDevice();

    int32_t Open() override;
    int32_t Close() override;
    int32_t Release() override;
    int32_t UpdateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings) override;
    int32_t GetEnabledResults(std::vector<int32_t> &results) override;
    int32_t EnableResult(std::vector<int32_t> &results) override;
    int32_t DisableResult(std::vector<int32_t> &results) override;
    int32_t GetStreamOperator(sptr<IStreamOperatorCallback> callback,
            sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> &streamOperator);
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> GetStreamOperator();
    int32_t SetCallback(sptr<ICameraDeviceServiceCallback> &callback) override;
    int32_t OnError(ErrorType type, int32_t errorCode) override;
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override;
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetSettings();
    std::shared_ptr<OHOS::Camera::CameraMetadata> CloneCachedSettings();
    std::string GetCameraId();
    bool IsReleaseCameraDevice();
    bool IsOpenedCameraDevice();
    int32_t SetReleaseCameraDevice(bool isRelease);
    int32_t SetDeviceOperatorsCallback(wptr<IDeviceOperatorsCallback> callback);
    int32_t OpenDevice();
    int32_t CloseDevice();
    int32_t GetCallerToken();

private:
    class FoldScreenListener;
    sptr<OHOS::HDI::Camera::V1_0::ICameraDevice> hdiCameraDevice_;
    sptr<HCameraHostManager> cameraHostManager_;
    std::string cameraID_;
    bool isReleaseCameraDevice_;
    std::atomic<bool> isOpenedCameraDevice_;
    std::mutex deviceSvcCbMutex_;
    std::mutex opMutex_; // Lock the operations updateSettings_, streamOperator_, and hdiCameraDevice_.
    std::mutex cachedSettingsMutex_;
    static std::mutex deviceOpenMutex_;
    static std::mutex deviceCloseMutex_;
    sptr<ICameraDeviceServiceCallback> deviceSvcCallback_;
    std::map<int32_t, wptr<ICameraServiceCallback>> statusSvcCallbacks_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> updateSettings_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> cachedSettings_;
    sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator_;
    uint32_t callerToken_;
    wptr<IDeviceOperatorsCallback> deviceOperatorsCallback_;

    void ReportFlashEvent(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void ReportMetadataDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void RegisterFoldStatusListener();
    void UnRegisterFoldStatusListener();
};

class IDeviceOperatorsCallback : public virtual RefBase {
public:
    IDeviceOperatorsCallback() = default;
    virtual ~IDeviceOperatorsCallback() = default;
    virtual int32_t DeviceOpen(const std::string& cameraId) = 0;
    virtual int32_t DeviceClose(const std::string& cameraId, pid_t pidFromSession = 0) = 0;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_DEVICE_H
