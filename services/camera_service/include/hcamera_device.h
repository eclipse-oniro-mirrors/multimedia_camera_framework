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

#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "v1_0/icamera_device_callback.h"
#include "camera_metadata_info.h"
#include "hcamera_device_stub.h"
#include "hcamera_host_manager.h"
#include "v1_0/icamera_device.h"
#include "v1_0/icamera_host.h"

#include <iostream>

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
class CameraDeviceCallback;

const std::string ACCESS_CAMERA = "ohos.permission.CAMERA";

class HCameraDevice : public HCameraDeviceStub {
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
            sptr<IStreamOperator> &streamOperator);
    sptr<IStreamOperator> GetStreamOperator();
    int32_t SetCallback(sptr<ICameraDeviceServiceCallback> &callback) override;
    int32_t SetStatusCallback(std::map<int32_t, sptr<ICameraServiceCallback>> &callbacks);
    int32_t OnError(const ErrorType type, const int32_t errorMsg);
    int32_t OnResult(const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata> &result);
    int32_t OnCameraStatus(const std::string& cameraId, CameraStatus status);
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetSettings();
    std::string GetCameraId();
    bool IsReleaseCameraDevice();
    bool IsOpenedCameraDevice();
    int32_t SetReleaseCameraDevice(bool isRelease);

private:
    sptr<ICameraDevice> hdiCameraDevice_;
    sptr<HCameraHostManager> cameraHostManager_;
    std::string cameraID_;
    bool isReleaseCameraDevice_;
    bool isOpenedCameraDevice_;

    sptr<ICameraDeviceServiceCallback> deviceSvcCallback_;
    sptr<CameraDeviceCallback> deviceHDICallback_;
    std::map<int32_t, wptr<ICameraServiceCallback>> statusSvcCallbacks_;
    std::mutex statusCbLock_;
    std::shared_ptr<OHOS::Camera::CameraMetadata> updateSettings_;
    sptr<IStreamOperator> streamOperator_;
    std::mutex deviceLock_;
    uint32_t callerToken_;
    std::vector<int32_t> videoFrameRateRange_;

    void ReportFlashEvent(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void ReportMetadataDebugLog(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    void GetFrameRateSetting(const std::shared_ptr<OHOS::Camera::CameraMetadata> &settings);
    int32_t OpenHdiCamera();
};

class CameraDeviceCallback : public ICameraDeviceCallback {
public:
    explicit CameraDeviceCallback(sptr<HCameraDevice> hCameraDevice);
    virtual ~CameraDeviceCallback()
    {
        hCameraDevice_ = nullptr;
    }
    int32_t OnError(ErrorType type, int32_t errorCode) override;
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override;

private:
    wptr<HCameraDevice> hCameraDevice_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_CAMERA_DEVICE_H
