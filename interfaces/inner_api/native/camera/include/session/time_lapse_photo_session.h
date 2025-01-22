/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_CAMERA_TIME_LAPSE_PHOTO_SESSION_H
#define OHOS_CAMERA_TIME_LAPSE_PHOTO_SESSION_H

#include "session/profession_session.h"

namespace OHOS {
namespace CameraStandard {

enum class TimeLapseRecordState : int32_t {
    IDLE = 0,
    RECORDING = 1,
};

enum class TimeLapsePreviewType : int32_t {
    DARK = 1,
    LIGHT = 2,
};

struct TryAEInfo {
    bool isTryAEDone;
    bool isTryAEHintNeeded;
    TimeLapsePreviewType previewType;
    int32_t captureInterval;
};

class TryAEInfoCallback {
public:
    TryAEInfoCallback() = default;
    virtual ~TryAEInfoCallback() = default;
    virtual void OnTryAEInfoChanged(TryAEInfo info) = 0;
};

class TimeLapsePhotoSession;

class TimeLapsePhotoSessionMetadataResultProcessor : public MetadataResultProcessor {
public:
    TimeLapsePhotoSessionMetadataResultProcessor(wptr<TimeLapsePhotoSession> session) : session_(session) {}
    virtual void ProcessCallbacks(
        const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result) override;
private:
    wptr<TimeLapsePhotoSession> session_;
};

class TimeLapsePhotoSession : public CaptureSession {
public:
    static const unordered_map<ExposureHintMode, camera_exposure_hint_mode_enum_t> fwkExposureHintModeMap_;
    static const unordered_map<camera_awb_mode_t, WhiteBalanceMode> metaWhiteBalanceModeMap_;
    static const unordered_map<WhiteBalanceMode, camera_awb_mode_t> fwkWhiteBalanceModeMap_;
    static const unordered_map<MeteringMode, camera_meter_mode_t> fwkMeteringModeMap_;
    static const unordered_map<camera_meter_mode_t, MeteringMode> metaMeteringModeMap_;

    explicit TimeLapsePhotoSession(sptr<ICaptureSession> &session, vector<sptr<CameraDevice>> devices)
        : CaptureSession(session)
    {
        metadataResultProcessor_ = make_shared<TimeLapsePhotoSessionMetadataResultProcessor>(this);
        supportedDevices_.resize(devices.size());
        std::copy(devices.begin(), devices.end(), supportedDevices_.begin());
        luminationValue_ = 0.0;
        info_.isTryAEHintNeeded = false;
        info_.captureInterval = 0;
        info_.previewType = TimeLapsePreviewType::DARK;
        info_.isTryAEDone = false;
        iso_ = 0;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> GetMetadata() override;

    int32_t IsTryAENeeded(bool& result);
    int32_t StartTryAE();
    int32_t StopTryAE();
    int32_t GetSupportedTimeLapseIntervalRange(vector<int32_t>& result);
    int32_t GetTimeLapseInterval(int32_t& result);
    int32_t SetTimeLapseInterval(int32_t interval);
    int32_t SetTimeLapseRecordState(TimeLapseRecordState state);
    int32_t SetTimeLapsePreviewType(TimeLapsePreviewType type);
    int32_t SetExposureHintMode(ExposureHintMode mode);

    void SetIsoInfoCallback(shared_ptr<IsoInfoCallback> callback);
    void SetExposureInfoCallback(shared_ptr<ExposureInfoCallback> callback);
    void SetLuminationInfoCallback(shared_ptr<LuminationInfoCallback> callback);
    void SetTryAEInfoCallback(shared_ptr<TryAEInfoCallback> callback);

    void ProcessIsoInfoChange(const shared_ptr<OHOS::Camera::CameraMetadata>& meta);
    void ProcessExposureChange(const shared_ptr<OHOS::Camera::CameraMetadata>& meta);
    void ProcessLuminationChange(const shared_ptr<OHOS::Camera::CameraMetadata>& meta);
    void ProcessSetTryAEChange(const shared_ptr<OHOS::Camera::CameraMetadata>& meta);
    void ProcessPhysicalCameraSwitch(const shared_ptr<OHOS::Camera::CameraMetadata>& meta);
    // ManualExposure
    int32_t GetExposure(uint32_t& result);
    int32_t SetExposure(uint32_t exposure);
    int32_t GetSupportedExposureRange(vector<uint32_t>& result);
    int32_t GetSupportedMeteringModes(vector<MeteringMode>& result);
    int32_t IsExposureMeteringModeSupported(MeteringMode mode, bool& result);
    int32_t GetExposureMeteringMode(MeteringMode& result);
    int32_t SetExposureMeteringMode(MeteringMode mode);
    // ManualIso
    int32_t GetIso(int32_t& result);
    int32_t SetIso(int32_t iso);
    int32_t IsManualIsoSupported(bool& result);
    int32_t GetIsoRange(vector<int32_t>& result);
    // WhiteBalance
    int32_t IsWhiteBalanceModeSupported(WhiteBalanceMode mode, bool& result);
    int32_t GetWhiteBalanceRange(vector<int32_t>& result);
    int32_t GetWhiteBalanceMode(WhiteBalanceMode& result);
    int32_t SetWhiteBalanceMode(WhiteBalanceMode mode);
    int32_t GetWhiteBalance(int32_t& result);
    int32_t SetWhiteBalance(int32_t wb);
    int32_t GetSupportedWhiteBalanceModes(vector<WhiteBalanceMode> &result);
private:
    shared_ptr<IsoInfoCallback> isoInfoCallback_;
    shared_ptr<ExposureInfoCallback> exposureInfoCallback_;
    shared_ptr<LuminationInfoCallback> luminationInfoCallback_;
    shared_ptr<TryAEInfoCallback> tryAEInfoCallback_;

    std::atomic<uint8_t> physicalCameraId_ = 0;
    std::vector<sptr<CameraDevice> > supportedDevices_;
    mutex cbMtx_;
    float luminationValue_;
    TryAEInfo info_;
    uint32_t iso_;
};

} // namespace CameraStandard
} // namespace OHOS
#endif