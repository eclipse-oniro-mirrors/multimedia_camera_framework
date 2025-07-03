/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CAMERA_SESSION_IMPL_H
#define CAMERA_SESSION_IMPL_H

#include <mutex>
#include <refbase.h>
#include <string>
#include "capture_session.h"

#include "camera_input_impl.h"
#include "camera_output_impl.h"
#include "camera_utils.h"
#include "cj_common_ffi.h"

namespace OHOS {

namespace CameraStandard {

class CJSmoothZoomCallback : public SmoothZoomCallback, public ListenerBase<int32_t> {
public:
    CJSmoothZoomCallback() = default;
    ~CJSmoothZoomCallback() = default;
    void OnSmoothZoom(int32_t duration) override;
};

class CJSessionCallback : public SessionCallback, public ListenerBase<int32_t> {
public:
    CJSessionCallback() = default;
    ~CJSessionCallback() = default;
    void OnError(int32_t errorCode) override;
};

class CJFocusStateCallback : public FocusCallback, public ListenerBase<int32_t> {
public:
    CJFocusStateCallback() = default;
    ~CJFocusStateCallback() = default;
    void OnFocusState(FocusState state) override;
};

class CJSession : public OHOS::FFI::FFIData {
public:
    OHOS::FFI::RuntimeType *GetRuntimeType() override
    {
        return GetClassType();
    }

    explicit CJSession(sptr<CameraStandard::CaptureSession> session);

    sptr<CameraStandard::CaptureSession> GetCaptureSession();

    int32_t BeginConfig();

    int32_t CommitConfig();

    bool CanAddInput(OHOS::sptr<CJCameraInput> cameraInput);

    int32_t AddInput(OHOS::sptr<CJCameraInput> cameraInput);

    int32_t RemoveInput(OHOS::sptr<CJCameraInput> cameraInput);

    bool CanAddOutput(sptr<CameraOutput> cameraOutput);

    int32_t AddOutput(sptr<CameraOutput> cameraOutput);

    int32_t RemoveOutput(sptr<CameraOutput> cameraOutput);

    int32_t Start();

    int32_t Stop();

    int32_t Release();

    // sessio common
    int32_t CanPreconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio, bool &isSupported);
    int32_t Preconfig(PreconfigType preconfigType, ProfileSizeRatio preconfigRatio);
    int32_t AddSecureOutput(sptr<CameraOutput> cameraOutput);

    // auto exposure
    int32_t IsExposureModeSupported(ExposureMode mode, bool &isSupported);
    int32_t GetExposureBiasRange(CArrFloat32 &ranges);
    int32_t GetExposureMode(ExposureMode &mode);
    int32_t SetExposureMode(ExposureMode mode);
    int32_t GetMeteringPoint(CameraPoint &point);
    int32_t SetMeteringPoint(CameraPoint point);
    int32_t SetExposureBias(float value);
    int32_t GetExposureValue(float &value);

    // color management
    void GetSupportedColorSpaces(CArrI32 &colorSpaces);
    int32_t SetColorSpace(ColorSpace colorSpace);
    int32_t GetActiveColorSpace(ColorSpace &colorSpace);

    // flash
    int32_t IsFlashModeSupported(FlashMode mode, bool &isSupported);
    int32_t HasFlash(bool &hasFlash);
    int32_t GetFlashMode(FlashMode &mode);
    int32_t SetFlashMode(FlashMode mode);

    // focus
    int32_t IsFocusModeSupported(FocusMode mode, bool &isSupported);
    int32_t SetFocusMode(FocusMode mode);
    int32_t GetFocusMode(FocusMode &mode);
    int32_t SetFocusPoint(CameraPoint point);
    int32_t GetFocusPoint(CameraPoint &point);
    int32_t GetFocalLength(float &focalLength);

    // stabilization
    int32_t IsVideoStabilizationModeSupported(VideoStabilizationMode mode, bool &isSupported);
    int32_t GetActiveVideoStabilizationMode(VideoStabilizationMode &mode);
    int32_t SetVideoStabilizationMode(VideoStabilizationMode mode);

    // zoom
    int32_t GetZoomRatioRange(CArrFloat32 &ranges);
    int32_t SetZoomRatio(float ratio);
    int32_t GetZoomRatio(float &ratio);
    int32_t SetSmoothZoom(float targetZoomRatio, uint32_t smoothZoomType);

    // callbacks
    void OnSmoothZoom(int64_t callbackId);
    void OffSmoothZoom(int64_t callbackId);
    void OffAllSmoothZoom();

    void OnError(int64_t callbackId);
    void OffError(int64_t callbackId);
    void OffAllError();

    void OnFocusStateChange(int64_t callbackId);
    void OffFocusStateChange(int64_t callbackId);
    void OffAllFocusStateChange();

private:
    sptr<CameraStandard::CaptureSession> session_;
    std::shared_ptr<CJSmoothZoomCallback> smoothZoomCallback_;
    std::shared_ptr<CJSessionCallback> errorCallback_;
    std::shared_ptr<CJFocusStateCallback> focusStateCallback_;

    friend class OHOS::FFI::RuntimeType;
    friend class OHOS::FFI::TypeBase;
    static OHOS::FFI::RuntimeType *GetClassType()
    {
        static OHOS::FFI::RuntimeType runtimeType = OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("CJSession");
        return &runtimeType;
    }
};

} // namespace CameraStandard
} // namespace OHOS

#endif