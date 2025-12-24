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

#ifndef PHOTO_OUTPUT_IMPL_H
#define PHOTO_OUTPUT_IMPL_H

#include "camera_log.h"
#include "camera_manager.h"
#include "camera_output_impl.h"
#include "camera_utils.h"
#include "cj_common_ffi.h"
#include "cj_lambda.h"
#include "ffi_remote_data.h"
#include "listener_base.h"
#include "photo_output.h"
#include "photo_output_callback.h"
#include "image_impl.h"

namespace OHOS {
namespace CameraStandard {
class CJPhotoOutputCallback : public PhotoStateCallback, public PhotoAvailableCallback {
public:
    CJPhotoOutputCallback() = default;
    ~CJPhotoOutputCallback() = default;

    void OnCaptureStarted(const int32_t captureId) const override;
    void OnCaptureStarted(const int32_t captureId, uint32_t exposureTime) const override;
    void OnCaptureEnded(const int32_t captureId, const int32_t frameCount) const override;
    void OnFrameShutter(const int32_t captureId, const uint64_t timestamp) const override;
    void OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp) const override;
    void OnCaptureReady(const int32_t captureId, const uint64_t timestamp) const override;
    void OnCaptureError(const int32_t captureId, const int32_t errorCode) const override;
    void OnEstimatedCaptureDuration(const int32_t duration) const override;
    void OnOfflineDeliveryFinished(const int32_t captureId) const override;
    void OnConstellationDrawingState(const int32_t drawingState) const override;
    void OnPhotoAvailable(
        const std::shared_ptr<Media::NativeImage> nativeImage, const bool isRaw = false) const override;
    void OnPhotoAvailable(const std::shared_ptr<Media::Picture> picture) const override;

    mutable std::mutex captureStartedMutex{};
    std::vector<std::shared_ptr<CallbackRef<const int32_t, uint32_t>>> captureStartedCallbackList;
    mutable std::mutex frameShutterMutex{};
    std::vector<std::shared_ptr<CallbackRef<const int32_t, const uint64_t>>> frameShutterCallbackList;
    mutable std::mutex captureEndedMutex{};
    std::vector<std::shared_ptr<CallbackRef<const int32_t, const int32_t>>> captureEndedCallbackList;
    mutable std::mutex frameShutterEndMutex{};
    std::vector<std::shared_ptr<CallbackRef<const int32_t>>> frameShutterEndCallbackList;
    mutable std::mutex captureReadyMutex{};
    std::vector<std::shared_ptr<CallbackRef<>>> captureReadyCallbackList;
    mutable std::mutex estimatedCaptureDurationMutex{};
    std::vector<std::shared_ptr<CallbackRef<const int32_t>>> estimatedCaptureDurationCallbackList;
    mutable std::mutex captureErrorMutex{};
    std::vector<std::shared_ptr<CallbackRef<const int32_t>>> captureErrorCallbackList;
    mutable std::mutex photoAvailableMutex{};
    std::vector<std::shared_ptr<CallbackRef<const int64_t>>> photoAvailableCallbackList;
};

class CJPhotoOutput : public CameraOutput {
    DECL_TYPE(CJPhotoOutput, OHOS::FFI::FFIData)
public:
    CJPhotoOutput();
    ~CJPhotoOutput() = default;

    sptr<CameraStandard::CaptureOutput> GetCameraOutput() override;
    int32_t Release() override;

    static int32_t CreatePhotoOutput();
    static int32_t CreatePhotoOutputWithProfile(Profile &profile);
    int32_t Capture();
    int32_t Capture(CJPhotoCaptureSetting &setting, bool isLocationNone);
    bool IsMovingPhotoSupported(int32_t *errCode);
    int32_t EnableMovingPhoto(bool enabled);
    bool IsMirrorSupported(int32_t *errCode);
    int32_t EnableMirror(bool isMirror);
    int32_t SetMovingPhotoVideoCodecType(int32_t codecType);
    CJProfile GetActiveProfile(int32_t *errCode);
    int32_t GetPhotoRotation(int32_t deviceDegree, int32_t *errCode);
    void OnCaptureStartWithInfo(int64_t callbackId);
    void OffCaptureStartWithInfo(int64_t callbackId);
    void OffAllCaptureStartWithInfo();
    void OnFrameShutter(int64_t callbackId);
    void OffFrameShutter(int64_t callbackId);
    void OffAllFrameShutter();
    void OnCaptureEnd(int64_t callbackId);
    void OffCaptureEnd(int64_t callbackId);
    void OffAllCaptureEnd();
    void OnFrameShutterEnd(int64_t callbackId);
    void OffFrameShutterEnd(int64_t callbackId);
    void OffAllFrameShutterEnd();
    void OnCaptureReady(int64_t callbackId);
    void OffCaptureReady(int64_t callbackId);
    void OffAllCaptureReady();
    void OnEstimatedCaptureDuration(int64_t callbackId);
    void OffEstimatedCaptureDuration(int64_t callbackId);
    void OffAllEstimatedCaptureDuration();
    void OnError(int64_t callbackId);
    void OffError(int64_t callbackId);
    void OffAllError();
    void OnPhotoAvailable(int64_t callbackId);
    void OffPhotoAvailable(int64_t callbackId);
    void OffAllPhotoAvailable();

private:
    sptr<PhotoOutput> photoOutput_;
    static thread_local sptr<PhotoOutput> sPhotoOutput_;
    std::shared_ptr<CJPhotoOutputCallback> photoOutputCallback_;
    uint8_t callbackFlag_ = 0;
};

} // namespace CameraStandard
} // namespace OHOS
#endif