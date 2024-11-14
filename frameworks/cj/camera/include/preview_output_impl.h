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

#ifndef PREVIEW_OUTPUT_IMPL_H
#define PREVIEW_OUTPUT_IMPL_H

#include "camera_output_impl.h"
#include "camera_utils.h"
#include "listener_base.h"
#include "preview_output.h"

namespace OHOS {
namespace CameraStandard {
class CJPreviewOutputCallback : public PreviewStateCallback {
public:
    CJPreviewOutputCallback() = default;
    ~CJPreviewOutputCallback() = default;

    void OnFrameStarted() const override;
    void OnFrameEnded(const int32_t frameCount) const override;
    void OnError(const int32_t errorCode) const override;
    void OnSketchStatusDataChanged(const SketchStatusData &statusData) const override;

    mutable std::mutex frameStartedMutex{};
    std::vector<std::shared_ptr<CallbackRef<>>> frameStartedCallbackList;
    mutable std::mutex frameEndedMutex{};
    std::vector<std::shared_ptr<CallbackRef<>>> frameEndedCallbackList;
    mutable std::mutex errorMutex{};
    std::vector<std::shared_ptr<CallbackRef<const int32_t>>> errorCallbackList;
};

class CJPreviewOutput : public CameraOutput {
    DECL_TYPE(CJPreviewOutput, OHOS::FFI::FFIData)
public:
    CJPreviewOutput();
    ~CJPreviewOutput() = default;

    sptr<CameraStandard::CaptureOutput> GetCameraOutput() override;
    int32_t Release() override;

    static int32_t CreatePreviewOutput(Profile &profile, std::string &surfaceId);
    static int32_t CreatePreviewOutputWithoutProfile(std::string &surfaceId);

    CArrFrameRateRange GetSupportedFrameRates(int32_t *errCode);
    int32_t SetFrameRate(int32_t min, int32_t max);
    FrameRateRange GetActiveFrameRate(int32_t *errCode);
    CJProfile GetActiveProfile(int32_t *errCode);
    int32_t GetPreviewRotation(int32_t value, int32_t *errCode);
    int32_t SetPreviewRotation(int32_t imageRotation, bool isDisplayLocked);
    void OnFrameStart(int64_t callbackId);
    void OnFrameEnd(int64_t callbackId);
    void OnError(int64_t callbackId);
    void OffFrameStart(int64_t callbackId);
    void OffError(int64_t callbackId);
    void OffFrameEnd(int64_t callbackId);
    void OffAllFrameStart();
    void OffAllFrameEnd();
    void OffAllError();

private:
    sptr<PreviewOutput> previewOutput_;
    static thread_local sptr<PreviewOutput> sPreviewOutput_;

    std::shared_ptr<CJPreviewOutputCallback> previewCallback_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif