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

#ifndef VIDEO_OUTPUT_IMPL_H
#define VIDEO_OUTPUT_IMPL_H

#include <mutex>
#include <refbase.h>
#include <string>

#include "camera_output_impl.h"
#include "camera_utils.h"
#include "cj_lambda.h"
#include "listener_base.h"
#include "video_output.h"

namespace OHOS {
namespace CameraStandard {
class CJVideoCallbackListener : public VideoStateCallback {
public:
    CJVideoCallbackListener() = default;
    ~CJVideoCallbackListener() = default;

    void OnFrameStarted() const override;
    void OnFrameEnded(const int32_t frameCount) const override;
    void OnError(const int32_t errorCode) const override;
    void OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt info) const override;

    mutable std::mutex frameStartedMutex{};
    std::vector<std::shared_ptr<CallbackRef<>>> frameStartedCallbackList;
    mutable std::mutex frameEndedMutex{};
    std::vector<std::shared_ptr<CallbackRef<>>> frameEndedCallbackList;
    mutable std::mutex errorMutex{};
    std::vector<std::shared_ptr<CallbackRef<const int32_t>>> errorCallbackList;
};

class CJVideoOutput : public CameraOutput {
    DECL_TYPE(CJVideoOutput, OHOS::FFI::FFIData)
public:
    CJVideoOutput();
    ~CJVideoOutput() = default;

    static int32_t CreateVideoOutput(VideoProfile &profile, std::string surfaceId);
    static int32_t CreateVideoOutputWithOutProfile(std::string surfaceId);

    sptr<CameraStandard::CaptureOutput> GetCameraOutput() override;
    int32_t Release() override;

    int32_t Start();
    int32_t Stop();
    void OnFrameStart(int64_t callbackId);
    void OffFrameStart(int64_t callbackId);
    void OffAllFrameStart();
    void OffFrameEnd(int64_t callbackId);
    void OnFrameEnd(int64_t callbackId);
    void OffAllFrameEnd();
    void OnError(int64_t callbackId);
    void OffError(int64_t callbackId);
    void OffAllError();

    CArrFrameRateRange GetSupportedFrameRates(int32_t *errCode);
    int32_t SetFrameRate(int32_t minFps, int32_t maxFps);
    FrameRateRange GetActiveFrameRate(int32_t *errCode);
    CJVideoProfile GetActiveProfile(int32_t *errCode);
    int32_t GetVideoRotation(int32_t imageRotation, int32_t *errCode);

private:
    sptr<VideoOutput> videoOutput_;
    static thread_local sptr<VideoOutput> sVideoOutput_;

    std::shared_ptr<CJVideoCallbackListener> videoCallback_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif