/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_RECORDER_ENGINE_ADAPTER_H
#define OHOS_CAMERA_RECORDER_ENGINE_ADAPTER_H

#include "recorder_engine.h"
#include "recorder_engine_interface.h"

namespace OHOS::CameraStandard {
class RecorderEngineAdapter : public RecorderEngineIntf {
public:
    RecorderEngineAdapter();
    virtual ~RecorderEngineAdapter();

    void CreateRecorderEngine(wptr<RecorderIntf> recorder) override;
    int32_t Prepare() override;
    int32_t StartRecording() override;
    int32_t PauseRecording() override;
    int32_t ResumeRecording() override;
    int32_t StopRecording() override;
    int32_t SetRotation(int32_t rotation) override;
    int32_t SetOutputSettings(const EngineMovieSettings& movieSettings) override;
    int32_t Init() override;
    int32_t GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters) override;
    int32_t SetVideoFilter(const std::string& filter, const std::string& filterParam) override;
    int32_t SetUserMeta(const std::string& key, const std::string& val) override;
    int32_t SetUserMeta(const std::string& key, const std::vector<uint8_t>& val) override;
    void GetFirstFrameTimestamp(int64_t& firstFrameTimestamp) override;
    void SetIsWaitForMeta(bool isWait) override;
    void SetIsWaitForMuxerDone(bool isWait) override;
    void SetIsStreamStarted(bool isStarted) override;
    int32_t UpdatePhotoProxy(const std::string& videoId, int32_t videoEnhancementType) override;
    bool IsNeedWaitForMuxerDone() override;
    sptr<Surface> GetRawSurface() override;
    sptr<Surface> GetDepthSurface() override;
    sptr<Surface> GetPreySurface() override;
    sptr<Surface> GetMetaSurface() override;
    sptr<Surface> GetMovieDebugSurface() override;
    sptr<Surface> GetRawDebugSurface() override;
    sptr<Surface> GetImageEffectSurface() override;
    void WaitForRawMuxerDone() override;
    void SetMovieFrameSize(int32_t width, int32_t height) override;
    void SetRawFrameSize(int32_t width, int32_t height) override;
    int32_t EnableVirtualAperture(bool isVirtualApertureEnabled) override;
    std::string GetMovieFileUri() override;
    bool IsNeedStopCallback() override;
    void SetIsNeedStopCallback(bool isNeed) override;
    void SetIsNeedWaitForRawMuxerDone(bool isNeed) override;

private:
    sptr<RecorderEngine> recorderEngine_{nullptr};
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_RECORDER_ENGINE_ADAPTER_H
