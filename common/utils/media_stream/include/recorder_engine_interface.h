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

#ifndef OHOS_CAMERA_RECORDER_ENGINE_INTERFACE_H
#define OHOS_CAMERA_RECORDER_ENGINE_INTERFACE_H

#include <refbase.h>
#include <cstdint>
#include "refbase.h"
#include "surface.h"

namespace OHOS::CameraStandard {
enum class EngineVideoCodecType : int32_t {
    VIDEO_ENCODE_TYPE_AVC = 0,
    VIDEO_ENCODE_TYPE_HEVC,
};

struct EngineLocation {
    double latitude;
    double longitude;
    double altitude;
};

struct EngineMovieSettings {
    EngineVideoCodecType videoCodecType;
    int32_t rotation;
    bool isHasLocation;
    EngineLocation location;
    bool isBFrameEnabled;
    int32_t videoBitrate;
};

class RecorderIntf : public RefBase {
public:
    virtual ~RecorderIntf() = default;
    virtual int32_t GetMuxerRotation() = 0;
    virtual void SetFirstFrameTimestamp(int64_t firstTimestamp) = 0;
    virtual void EnableDetectedObjectLifecycleReport(bool isEnable, int64_t timestamp) = 0;
    virtual bool IsMovieStreamHdr() = 0;
};

class RecorderEngineIntf {
public:
    virtual ~RecorderEngineIntf() = default;
    virtual void CreateRecorderEngine(wptr<RecorderIntf> recorder) = 0;
    virtual int32_t Prepare() = 0;
    virtual int32_t StartRecording() = 0;
    virtual int32_t PauseRecording() = 0;
    virtual int32_t ResumeRecording() = 0;
    virtual int32_t StopRecording() = 0;
    virtual int32_t SetRotation(int32_t rotation) = 0;
    virtual int32_t SetOutputSettings(const EngineMovieSettings& movieSettings) = 0;
    virtual int32_t Init() = 0;
    virtual int32_t GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters) = 0;
    virtual int32_t SetVideoFilter(const std::string& filter, const std::string& filterParam) = 0;
    virtual int32_t SetUserMeta(const std::string& key, const std::string& val) = 0;
    virtual int32_t SetUserMeta(const std::string& key, const std::vector<uint8_t>& val) = 0;
    virtual void GetFirstFrameTimestamp(int64_t& firstFrameTimestamp) = 0;
    virtual void SetIsWaitForMeta(bool isWait) = 0;
    virtual void SetIsWaitForMuxerDone(bool isWait) = 0;
    virtual void SetIsStreamStarted(bool isStarted) = 0;
    virtual int32_t UpdatePhotoProxy(const std::string& videoId, int32_t videoEnhancementType) = 0;
    virtual bool IsNeedWaitForMuxerDone() = 0;
    virtual sptr<Surface> GetRawSurface() = 0;
    virtual sptr<Surface> GetDepthSurface() = 0;
    virtual sptr<Surface> GetPreySurface() = 0;
    virtual sptr<Surface> GetMetaSurface() = 0;
    virtual sptr<Surface> GetMovieDebugSurface() = 0;
    virtual sptr<Surface> GetRawDebugSurface() = 0;
    virtual sptr<Surface> GetImageEffectSurface() = 0;
    virtual void WaitForRawMuxerDone() = 0;
    virtual void SetMovieFrameSize(int32_t width, int32_t height) = 0;
    virtual void SetRawFrameSize(int32_t width, int32_t height) = 0;
    virtual int32_t EnableVirtualAperture(bool isVirtualApertureEnabled) = 0;
    virtual std::string GetMovieFileUri() = 0;
    virtual bool IsNeedStopCallback() = 0;
    virtual void SetIsNeedStopCallback(bool isNeed) = 0;
    virtual void SetIsNeedWaitForRawMuxerDone(bool isNeed) = 0;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_RECORDER_ENGINE_INTERFACE_H