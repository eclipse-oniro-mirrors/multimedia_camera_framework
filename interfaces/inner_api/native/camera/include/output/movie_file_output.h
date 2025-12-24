/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef MOVIE_FILE_OUTPUT_H
#define MOVIE_FILE_OUTPUT_H

#include <memory>

#include "camera_recorder_callback_stub.h"
#include "icamera_recorder.h"
#include "istream_repeat.h"
#include "output/capture_output.h"
#include "video_capability.h"

namespace OHOS {
namespace CameraStandard {
class IMovieFileOutputStateCallback {
public:
    IMovieFileOutputStateCallback() = default;
    virtual ~IMovieFileOutputStateCallback() = default;
    virtual void OnRecordingStart() const = 0;
    virtual void OnRecordingPause() const = 0;
    virtual void OnRecordingResume() const = 0;
    virtual void OnRecordingStop() const = 0;
    virtual void OnPhotoAssetAvailable(const std::string& uri) const = 0;
    virtual void OnError(const int32_t errorCode) const = 0;
};

class MovieFileOutput : public CaptureOutput {
public:
    MovieFileOutput();
    virtual ~MovieFileOutput();
    int32_t CreateStream() override;
    int32_t Release() override;
    void CameraServerDied(pid_t pid) override;
    int32_t Prepare();
    int32_t Start();
    int32_t Pause();
    int32_t Resume();
    int32_t Stop();
    int32_t SetRotation(int32_t rotation);
    void SetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate);
    void SetRawVideoStream(sptr<IStreamCommon> stream);
    sptr<IStreamCommon> GetRawVideoStream();
    void SetCallback(std::shared_ptr<IMovieFileOutputStateCallback> callback);
    void AddRecorderCallback();
    std::shared_ptr<IMovieFileOutputStateCallback> GetApplicationCallback();
    void SetRecorder(sptr<ICameraRecorder> recorder);
    int32_t SetOutputSettings(const std::shared_ptr<MovieSettings>& movieSettings);
    std::shared_ptr<MovieSettings> GetOutputSettings();
    sptr<VideoCapability> GetSupportedVideoCapability(int32_t videoCodecType);
    int32_t GetSupportedVideoCodecTypes(std::vector<int32_t> &supportedVideoCodecTypes);
    bool IsMirrorSupported();
    int32_t EnableMirror(bool isEnable);
    int32_t GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters);
    int32_t SetVideoFilter(const std::string& filter, const std::string& filterParam);
private:
    void SetUserMeta();
    int32_t GetCameraPosition();

    std::vector<int32_t> videoFrameRateRange_{0, 0};
    std::shared_ptr<IMovieFileOutputStateCallback> appCallback_;
    sptr<ICameraRecorderCallback> svcCallback_;
    std::mutex streamMutex_;
    sptr<IStreamCommon> rawVideoStream_;
    sptr<ICameraRecorder> recorder_;
    std::shared_ptr<MovieSettings> currentSettings_;
    std::mutex videoCapabilityMutex_;
    sptr<VideoCapability> videoCapability_;
};

class MovieFileOutputCallbackImpl : public CameraRecorderCallbackStub {
public:
    MovieFileOutputCallbackImpl() : movieFileOutput_(nullptr) {}
    explicit MovieFileOutputCallbackImpl(MovieFileOutput* movieFileOutput) : movieFileOutput_(movieFileOutput) {}

    ~MovieFileOutputCallbackImpl()
    {
        movieFileOutput_ = nullptr;
    }

    int32_t OnRecordingStart() override;
    int32_t OnRecordingPause() override;
    int32_t OnRecordingResume() override;
    int32_t OnRecordingStop() override;
    int32_t OnPhotoAssetAvailable(const std::string& uri) override;
    int32_t OnError(const int32_t errorCode) override;

    wptr<MovieFileOutput> movieFileOutput_ = nullptr;
};

} // namespace CameraStandard
} // namespace OHOS
#endif
