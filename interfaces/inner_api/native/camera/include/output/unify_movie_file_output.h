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

#ifndef UNIFY_MOVIE_FILE_OUTPUT_H
#define UNIFY_MOVIE_FILE_OUTPUT_H

#include "camera_listener_manager.h"
#include "capture_output.h"
#include "movie_file_output_callback_stub.h"
#include "imovie_file_output.h"
#include "video_capability.h"

namespace OHOS {
namespace CameraStandard {

class UnifyMovieFileOutputStateCallback {
public:
    UnifyMovieFileOutputStateCallback() = default;
    virtual ~UnifyMovieFileOutputStateCallback() = default;
    virtual void OnStart() = 0;
    virtual void OnPause() = 0;
    virtual void OnResume() = 0;
    virtual void OnStop() = 0;
    virtual void OnMovieInfoAvailable(int32_t captureId, std::string uri) = 0;
    virtual void OnError(const int32_t errorCode) = 0;
};

class UnifyMovieFileOutputListenerManager;
class UnifyMovieFileOutput : public CaptureOutput {
public:
    UnifyMovieFileOutput(sptr<IMovieFileOutput> movieFileOutputProxy);
    virtual ~UnifyMovieFileOutput();

    virtual int32_t Release() override;

    virtual void CameraServerDied(pid_t pid) override;

    virtual int32_t CreateStream() override;

    int32_t SetOutputSettings(std::shared_ptr<MovieSettings> movieSettings);

    std::shared_ptr<MovieSettings> GetOutputSettings();

    int32_t GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes);

    int32_t GetSupportedVideoFilters(std::vector<std::string>& supportedVideoFilters);

    int32_t AddVideoFilter(const std::string& filter, const std::string& filterParam);

    int32_t RemoveVideoFilter(const std::string& filter);

    bool IsMirrorSupported();

    int32_t EnableMirror(bool isEnable);

    int32_t Start();

    int32_t Pause();

    int32_t Resume();

    int32_t Stop();

    int32_t IsAutoDeferredVideoEnhancementSupported(bool& isSupported);

    int32_t IsAutoDeferredVideoEnhancementEnabled(bool& isEnabled);

    int32_t EnableAutoDeferredVideoEnhancement(bool enabled);

    bool IsAutoVideoFrameRateSupported();

    int32_t EnableAutoVideoFrameRate(bool enable);

    int32_t GetVideoRotation(int32_t& imageRotation);

    sptr<VideoCapability> GetSupportedVideoCapability(int32_t videoCodecType);

    void AddUnifyMovieFileOutputStateCallback(std::shared_ptr<UnifyMovieFileOutputStateCallback> callback);

    void RemoveUnifyMovieFileOutputStateCallback(std::shared_ptr<UnifyMovieFileOutputStateCallback> callback);

    inline sptr<IMovieFileOutput> GetMovieFileOutputProxy()
    {
        std::lock_guard<std::mutex> lock(movieFileOutputProxyMutex_);
        return movieFileOutputProxy_;
    }

    inline sptr<UnifyMovieFileOutputListenerManager> GetUnifyMovieFileOutputListenerManager()
    {
        return unifyMovieFileOutputListenerManager_;
    }

private:
    inline void ClearMovieFileOutputProxy()
    {
        std::lock_guard<std::mutex> lock(movieFileOutputProxyMutex_);
        movieFileOutputProxy_ = nullptr;
    }

    std::mutex movieFileOutputProxyMutex_;
    sptr<IMovieFileOutput> movieFileOutputProxy_;

    std::mutex currentMovieFileOutputSettingsMutex_;
    std::shared_ptr<MovieSettings> currentMovieFileOutputSettings_;

    sptr<UnifyMovieFileOutputListenerManager> unifyMovieFileOutputListenerManager_ =
        sptr<UnifyMovieFileOutputListenerManager>::MakeSptr();
    
    std::mutex videoCapabilityMutex_;
    sptr<VideoCapability> videoCapability_ {nullptr};
};

class UnifyMovieFileOutputListenerManager : public MovieFileOutputCallbackStub,
                                            public CameraListenerManager<UnifyMovieFileOutputStateCallback> {
public:
    int32_t OnRecordingStart() override;
    int32_t OnRecordingPause() override;
    int32_t OnRecordingResume() override;
    int32_t OnRecordingStop() override;
    int32_t OnMovieInfoAvailable(int32_t captureId, const std::string& uri) override;
    int32_t OnError(const int32_t errorCode) override;

    inline void SetUnifyMovieFileOutput(wptr<UnifyMovieFileOutput> unifyMovieFileOutput)
    {
        unifyMovieFileOutput_ = unifyMovieFileOutput;
    };
    sptr<UnifyMovieFileOutput> GetUnifyMovieFileOutput()
    {
        return unifyMovieFileOutput_.promote();
    }

private:
    wptr<UnifyMovieFileOutput> unifyMovieFileOutput_ = nullptr;
};

} // namespace CameraStandard
} // namespace OHOS
#endif
