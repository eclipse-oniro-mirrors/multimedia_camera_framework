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

#ifndef OHOS_CAMERA_H_CAMERA_MOVIE_FILE_OUTPUT_H
#define OHOS_CAMERA_H_CAMERA_MOVIE_FILE_OUTPUT_H

#include "camera_util.h"
#include "hstream_repeat.h"
#include "imovie_file_output_callback.h"
#include "movie_file_proxy.h"
#include "movie_file_output_stub.h"
#include "sp_holder.h"

namespace OHOS {
namespace CameraStandard {
class HCameraMovieFileOutput : public MovieFileOutputStub, public ICameraIpcChecker {
public:
    struct MovieFileOutputFrameRateRange {
        int32_t minFrameRate = 30;
        int32_t maxFrameRate = 30;
    };

public:
    HCameraMovieFileOutput(int32_t format, int32_t width,
    int32_t height, MovieFileOutputFrameRateRange& frameRateRange);

    int32_t Start() override;
    int32_t Stop() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t SetOutputSettings(const MovieSettings& movieSettings) override;
    int32_t GetSupportedVideoFilters(std::vector<std::string>& supportedVideoFilters) override;
    int32_t SetMovieFileOutputCallback(const sptr<IMovieFileOutputCallback>& callbackFunc) override;
    int32_t UnsetMovieFileOutputCallback() override;
    int32_t AddVideoFilter(const std::string& filter, const std::string& filterParam) override;
    int32_t RemoveVideoFilter(const std::string& filter) override;
    int32_t EnableMirror(bool isEnable) override;
    int32_t IsMirrorEnabled(bool& isEnable) override;
    int32_t Release() override;
    int32_t GetSupportedVideoCapability(int32_t videoCodecType,
        std::shared_ptr<MediaCapabilityProxy>& mediaCapability) override;

    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

    // implement ICameraIpcChecker
    int32_t OperatePermissionCheck(uint32_t interfaceCode) override;

    int32_t InitConfig(int32_t opMode);
    std::vector<sptr<HStreamRepeat>> GetStreams();

    void SetCameraPosition(int32_t position);

    void GetCurrentTime(int64_t &currentTime);

    inline MovieFileOutputFrameRateRange GetMovieFileOutputFrameRateRange()
    {
        return frameRateRange_;
    }

private:
    void InitCallerInfo();

    inline sptr<IMovieFileOutputCallback> GetMovieFileOutputCallback()
    {
        std::lock_guard<std::mutex> lock(movieFileOutputCallbackMtx_);
        return movieFileOutputCallback_;
    }

    SpHolder<std::shared_ptr<MovieFileProxy>> movieFileProxy_;

    SpHolder<sptr<HStreamRepeat>> videoStreamRepeat_;

    std::mutex movieFileOutputCallbackMtx_;
    sptr<IMovieFileOutputCallback> movieFileOutputCallback_ = nullptr;

    MovieSettings currentMovieSettings_ {};

    int32_t format_ = 0;
    int32_t width_ = 0;
    int32_t height_ = 0;

    MovieFileOutputFrameRateRange frameRateRange_;

    int32_t appUid_ = 0;
    int32_t appPid_ = 0;
    uint32_t appTokenId_ = 0;
    uint64_t appFullTokenId_ = 0;
    std::string bundleName_ = "";
    int32_t cameraPosition_ = -1; // -1 represents an uninitialized state.
};
} // namespace CameraStandard
} // namespace OHOS

#endif