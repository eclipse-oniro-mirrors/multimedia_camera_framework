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

#ifndef OHOS_CAMERA_MOVIE_FILE_PROXY_H
#define OHOS_CAMERA_MOVIE_FILE_PROXY_H

#include "movie_file_interface.h"
#include "camera_dynamic_loader.h"

namespace OHOS::CameraStandard {
class MovieFileProxy : public MovieFileIntf {
public:
    explicit MovieFileProxy(std::shared_ptr<Dynamiclib> movieFileLib, std::shared_ptr<MovieFileIntf> movieFileIntf);
    ~MovieFileProxy() override;
    static std::shared_ptr<MovieFileProxy> CreateMovieFileProxy();
    static void FreeMovieFileDynamiclib();
    void CreateMovieControllerVideo(
        int32_t width, int32_t height, bool isHdr, int32_t frameRate, int32_t videoBitrate) override;
    void ReleaseController() override;
    sptr<OHOS::IBufferProducer> GetVideoProducer() override;
    sptr<OHOS::IBufferProducer> GetMetaProducer() override;
    int32_t MuxMovieFileStart(int64_t timestamp, MovieSettings movieSettings, int32_t cameraPosition) override;
    std::string MuxMovieFileStop(int64_t timestamp) override;
    void MuxMovieFilePause(int64_t timestamp) override;
    void MuxMovieFileResume() override;
    void AddVideoFilter(const std::string& filterName, const std::string& filterParam) override;
    void RemoveVideoFilter(const std::string& filterName) override;
    sptr<IStreamRepeatCallback> GetVideoStreamCallback() override;
    bool WaitFirstFrame() override;
    void ReleaseConsumer() override;
    void ChangeCodecSettings(
        VideoCodecType codecType, int32_t rotation, bool isBFrame, int32_t videoBitrate) override;

private:
    // Keep the order of members in this class, the bottom member will be destroyed first
    std::shared_ptr<Dynamiclib> movieFileLib_ = {nullptr};
    std::shared_ptr<MovieFileIntf> movieFileIntf_ = {nullptr};
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_MOVIE_FILE_PROXY_H