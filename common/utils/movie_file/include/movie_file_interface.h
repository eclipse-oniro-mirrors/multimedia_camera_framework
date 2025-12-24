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

#ifndef OHOS_CAMERA_MOVIE_FILE_INTERFACE_H
#define OHOS_CAMERA_MOVIE_FILE_INTERFACE_H

#include "surface.h"
#include "istream_repeat_callback.h"

namespace OHOS::CameraStandard {
class MovieFileIntf {
public:
    virtual ~MovieFileIntf() = default;
    virtual void CreateMovieControllerVideo(
        int32_t width, int32_t height, bool isHdr, int32_t frameRate, int32_t videoBitrate) = 0;
    virtual void ReleaseController() = 0;
    virtual sptr<OHOS::IBufferProducer> GetVideoProducer() = 0;
    virtual sptr<OHOS::IBufferProducer> GetMetaProducer() = 0;
    virtual int32_t MuxMovieFileStart(int64_t timestamp, MovieSettings movieSettings, int32_t cameraPosition) = 0;
    virtual std::string MuxMovieFileStop(int64_t timestamp) = 0;
    virtual void MuxMovieFilePause(int64_t timestamp) = 0;
    virtual void MuxMovieFileResume() = 0;
    virtual void AddVideoFilter(const std::string& filterName, const std::string& filterParam) = 0;
    virtual void RemoveVideoFilter(const std::string& filterName) = 0;
    virtual sptr<IStreamRepeatCallback> GetVideoStreamCallback() = 0;
    virtual bool WaitFirstFrame() = 0;
    virtual void ReleaseConsumer() = 0;
    virtual void ChangeCodecSettings(
        VideoCodecType codecType, int32_t rotation, bool isBFrame, int32_t videoBitrate) = 0;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_MOVIE_FILE_INTERFACE_H