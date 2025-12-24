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

#include "movie_file_adapter.h"
#include "movie_file_controller_video.h"
#include "camera_log.h"

namespace OHOS::CameraStandard {
MovieFileAdapter::MovieFileAdapter()
{
    MEDIA_DEBUG_LOG("MovieFileAdapter ctor");
}

void MovieFileAdapter::CreateMovieControllerVideo(
    int32_t width, int32_t height, bool isHdr, int32_t frameRate, int32_t videoBitrate)
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::CreateMovieControllerVideo is called");
    auto controller = std::make_shared<MovieFileControllerVideo>(width, height, isHdr, frameRate, videoBitrate);
    movieFileController_.Set(controller);
}

void MovieFileAdapter::ReleaseController()
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::ReleaseController is called");
    movieFileController_.Set(nullptr);
}

sptr<OHOS::IBufferProducer> MovieFileAdapter::GetVideoProducer()
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::GetVideoProducer is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_RET_ELOG(movieFileController == nullptr, nullptr, "movieFileController is null");
    return movieFileController->GetVideoProducer();
}

sptr<OHOS::IBufferProducer> MovieFileAdapter::GetMetaProducer()
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::GetMetaProducer is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_RET_ELOG(movieFileController == nullptr, nullptr, "movieFileController is null");
    return movieFileController->GetMetaProducer();
}

int32_t MovieFileAdapter::MuxMovieFileStart(int64_t timestamp, MovieSettings movieSettings, int32_t cameraPosition)
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::MuxMovieFileStart is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_RET_ELOG(movieFileController == nullptr, MEDIA_ERR, "movieFileController is null");
    return movieFileController->MuxMovieFileStart(timestamp, movieSettings, cameraPosition);
}

std::string MovieFileAdapter::MuxMovieFileStop(int64_t timestamp)
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::MuxMovieFileStop is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_RET_ELOG(movieFileController == nullptr, "", "movieFileController is null");
    return movieFileController->MuxMovieFileStop(timestamp);
}

void MovieFileAdapter::MuxMovieFilePause(int64_t timestamp)
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::MuxMovieFilePause is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_ELOG(movieFileController == nullptr, "movieFileController is null");
    movieFileController->MuxMovieFilePause(timestamp);
}

void MovieFileAdapter::MuxMovieFileResume()
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::MuxMovieFileResume is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_ELOG(movieFileController == nullptr, "movieFileController is null");
    movieFileController->MuxMovieFileResume();
}

void MovieFileAdapter::AddVideoFilter(const std::string& filterName, const std::string& filterParam)
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::AddVideoFilter is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_ELOG(movieFileController == nullptr, "movieFileController is null");
    movieFileController->AddVideoFilter(filterName, filterParam);
}

void MovieFileAdapter::RemoveVideoFilter(const std::string& filterName)
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::RemoveVideoFilter is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_ELOG(movieFileController == nullptr, "movieFileController is null");
    movieFileController->RemoveVideoFilter(filterName);
}

sptr<IStreamRepeatCallback> MovieFileAdapter::GetVideoStreamCallback()
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::GetVideoStreamCallback is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_RET_ELOG(movieFileController == nullptr, nullptr, "movieFileController is null");
    return movieFileController->GetVideoStreamCallback();
}

bool MovieFileAdapter::WaitFirstFrame()
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::WaitFirstFrame is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_RET_ELOG(movieFileController == nullptr, false, "movieFileController is null");
    return movieFileController->WaitFirstFrame();
}

void MovieFileAdapter::ReleaseConsumer()
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::ReleaseConsumer is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_ELOG(movieFileController == nullptr, "movieFileController is null");
    movieFileController->ReleaseConsumer();
}

void MovieFileAdapter::ChangeCodecSettings(
    VideoCodecType codecType, int32_t rotation, bool isBFrame, int32_t videoBitrate)
{
    MEDIA_DEBUG_LOG("MovieFileAdapter::ChangeCodecSettings is called");
    auto movieFileController = movieFileController_.Get();
    CHECK_RETURN_ELOG(movieFileController == nullptr, "movieFileController is null");
    movieFileController->ChangeCodecSettings(codecType, rotation, isBFrame, videoBitrate);
}

extern "C" MovieFileIntf *createMovieFileIntf()
{
    return new MovieFileAdapter();
}
}  // namespace OHOS::CameraStandard