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

#include "movie_file_proxy.h"
#include "camera_log.h"
#include "movie_file_interface.h"

namespace OHOS::CameraStandard {

MovieFileProxy::MovieFileProxy(std::shared_ptr<Dynamiclib> movieFileLib, std::shared_ptr<MovieFileIntf> movieFileIntf)
    : movieFileLib_(movieFileLib), movieFileIntf_(movieFileIntf)
{
    MEDIA_DEBUG_LOG("MovieFileProxy constructor");
}

MovieFileProxy::~MovieFileProxy()
{
    MEDIA_DEBUG_LOG("MovieFileProxy destructor");
}

using CreateMovieFileIntf = MovieFileIntf*(*)();

std::shared_ptr<MovieFileProxy> MovieFileProxy::CreateMovieFileProxy()
{
    MEDIA_DEBUG_LOG("CreateMovieFileProxy start");
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MOVIE_FILE_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "get dynamiclib fail");
    CreateMovieFileIntf createMovieFileIntf = (CreateMovieFileIntf)dynamiclib->GetFunction("createMovieFileIntf");
    CHECK_RETURN_RET_ELOG(createMovieFileIntf == nullptr, nullptr, "createMovieFileIntf fail");
    MovieFileIntf* movieFileIntf = createMovieFileIntf();
    CHECK_RETURN_RET_ELOG(movieFileIntf == nullptr, nullptr, "get movieFileIntf fail");
    auto movieFileProxy = std::make_shared<MovieFileProxy>(dynamiclib, std::shared_ptr<MovieFileIntf>(movieFileIntf));
    return movieFileProxy;
}

void MovieFileProxy::FreeMovieFileDynamiclib()
{
    constexpr uint32_t delayMs = 60 * 1000; // 60 second
    CameraDynamicLoader::FreeDynamicLibDelayed(MOVIE_FILE_SO, delayMs);
}

void MovieFileProxy::CreateMovieControllerVideo(
    int32_t width, int32_t height, bool isHdr, int32_t frameRate, int32_t videoBitrate)
{
    MEDIA_DEBUG_LOG("MovieFileProxy::CreateMovieControllerVideo is called");
    CHECK_RETURN_ELOG(movieFileIntf_ == nullptr, "movieFileIntf_ is nullptr");
    movieFileIntf_->CreateMovieControllerVideo(width, height, isHdr, frameRate, videoBitrate);
}

void MovieFileProxy::ReleaseController()
{
    MEDIA_DEBUG_LOG("MovieFileProxy::ReleaseController is called");
    CHECK_RETURN_ELOG(movieFileIntf_ == nullptr, "movieFileIntf_ is nullptr");
    movieFileIntf_->ReleaseController();
}

sptr<OHOS::IBufferProducer> MovieFileProxy::GetVideoProducer()
{
    MEDIA_DEBUG_LOG("MovieFileProxy::GetVideoProducer is called");
    CHECK_RETURN_RET_ELOG(movieFileIntf_ == nullptr, nullptr, "movieFileIntf_ is nullptr");
    auto producer = movieFileIntf_->GetVideoProducer();
    CHECK_RETURN_RET_ILOG(producer == nullptr, nullptr, "MovieFileProxy::GetVideoProducer, producer is null");
    MEDIA_INFO_LOG("MovieFileProxy::GetVideoProducer uniqueid: %{public}" PRIu64, producer->GetUniqueId());
    return producer;
}

sptr<OHOS::IBufferProducer> MovieFileProxy::GetMetaProducer()
{
    MEDIA_DEBUG_LOG("MovieFileProxy::GetMetaProducer is called");
    CHECK_RETURN_RET_ELOG(movieFileIntf_ == nullptr, nullptr, "movieFileIntf_ is nullptr");
    auto producer = movieFileIntf_->GetMetaProducer();
    CHECK_RETURN_RET_ILOG(producer == nullptr, nullptr, "MovieFileProxy::GetMetaProducer, producer is null");
    MEDIA_INFO_LOG("MovieFileProxy::GetMetaProducer uniqueid: %{public}" PRIu64, producer->GetUniqueId());
    return producer;
}

int32_t MovieFileProxy::MuxMovieFileStart(int64_t timestamp, MovieSettings movieSettings, int32_t cameraPosition)
{
    MEDIA_DEBUG_LOG("MovieFileProxy::MuxMovieFileStart is called");
    CHECK_RETURN_RET_ELOG(movieFileIntf_ == nullptr, MEDIA_ERR, "movieFileIntf_ is nullptr");
    return movieFileIntf_->MuxMovieFileStart(timestamp, movieSettings, cameraPosition);
}

std::string MovieFileProxy::MuxMovieFileStop(int64_t timestamp)
{
    MEDIA_DEBUG_LOG("MovieFileProxy::MuxMovieFileStop is called");
    CHECK_RETURN_RET_ELOG(movieFileIntf_ == nullptr, "", "movieFileIntf_ is nullptr");
    return movieFileIntf_->MuxMovieFileStop(timestamp);
}

void MovieFileProxy::MuxMovieFilePause(int64_t timestamp)
{
    MEDIA_DEBUG_LOG("MovieFileProxy::MuxMovieFilePause is called");
    CHECK_RETURN_ELOG(movieFileIntf_ == nullptr, "movieFileIntf_ is nullptr");
    movieFileIntf_->MuxMovieFilePause(timestamp);
}

void MovieFileProxy::MuxMovieFileResume()
{
    MEDIA_DEBUG_LOG("MovieFileProxy::MuxMovieFileResume is called");
    CHECK_RETURN_ELOG(movieFileIntf_ == nullptr, "movieFileIntf_ is nullptr");
    movieFileIntf_->MuxMovieFileResume();
}

void MovieFileProxy::AddVideoFilter(const std::string& filterName, const std::string& filterParam)
{
    MEDIA_DEBUG_LOG("MovieFileProxy::AddVideoFilter is called");
    CHECK_RETURN_ELOG(movieFileIntf_ == nullptr, "movieFileIntf_ is nullptr");
    movieFileIntf_->AddVideoFilter(filterName, filterParam);
}

void MovieFileProxy::RemoveVideoFilter(const std::string& filterName)
{
    MEDIA_DEBUG_LOG("MovieFileProxy::RemoveVideoFilter is called");
    CHECK_RETURN_ELOG(movieFileIntf_ == nullptr, "movieFileIntf_ is nullptr");
    movieFileIntf_->RemoveVideoFilter(filterName);
}

sptr<IStreamRepeatCallback> MovieFileProxy::GetVideoStreamCallback()
{
    MEDIA_DEBUG_LOG("MovieFileProxy::GetVideoStreamCallback is called");
    CHECK_RETURN_RET_ELOG(movieFileIntf_ == nullptr, nullptr, "movieFileIntf_ is nullptr");
    return movieFileIntf_->GetVideoStreamCallback();
}

bool MovieFileProxy::WaitFirstFrame()
{
    MEDIA_DEBUG_LOG("MovieFileProxy::WaitFirstFrame is called");
    CHECK_RETURN_RET_ELOG(movieFileIntf_ == nullptr, false, "movieFileIntf_ is nullptr");
    return movieFileIntf_->WaitFirstFrame();
}

void MovieFileProxy::ReleaseConsumer()
{
    MEDIA_DEBUG_LOG("MovieFileProxy::ReleaseConsumer is called");
    CHECK_RETURN_ELOG(movieFileIntf_ == nullptr, "movieFileIntf_ is nullptr");
    movieFileIntf_->ReleaseConsumer();
}

void MovieFileProxy::ChangeCodecSettings(
    VideoCodecType codecType, int32_t rotation, bool isBFrame, int32_t videoBitrate)
{
    MEDIA_DEBUG_LOG("MovieFileProxy::ChangeCodecSettings is called");
    CHECK_RETURN_ELOG(movieFileIntf_ == nullptr, "movieFileIntf_ is nullptr");
    movieFileIntf_->ChangeCodecSettings(codecType, rotation, isBFrame, videoBitrate);
}
}  // namespace OHOS::CameraStandard