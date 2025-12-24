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

#include "util/moving_photo_engine_context.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

MovingPhotoRecorderEngineContext::MovingPhotoRecorderEngineContext()
{
    MEDIA_INFO_LOG("MovingPhotoRecorderEngineContext::MovingPhotoRecorderEngineContext called");
}

MovingPhotoRecorderEngineContext::~MovingPhotoRecorderEngineContext()
{
    MEDIA_INFO_LOG("MovingPhotoRecorderEngineContext::~MovingPhotoRecorderEngineContext called");
    taskManager_ = nullptr;
    audioCacheFilter_ = nullptr;
    videoCacheFilter_ = nullptr;
    videoEncoderFilter_ = nullptr;
    metaCacheFilter_ = nullptr;
    muxerFilter_ = nullptr;
}

void MovingPhotoRecorderEngineContext::SetTaskManager(sptr<MovingPhotoRecorderTaskManager> taskManager)
{
    CHECK_RETURN(!taskManager);
    taskManager_ = taskManager;
    auto weakPtr= wptr<MovingPhotoRecorderEngineContext>(this);
    taskManager->SetEngineContext(weakPtr);
}

sptr<MovingPhotoRecorderTaskManager> MovingPhotoRecorderEngineContext::GetTaskManager()
{
    return taskManager_;
}

void MovingPhotoRecorderEngineContext::SetAudioCacheFilter(std::shared_ptr<AudioCacheFilter> audioCacheFilter)
{
    CHECK_RETURN(!audioCacheFilter);
    audioCacheFilter_ = audioCacheFilter;
    auto weakPtr= wptr<MovingPhotoRecorderEngineContext>(this);
    audioCacheFilter->SetEngineContext(weakPtr);
}

std::shared_ptr<AudioCacheFilter> MovingPhotoRecorderEngineContext::GetAudioCacheFilter()
{
    return audioCacheFilter_;
}

void MovingPhotoRecorderEngineContext::SetVideoCacheFilter(std::shared_ptr<VideoCacheFilter> videoCacheFilter)
{
    CHECK_RETURN(!videoCacheFilter);
    videoCacheFilter_ = videoCacheFilter;
    auto weakPtr= wptr<MovingPhotoRecorderEngineContext>(this);
    videoCacheFilter->SetEngineContext(weakPtr);
}

std::shared_ptr<VideoCacheFilter> MovingPhotoRecorderEngineContext::GetVideoCacheFilter()
{
    return videoCacheFilter_;
}

void MovingPhotoRecorderEngineContext::SetMetaCacheFilter(std::shared_ptr<MetaCacheFilter> metaCacheFilter)
{
    CHECK_RETURN(!metaCacheFilter);
    metaCacheFilter_ = metaCacheFilter;
    auto weakPtr= wptr<MovingPhotoRecorderEngineContext>(this);
    metaCacheFilter->SetEngineContext(weakPtr);
}

std::shared_ptr<MetaCacheFilter> MovingPhotoRecorderEngineContext::GetMetaCacheFilter()
{
    return metaCacheFilter_;
}

void MovingPhotoRecorderEngineContext::SetVideoEncoderFilter(
    std::shared_ptr<MovingPhotoVideoEncoderFilter> videoEncoderFilter)
{
    CHECK_RETURN(!videoEncoderFilter);
    videoEncoderFilter_ = videoEncoderFilter;
    auto weakPtr= wptr<MovingPhotoRecorderEngineContext>(this);
    videoEncoderFilter->SetEngineContext(weakPtr);
}

std::shared_ptr<MovingPhotoVideoEncoderFilter> MovingPhotoRecorderEngineContext::GetVideoEncoderFilter()
{
    return videoEncoderFilter_;
}

void MovingPhotoRecorderEngineContext::SetAudioEncoderFilter(
    std::shared_ptr<MovingPhotoAudioEncoderFilter> audioEncoderFilter)
{
    CHECK_RETURN(!audioEncoderFilter);
    audioEncoderFilter_ = audioEncoderFilter;
    auto weakPtr= wptr<MovingPhotoRecorderEngineContext>(this);
    audioEncoderFilter->SetEngineContext(weakPtr);
}

std::shared_ptr<MovingPhotoAudioEncoderFilter> MovingPhotoRecorderEngineContext::GetAudioEncoderFilter()
{
    return audioEncoderFilter_;
}

void MovingPhotoRecorderEngineContext::SetMovingPhotoMuxerFilter(std::shared_ptr<MovingPhotoMuxerFilter> muxerFilter)
{
    CHECK_RETURN(!muxerFilter);
    muxerFilter_ = muxerFilter;
    auto weakPtr= wptr<MovingPhotoRecorderEngineContext>(this);
    muxerFilter->SetEngineContext(weakPtr);
}

std::shared_ptr<MovingPhotoMuxerFilter> MovingPhotoRecorderEngineContext::GetMovingPhotoMuxerFilter()
{
    return muxerFilter_;
}
} // namespace CameraStandard
} // namespace OHOS