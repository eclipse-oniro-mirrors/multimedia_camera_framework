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

#ifndef MOVING_PHOTO_ENGINE_CONTEXT_H
#define MOVING_PHOTO_ENGINE_CONTEXT_H

#include "moving_photo_recorder_task.h"
#include "meta_cache_filter.h"
#include "audio_cache_filter.h"
#include "video_cache_filter.h"
#include "moving_photo_video_encoder_filter.h"
#include "moving_photo_muxer_filter.h"
#include "moving_photo_audio_encoder_filter.h"

namespace OHOS {
namespace CameraStandard {

class MovingPhotoRecorderEngineContext : public RefBase{
public:
    MovingPhotoRecorderEngineContext();
    ~MovingPhotoRecorderEngineContext();
    void SetTaskManager(sptr<MovingPhotoRecorderTaskManager> taskManager);
    sptr<MovingPhotoRecorderTaskManager> GetTaskManager();

    void SetAudioCacheFilter(std::shared_ptr<AudioCacheFilter> audioCacheFilter);
    std::shared_ptr<AudioCacheFilter> GetAudioCacheFilter();

    void SetVideoCacheFilter(std::shared_ptr<VideoCacheFilter> videoCacheFilter);
    std::shared_ptr<VideoCacheFilter> GetVideoCacheFilter();

    void SetMetaCacheFilter(std::shared_ptr<MetaCacheFilter> metaCacheFilter);
    std::shared_ptr<MetaCacheFilter> GetMetaCacheFilter();

    void SetVideoEncoderFilter(std::shared_ptr<MovingPhotoVideoEncoderFilter> videoEncoderFilter);
    std::shared_ptr<MovingPhotoVideoEncoderFilter> GetVideoEncoderFilter();

    void SetAudioEncoderFilter(std::shared_ptr<MovingPhotoAudioEncoderFilter> audioEncoderFilter);
    std::shared_ptr<MovingPhotoAudioEncoderFilter> GetAudioEncoderFilter();

    void SetMovingPhotoMuxerFilter(std::shared_ptr<MovingPhotoMuxerFilter> muxerFilter);
    std::shared_ptr<MovingPhotoMuxerFilter> GetMovingPhotoMuxerFilter();

private:
    sptr<MovingPhotoRecorderTaskManager> taskManager_{nullptr};
    std::shared_ptr<AudioCacheFilter> audioCacheFilter_ {nullptr};
    std::shared_ptr<VideoCacheFilter> videoCacheFilter_ {nullptr};
    std::shared_ptr<MovingPhotoAudioEncoderFilter> audioEncoderFilter_ {nullptr};
    std::shared_ptr<MovingPhotoVideoEncoderFilter> videoEncoderFilter_ {nullptr};
    std::shared_ptr<MetaCacheFilter> metaCacheFilter_ {nullptr};
    std::shared_ptr<MovingPhotoMuxerFilter> muxerFilter_ {nullptr};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // MOVING_PHOTO_ENGINE_CONTEXT_H