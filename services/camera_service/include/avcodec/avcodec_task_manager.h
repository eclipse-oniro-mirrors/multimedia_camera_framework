/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef CAMERA_FRAMEWORK_LIVEPHOTO_GENERATOR_H
#define CAMERA_FRAMEWORK_LIVEPHOTO_GENERATOR_H

#include <mutex>
#include <memory>
#include <atomic>
#include <queue>
#include <thread>
#include <fstream>
#include "frame_record.h"
#include "audio_record.h"
#include "audio_capturer_session.h"
#include "native_avmuxer.h"
#include "refbase.h"
#include "surface_buffer.h"
#include "video_encoder.h"
#include "audio_encoder.h"
#include "audio_video_muxer.h"
#include "iconsumer_surface.h"
#include "blocking_queue.h"
#include "task_manager.h"

#include "media_photo_asset_proxy.h"

namespace OHOS {
namespace CameraStandard {
using namespace std;
using namespace DeferredProcessing;
using namespace Media;
using CacheCbFunc = function<void(sptr<FrameRecord>, bool)>;
constexpr uint32_t DEFAULT_THREAD_NUMBER = 6;
constexpr uint32_t DEFAULT_ENCODER_THREAD_NUMBER = 1;
constexpr uint32_t GET_FD_EXPIREATION_TIME = 500;
class AvcodecTaskManager : public RefBase, public std::enable_shared_from_this<AvcodecTaskManager> {
public:
    explicit AvcodecTaskManager(sptr<AudioCapturerSession> audioCapturerSession);
    ~AvcodecTaskManager();
    void EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback);
    void CollectAudioBuffer(vector<sptr<AudioRecord>> audioRecordVec, sptr<AudioVideoMuxer> muxer);
    void DoMuxerVideo(vector<sptr<FrameRecord>> frameRecords, string taskName);
    sptr<AudioVideoMuxer> CreateAVMuxer(vector<sptr<FrameRecord>> frameRecord);
    void SubmitTask(function<void()> task);
    void SetVideoFd(int32_t videoFd, shared_ptr<PhotoAssetProxy> photoAssetProxy);
    void Stop();

private:
    void FinishMuxer(sptr<AudioVideoMuxer> muxer);
    void Release();
    unique_ptr<VideoEncoder> videoEncoder_ = nullptr;
    unique_ptr<AudioEncoder> audioEncoder_ = nullptr;
    unique_ptr<TaskManager> taskManager_ = nullptr;
    unique_ptr<TaskManager> audioEncoderManager_ = nullptr;
    unique_ptr<TaskManager> videoEncoderManager_ = nullptr;
    sptr<AudioCapturerSession> audioCapturerSession_ = nullptr;
    condition_variable cvEmpty_;
    mutex videoFdMutex_;
    queue<std::pair<int32_t, shared_ptr<PhotoAssetProxy>>> videoFdQueue_;
};
} // CameraStandard
} // OHOS
#endif // CAMERA_FRAMEWORK_LIVEPHOTO_GENERATOR_H