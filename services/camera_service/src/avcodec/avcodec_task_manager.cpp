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

#include "avcodec_task_manager.h"
#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <mutex>
#include <unistd.h>
#include <chrono>
#include <fcntl.h>
#include <memory>
#include <utility>
#include "audio_capturer_session.h"
#include "audio_record.h"
#include "audio_video_muxer.h"
#include "external_window.h"
#include "frame_record.h"
#include "native_avbuffer.h"
#include "native_avbuffer_info.h"
#include "native_buffer_inner.h"
#include "camera_log.h"
#include "sample_info.h"

namespace {
    using namespace std::string_literals;
    using namespace std::chrono_literals;
}
namespace OHOS {
namespace CameraStandard {

AvcodecTaskManager::~AvcodecTaskManager()
{
    CAMERA_SYNC_TRACE;
    Release();
}

AvcodecTaskManager::AvcodecTaskManager(sptr<AudioCapturerSession> audioCaptureSession)
{
    CAMERA_SYNC_TRACE;
    audioCapturerSession_ = audioCaptureSession;
    // Create Task Manager
    taskManager_ = make_unique<TaskManager>("AvcodecTaskManager", DEFAULT_THREAD_NUMBER, false);
    audioEncoderManager_ = make_unique<TaskManager>("AudioTaskManager", DEFAULT_ENCODER_THREAD_NUMBER, true);
    videoEncoderManager_ = make_unique<TaskManager>("VideoTaskManager", DEFAULT_ENCODER_THREAD_NUMBER, true);
    videoEncoder_ = make_unique<VideoEncoder>();
    audioEncoder_ = make_unique<AudioEncoder>();
}

void AvcodecTaskManager::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    videoEncoderManager_->SubmitTask([this, frameRecord, cacheCallback]() {
        bool isEncodeSuccess = false;
        if (!videoEncoder_ && !frameRecord) {
            return;
        }
        isEncodeSuccess = videoEncoder_->EncodeSurfaceBuffer(frameRecord);
        if (isEncodeSuccess) {
            videoEncoder_->ReleaseSurfaceBuffer(frameRecord);
        }
        frameRecord->SetEncodedResult(isEncodeSuccess);
        if (isEncodeSuccess) {
            MEDIA_INFO_LOG("encode image success %{public}s, refCount: %{public}d",
                frameRecord->GetFrameId().c_str(),  frameRecord->GetSptrRefCount());
        } else {
            MEDIA_ERR_LOG("encode image fail %{public}s", frameRecord->GetFrameId().c_str());
        }
        if (cacheCallback) {
            cacheCallback(frameRecord, isEncodeSuccess);
        }
    });
}

void AvcodecTaskManager::SubmitTask(function<void()> task)
{
    taskManager_->SubmitTask(task);
}

void AvcodecTaskManager::SetVideoFd(int32_t videoFd, shared_ptr<PhotoAssetProxy> photoAssetProxy)
{
    lock_guard<mutex> lock(videoFdMutex_);
    MEDIA_INFO_LOG("Set videoFd: %{public}d", videoFd);
    videoFdQueue_.push(std::make_pair(videoFd, photoAssetProxy));
    cvEmpty_.notify_all();
}

sptr<AudioVideoMuxer> AvcodecTaskManager::CreateAVMuxer(vector<sptr<FrameRecord>> frameRecords, int32_t captureRotation)
{
    unique_lock<mutex> lock(videoFdMutex_);
    if (videoFdQueue_.empty()) {
        bool waitResult = false;
        waitResult = cvEmpty_.wait_for(lock, std::chrono::milliseconds(GET_FD_EXPIREATION_TIME),
            [this] { return !videoFdQueue_.empty(); });
        if (!waitResult || videoFdQueue_.empty()) {
            return nullptr;
        }
    }
    sptr<AudioVideoMuxer> muxer = new AudioVideoMuxer();
    OH_AVOutputFormat format = AV_OUTPUT_FORMAT_MPEG_4;
    int32_t fd = videoFdQueue_.front().first;
    shared_ptr<PhotoAssetProxy> photoAssetProxy = videoFdQueue_.front().second;
    MEDIA_INFO_LOG("CreateAVMuxer with videoFd: %{public}d", fd);
    videoFdQueue_.pop();
    muxer->Create(fd, format, photoAssetProxy);
    OH_AVFormat *formatVideo = OH_AVFormat_Create();
    OH_AVFormat_SetStringValue(formatVideo, OH_MD_KEY_CODEC_MIME, OH_AVCODEC_MIMETYPE_VIDEO_AVC);
    muxer->SetRotation(frameRecords[0]->GetRotation() + captureRotation);
    bool hasCover = false;
    for (size_t index = frameRecords.size() - 1; index >= 0; index--) {
        auto tempFrameRecord = frameRecords[index];
        if (tempFrameRecord != nullptr && tempFrameRecord->IsCoverFrame()) {
            float coverTime = index * VIDEO_FRAME_INTERVAL_MS;
            MEDIA_INFO_LOG("CreateAVMuxer with SetCoverTime: %{public}f", coverTime);
            muxer->SetCoverTime(coverTime);
            hasCover = true;
            break;
        }
    }
    if (!hasCover) {
        MEDIA_WARNING_LOG("CreateAVMuxer with default coverTime");
        muxer->SetCoverTime(VIDEO_FRAME_INTERVAL_MS);
    }
    OH_AVFormat_SetIntValue(formatVideo, OH_MD_KEY_WIDTH, frameRecords[0]->GetFrameSize()->width);
    OH_AVFormat_SetIntValue(formatVideo, OH_MD_KEY_HEIGHT, frameRecords[0]->GetFrameSize()->height);
    int videoTrackId = -1;
    muxer->AddTrack(videoTrackId, formatVideo, VIDEO_TRACK);
    MEDIA_INFO_LOG("Succeed create videoTrackId %{public}d", videoTrackId);
    OH_AVFormat *formatAudio = OH_AVFormat_Create();
    OH_AVFormat_SetStringValue(formatAudio, OH_MD_KEY_CODEC_MIME, OH_AVCODEC_MIMETYPE_AUDIO_AAC);
    OH_AVFormat_SetIntValue(formatAudio, OH_MD_KEY_AUD_SAMPLE_RATE, DEFAULT_SAMPLERATE);
    OH_AVFormat_SetIntValue(formatAudio, OH_MD_KEY_AUD_CHANNEL_COUNT, DEFAULT_CHANNEL_COUNT);
    int audioTrackId = -1;
    muxer->AddTrack(audioTrackId, formatAudio, AUDIO_TRACK);
    MEDIA_INFO_LOG("Succeed create audioTrackId %{public}d", audioTrackId);
    muxer->Start();
    return muxer;
}

void AvcodecTaskManager::FinishMuxer(sptr<AudioVideoMuxer> muxer)
{
    MEDIA_INFO_LOG("doMxuer video is finished");
    if (muxer) {
        shared_ptr<PhotoAssetProxy> proxy = muxer->GetPhotoAssetProxy();
        MEDIA_INFO_LOG("PhotoAssetProxy notify enter");
        if (proxy) {
            proxy->NotifyVideoSaveFinished();
        }
        muxer->Stop();
        muxer->Release();
    }
}


void AvcodecTaskManager::DoMuxerVideo(vector<sptr<FrameRecord>> frameRecords, string taskName, int32_t captureRotation)
{
    if (frameRecords.empty()) {
        MEDIA_ERR_LOG("DoMuxerVideo error of empty encoded frame");
        return;
    }
    taskManager_->SubmitTask([this, frameRecords, taskName, captureRotation]() {
        MEDIA_INFO_LOG("CreateAVMuxer with %{public}s %{public}s",
            frameRecords.front()->GetFrameId().c_str(), taskName.c_str());
        sptr<AudioVideoMuxer> muxer = this->CreateAVMuxer(frameRecords, captureRotation);
        if (muxer == nullptr) {
            MEDIA_ERR_LOG("CreateAVMuxer failed");
            return;
        }
        // CollectAudioBuffer
        vector<sptr<AudioRecord>> audioRecords;
        if (audioCapturerSession_) {
            int64_t endTime = frameRecords.front()->GetTimeStamp() +
                (int64_t)(frameRecords.size() * VIDEO_FRAME_INTERVAL_MS);
            audioCapturerSession_->GetAudioRecords(frameRecords.front()->GetTimeStamp(),
                endTime, audioRecords);
        }
        for (size_t index = 0; index < frameRecords.size(); index++) {
            OH_AVCodecBufferAttr attr = {0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE};
            OH_AVBuffer *buffer = frameRecords[index]->encodedBuffer;
            OH_AVBuffer_GetBufferAttr(buffer, &attr);
            MEDIA_DEBUG_LOG("DoMuxerVideo frameRecord addr %{public}s videoBuffer addr %{public}p size: %{public}d",
                frameRecords[index]->GetFrameId().c_str(), OH_AVBuffer_GetAddr(buffer), attr.size);
            attr.pts = index * VIDEO_FRAME_INTERVAL;
            OH_AVBuffer_SetBufferAttr(buffer, &attr);
            muxer->WriteSampleBuffer(buffer, VIDEO_TRACK);
        }
        CollectAudioBuffer(audioRecords, muxer);
        FinishMuxer(muxer);
    });
}

void AvcodecTaskManager::CollectAudioBuffer(vector<sptr<AudioRecord>> audioRecordVec, sptr<AudioVideoMuxer> muxer)
{
    MEDIA_INFO_LOG("CollectAudioBuffer start with size %{public}zu",  audioRecordVec.size());
    bool isEncodeSuccess = false;
    if (!audioEncoder_ || audioRecordVec.empty() || !muxer) {
        MEDIA_ERR_LOG("CollectAudioBuffer cannot find useful data");
        return;
    }
    isEncodeSuccess = audioEncoder_->EncodeAudioBuffer(audioRecordVec);
    MEDIA_DEBUG_LOG("encode audio buffer result %{public}d", isEncodeSuccess);
    for (size_t index = 0; index < audioRecordVec.size(); index++) {
        OH_AVCodecBufferAttr attr = {0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE};
        OH_AVBuffer *buffer = audioRecordVec[index]->encodedBuffer;
        OH_AVBuffer_GetBufferAttr(buffer, &attr);
        attr.pts = static_cast<int64_t>(index * AUDIO_FRAME_INTERVAL);
        if (index == audioRecordVec.size() - 1) {
            attr.flags = AVCODEC_BUFFER_FLAGS_EOS;
        }
        OH_AVBuffer_SetBufferAttr(buffer, &attr);
        muxer->WriteSampleBuffer(buffer, AUDIO_TRACK);
    }
    MEDIA_INFO_LOG("CollectAudioBuffer finished");
}

void AvcodecTaskManager::Release()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AvcodecTaskManager release start");
    if (videoEncoder_ != nullptr) {
        videoEncoder_->Release();
    }
    if (audioEncoder_ != nullptr) {
        audioEncoder_->Release();
    }
    unique_lock<mutex> lock(videoFdMutex_);
    while (!videoFdQueue_.empty()) {
        int32_t fd = videoFdQueue_.front().first;
        MEDIA_INFO_LOG("close with videoFd: %{public}d", fd);
        close(fd);
        videoFdQueue_.pop();
    }
    MEDIA_INFO_LOG("AvcodecTaskManager release end");
}

void AvcodecTaskManager::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AvcodecTaskManager Stop start");
    videoEncoderManager_->SubmitTask([this]() {
        if (videoEncoder_ != nullptr) {
            videoEncoder_->Stop();
        }
    });
    audioEncoderManager_->SubmitTask([this]() {
        if (audioEncoder_ != nullptr) {
            audioEncoder_->Stop();
        }
        MEDIA_INFO_LOG("AvcodecTaskManager Stop end");
    });
}
} // CameraStandard
} // OHOS