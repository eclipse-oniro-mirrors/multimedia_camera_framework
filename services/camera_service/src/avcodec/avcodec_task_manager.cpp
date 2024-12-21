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
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <unistd.h>
#include <utility>
#include "datetime_ex.h"
#include "camera_util.h"
#include "datetime_ex.h"
#include "audio_capturer_session.h"
#include "audio_record.h"
#include "audio_video_muxer.h"
#include "camera_log.h"
#include "datetime_ex.h"
#include "external_window.h"
#include "frame_record.h"
#include "native_avbuffer.h"
#include "native_avbuffer_info.h"
#include "native_buffer_inner.h"
#include "sample_info.h"
#include "native_mfmagic.h"

namespace {
using namespace std::string_literals;
using namespace std::chrono_literals;
} // namespace
namespace OHOS {
namespace CameraStandard {

AvcodecTaskManager::~AvcodecTaskManager()
{
    CAMERA_SYNC_TRACE;
    Release();
}

AvcodecTaskManager::AvcodecTaskManager(sptr<AudioCapturerSession> audioCaptureSession,
    VideoCodecType type) : videoCodecType_(type)
{
    CAMERA_SYNC_TRACE;
    #ifdef MOVING_PHOTO_ADD_AUDIO
    audioCapturerSession_ = audioCaptureSession;
    audioEncoder_ = make_unique<AudioEncoder>();
    #endif
    // Create Task Manager
    videoEncoder_ = make_unique<VideoEncoder>(type);
}

shared_ptr<TaskManager>& AvcodecTaskManager::GetTaskManager()
{
    lock_guard<mutex> lock(taskManagerMutex_);
    if (taskManager_ == nullptr && isActive_.load()) {
        taskManager_ = make_unique<TaskManager>("AvcodecTaskManager", DEFAULT_THREAD_NUMBER, false);
    }
    return taskManager_;
}

shared_ptr<TaskManager>& AvcodecTaskManager::GetEncoderManager()
{
    lock_guard<mutex> lock(encoderManagerMutex_);
    if (videoEncoderManager_ == nullptr && isActive_.load()) {
        videoEncoderManager_ = make_unique<TaskManager>("VideoTaskManager", DEFAULT_ENCODER_THREAD_NUMBER, true);
    }
    return videoEncoderManager_;
}

void AvcodecTaskManager::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    auto encodeManager = GetEncoderManager();
    if (!encodeManager) {
        return;
    }
    encodeManager->SubmitTask([thisPtr, frameRecord, cacheCallback]() {
        CAMERA_SYNC_TRACE;
        bool isEncodeSuccess = false;
        if (!thisPtr->videoEncoder_ && !frameRecord) {
            return;
        }
        isEncodeSuccess = thisPtr->videoEncoder_->EncodeSurfaceBuffer(frameRecord);
        if (isEncodeSuccess) {
            thisPtr->videoEncoder_->ReleaseSurfaceBuffer(frameRecord);
        }
        frameRecord->SetEncodedResult(isEncodeSuccess);
        frameRecord->SetFinishStatus();
        if (isEncodeSuccess) {
            MEDIA_INFO_LOG("encode image success %{public}s, refCount: %{public}d", frameRecord->GetFrameId().c_str(),
                frameRecord->GetSptrRefCount());
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
    auto taskManager = GetTaskManager();
    if (taskManager) {
        taskManager->SubmitTask(task);
    }
}

void AvcodecTaskManager::SetVideoFd(int64_t timestamp, PhotoAssetIntf* photoAssetProxy, int32_t captureId)
{
    lock_guard<mutex> lock(videoFdMutex_);
    MEDIA_INFO_LOG("Set timestamp: %{public}" PRIu64 ", captureId: %{public}d", timestamp, captureId);
    videoFdMap_.insert(std::make_pair(captureId, std::make_pair(timestamp, photoAssetProxy)));
    MEDIA_DEBUG_LOG("video map size:%{public}zu", videoFdMap_.size());
    cvEmpty_.notify_all();
}

sptr<AudioVideoMuxer> AvcodecTaskManager::CreateAVMuxer(vector<sptr<FrameRecord>> frameRecords, int32_t captureRotation,
    vector<sptr<FrameRecord>> &choosedBuffer, int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    unique_lock<mutex> lock(videoFdMutex_);
<<<<<<< HEAD
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    if (videoFdQueue_.empty()) {
=======
    if (videoFdMap_.empty()) {
>>>>>>> 745a848d (fix diff)
        bool waitResult = false;
        waitResult = cvEmpty_.wait_for(lock, std::chrono::milliseconds(GET_FD_EXPIREATION_TIME),
            [thisPtr] { return !thisPtr->videoFdMap_.empty(); });
        CHECK_ERROR_RETURN_RET(!waitResult || videoFdMap_.empty(), nullptr);
    }
    sptr<AudioVideoMuxer> muxer = new AudioVideoMuxer();
    OH_AVOutputFormat format = AV_OUTPUT_FORMAT_MPEG_4;
    int64_t timestamp = videoFdMap_[captureId].first;
    auto photoAssetProxy = videoFdMap_[captureId].second;
    videoFdMap_.erase(captureId);
    ChooseVideoBuffer(frameRecords, choosedBuffer, timestamp, captureId);
    muxer->Create(format, photoAssetProxy);
    muxer->SetRotation(captureRotation);
    if (!choosedBuffer.empty()) {
        muxer->SetCoverTime(NanosecToMillisec(timestamp - choosedBuffer.front()->GetTimeStamp()));
    }
    auto formatVideo = make_shared<Format>();
    MEDIA_INFO_LOG("CreateAVMuxer videoCodecType_ = %{public}d", videoCodecType_);
    formatVideo->PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, videoCodecType_
        == VIDEO_ENCODE_TYPE_HEVC ? OH_AVCODEC_MIMETYPE_VIDEO_HEVC : OH_AVCODEC_MIMETYPE_VIDEO_AVC);
    formatVideo->PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, frameRecords[0]->GetFrameSize()->width);
    formatVideo->PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, frameRecords[0]->GetFrameSize()->height);
    formatVideo->PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, VIDEO_FRAME_RATE);
    int videoTrackId = -1;
    muxer->AddTrack(videoTrackId, formatVideo, VIDEO_TRACK);
    int audioTrackId = -1;
    #ifdef MOVING_PHOTO_ADD_AUDIO
    auto formatAudio = make_shared<Format>();
    formatAudio->PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, OH_AVCODEC_MIMETYPE_AUDIO_AAC);
    formatAudio->PutIntValue(MediaDescriptionKey::MD_KEY_SAMPLE_RATE, SAMPLERATE_32000);
    formatAudio->PutIntValue(MediaDescriptionKey::MD_KEY_CHANNEL_COUNT, DEFAULT_CHANNEL_COUNT);
    muxer->AddTrack(audioTrackId, formatAudio, AUDIO_TRACK);
    #endif
    int metaTrackId = -1;
    auto formatMeta = make_shared<Format>();
    formatMeta->PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, TIMED_METADATA_TRACK_MIMETYPE);
    formatMeta->PutStringValue(MediaDescriptionKey::MD_KEY_TIMED_METADATA_KEY, TIMED_METADATA_KEY);
    formatMeta->PutIntValue(MediaDescriptionKey::MD_KEY_TIMED_METADATA_SRC_TRACK_ID, videoTrackId);
    muxer->AddTrack(metaTrackId, formatMeta, META_TRACK);
    MEDIA_INFO_LOG("CreateMuxer vId:%{public}d,aid:%{public}d,mid:%{public}d", videoTrackId, audioTrackId, metaTrackId);
    muxer->SetTimedMetadata();
    muxer->Start();
    return muxer;
}

void AvcodecTaskManager::FinishMuxer(sptr<AudioVideoMuxer> muxer)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("doMxuer video is finished");
    if (muxer) {
        muxer->Stop();
        muxer->Release();
        PhotoAssetIntf* proxy = muxer->GetPhotoAssetProxy();
        MEDIA_INFO_LOG("PhotoAssetProxy notify enter");
        if (proxy) {
            proxy->NotifyVideoSaveFinished();
            delete proxy;
        }
    }
}

void AvcodecTaskManager::DoMuxerVideo(vector<sptr<FrameRecord>> frameRecords, uint64_t taskName,
    int32_t captureRotation, int32_t captureId) __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    CHECK_ERROR_RETURN_LOG(frameRecords.empty(), "DoMuxerVideo error of empty encoded frame");
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    auto taskManager = GetTaskManager();
    CHECK_ERROR_RETURN_LOG(taskManager == nullptr, "GetTaskManager is null");
    GetTaskManager()->SubmitTask([thisPtr, frameRecords, captureRotation, captureId]() {
        CAMERA_SYNC_TRACE;
        MEDIA_INFO_LOG("CreateAVMuxer with %{public}zu", frameRecords.size());
        vector<sptr<FrameRecord>> choosedBuffer;
        sptr<AudioVideoMuxer> muxer = thisPtr->CreateAVMuxer(frameRecords, captureRotation, choosedBuffer, captureId);
        CHECK_ERROR_RETURN_LOG(muxer == nullptr, "CreateAVMuxer failed");
        CHECK_ERROR_RETURN_LOG(choosedBuffer.empty(), "choosed empty buffer!");
        int64_t videoStartTime = choosedBuffer.front()->GetTimeStamp();
        for (size_t index = 0; index < choosedBuffer.size(); index++) {
            MEDIA_DEBUG_LOG("write sample index %{public}zu", index);
            OH_AVBuffer *buffer = choosedBuffer[index]->encodedBuffer;
            {
                std::lock_guard<std::mutex> lock(choosedBuffer[index]->bufferMutex_);
                OH_AVCodecBufferAttr attr = {0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE};
                CHECK_AND_CONTINUE_LOG(buffer != nullptr, "video encodedBuffer is null");
                OH_AVBuffer_GetBufferAttr(buffer, &attr);
                attr.pts = NanosecToMicrosec(choosedBuffer[index]->GetTimeStamp() - videoStartTime);
                MEDIA_DEBUG_LOG("choosed buffer pts:%{public}" PRIu64, attr.pts);
                OH_AVBuffer_SetBufferAttr(buffer, &attr);
                muxer->WriteSampleBuffer(buffer->buffer_, VIDEO_TRACK);
            }
            sptr<SurfaceBuffer> metaSurfaceBuffer = frameRecords[index]->GetMetaBuffer();
            if (metaSurfaceBuffer) {
                shared_ptr<AVBuffer> metaAvBuffer = AVBuffer::CreateAVBuffer(metaSurfaceBuffer);
                metaAvBuffer->pts_ = buffer->buffer_->pts_;
                MEDIA_DEBUG_LOG("metaAvBuffer pts_ %{public}llu, avBufferSize: %{public}d",
                    (long long unsigned)(metaAvBuffer->pts_), metaAvBuffer->memory_->GetSize());
                muxer->WriteSampleBuffer(metaAvBuffer, META_TRACK);
            } else {
                MEDIA_ERR_LOG("metaSurfaceBuffer is nullptr");
            }
            frameRecords[index]->UnLockMetaBuffer();
        }
        #ifdef MOVING_PHOTO_ADD_AUDIO
        // CollectAudioBuffer
        vector<sptr<AudioRecord>> audioRecords;
        vector<sptr<AudioRecord>> processedAudioRecords;
        thisPtr->PrepareAudioBuffer(choosedBuffer, audioRecords, processedAudioRecords);
        thisPtr->CollectAudioBuffer(processedAudioRecords, muxer);
        #endif
        thisPtr->FinishMuxer(muxer);
    });
}

size_t AvcodecTaskManager::FindIdrFrameIndex(vector<sptr<FrameRecord>> frameRecords, int64_t shutterTime,
    int32_t captureId)
{
    bool isDeblurStartTime = false;
    std::unique_lock<mutex> startTimeLock(startTimeMutex_);
    int64_t clearVideoStartTime = shutterTime - preBufferDuration_;
    if (mPStartTimeMap_.count(captureId) && mPStartTimeMap_[captureId] <= shutterTime
        && mPStartTimeMap_[captureId] > clearVideoStartTime) {
        MEDIA_INFO_LOG("set deblur start time is %{public}" PRIu64, mPStartTimeMap_[captureId]);
        clearVideoStartTime = mPStartTimeMap_[captureId];
        isDeblurStartTime = true;
    }
    mPStartTimeMap_.erase(captureId);
    startTimeLock.unlock();
    MEDIA_INFO_LOG("FindIdrFrameIndex captureId : %{public}d, clearVideoStartTime : %{public}" PRIu64,
        captureId, clearVideoStartTime);
    size_t idrIndex = frameRecords.size();
    if (isDeblurStartTime) {
        for (size_t index = 0; index < frameRecords.size(); ++index) {
            auto frame = frameRecords[index];
            if (frame->IsIDRFrame() && frame->GetTimeStamp() <= clearVideoStartTime) {
                MEDIA_INFO_LOG("FindIdrFrameIndex before start time");
                idrIndex = index;
            }
        }
    }
    if (idrIndex == frameRecords.size()) {
        for (size_t index = 0; index < frameRecords.size(); ++index) {
            auto frame = frameRecords[index];
            if (frame->IsIDRFrame() && frame->GetTimeStamp() >= clearVideoStartTime) {
                MEDIA_INFO_LOG("FindIdrFrameIndex after start time");
                idrIndex = index;
                break;
            }
            idrIndex = 0;
        }
    }
    return idrIndex;
}

void AvcodecTaskManager::IgnoreDeblur(vector<sptr<FrameRecord>> frameRecords,
    vector<sptr<FrameRecord>> &choosedBuffer, int64_t shutterTime)
{
    MEDIA_INFO_LOG("IgnoreDeblur enter");
    choosedBuffer.clear();
    if (!frameRecords.empty()) {
        auto it = find_if(frameRecords.begin(), frameRecords.end(),
            [](const sptr<FrameRecord>& frame) { return frame->IsIDRFrame(); });
        while (it != frameRecords.end()) {
            choosedBuffer.emplace_back(*it);
            ++it;
        }
    }
}

void AvcodecTaskManager::ChooseVideoBuffer(vector<sptr<FrameRecord>> frameRecords,
    vector<sptr<FrameRecord>> &choosedBuffer, int64_t shutterTime, int32_t captureId)
{
    choosedBuffer.clear();
    size_t idrIndex = FindIdrFrameIndex(frameRecords, shutterTime, captureId);
    std::unique_lock<mutex> endTimeLock(endTimeMutex_);
    int64_t clearVideoEndTime = shutterTime + postBufferDuration_;
    if (mPEndTimeMap_.count(captureId) && mPEndTimeMap_[captureId] >= shutterTime
        && mPEndTimeMap_[captureId] < clearVideoEndTime) {
        MEDIA_INFO_LOG("set deblur end time is %{public}" PRIu64, mPEndTimeMap_[captureId]);
        clearVideoEndTime = mPEndTimeMap_[captureId];
    }
    mPEndTimeMap_.erase(captureId);
    endTimeLock.unlock();
    MEDIA_INFO_LOG("ChooseVideoBuffer captureId : %{public}d, shutterTime : %{public}" PRIu64 ", "
        "clearVideoEndTime : %{public}" PRIu64, captureId, shutterTime, clearVideoEndTime);
    size_t frameCount = 0;
    for (size_t index = idrIndex; index < frameRecords.size(); ++index) {
        auto frame = frameRecords[index];
        int64_t timestamp = frame->GetTimeStamp();
        if (timestamp <= clearVideoEndTime && frameCount < MAX_FRAME_COUNT) {
            choosedBuffer.push_back(frame);
            ++frameCount;
        }
    }
    if (choosedBuffer.empty() || !frameRecords[idrIndex]->IsIDRFrame()) {
        IgnoreDeblur(frameRecords, choosedBuffer, shutterTime);
    }
    MEDIA_INFO_LOG("ChooseVideoBuffer with size %{public}zu", choosedBuffer.size());
}

void AvcodecTaskManager::PrepareAudioBuffer(vector<sptr<FrameRecord>>& choosedBuffer,
    vector<sptr<AudioRecord>>& audioRecords, vector<sptr<AudioRecord>>& processedAudioRecords)
{
    int64_t videoStartTime = choosedBuffer.front()->GetTimeStamp();
    if (audioCapturerSession_) {
        int64_t startTime = NanosecToMillisec(videoStartTime);
        int64_t endTime = NanosecToMillisec(choosedBuffer.back()->GetTimeStamp());
        audioCapturerSession_->GetAudioRecords(startTime, endTime, audioRecords);
        for (auto ptr: audioRecords) {
            processedAudioRecords.emplace_back(new AudioRecord(ptr->GetTimeStamp()));
        }
        audioCapturerSession_->GetAudioDeferredProcess()->Process(audioRecords, processedAudioRecords);
    }
}

void AvcodecTaskManager::CollectAudioBuffer(vector<sptr<AudioRecord>> audioRecordVec, sptr<AudioVideoMuxer> muxer)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CollectAudioBuffer start with size %{public}zu", audioRecordVec.size());
    bool isEncodeSuccess = false;
    CHECK_ERROR_RETURN_LOG(!audioEncoder_ || audioRecordVec.empty() || !muxer,
        "CollectAudioBuffer cannot find useful data");
    isEncodeSuccess = audioEncoder_->EncodeAudioBuffer(audioRecordVec);
    MEDIA_DEBUG_LOG("encode audio buffer result %{public}d", isEncodeSuccess);
    size_t maxFrameCount = std::min(audioRecordVec.size(), MAX_AUDIO_FRAME_COUNT);
    for (size_t index = 0; index < maxFrameCount; index++) {
        OH_AVCodecBufferAttr attr = { 0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE };
        OH_AVBuffer* buffer = audioRecordVec[index]->encodedBuffer;
        CHECK_AND_CONTINUE_LOG(buffer != nullptr, "audio encodedBuffer is null");
        OH_AVBuffer_GetBufferAttr(buffer, &attr);
        attr.pts = static_cast<int64_t>(index * AUDIO_FRAME_INTERVAL);
        if (audioRecordVec.size() > 0) {
            if (index == audioRecordVec.size() - 1) {
                attr.flags = AVCODEC_BUFFER_FLAGS_EOS;
            }
        }
        OH_AVBuffer_SetBufferAttr(buffer, &attr);
        muxer->WriteSampleBuffer(buffer->buffer_, AUDIO_TRACK);
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
    MEDIA_INFO_LOG("AvcodecTaskManager::Release videoFdMap_ size is %{public}zu", videoFdMap_.size());
    for (auto videoFdPair : videoFdMap_) {
        PhotoAssetIntf* photoAssetProxy = videoFdPair.second.second;
        if (photoAssetProxy) {
            delete photoAssetProxy;
        }
    }
    videoFdMap_.clear();
    MEDIA_INFO_LOG("AvcodecTaskManager release end");
}

void AvcodecTaskManager::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AvcodecTaskManager Stop start");
    if (videoEncoder_ != nullptr) {
        videoEncoder_->Stop();
    }
    if (audioEncoder_ != nullptr) {
        audioEncoder_->Stop();
    }
    MEDIA_INFO_LOG("AvcodecTaskManager Stop end");
}

void AvcodecTaskManager::ClearTaskResource()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AvcodecTaskManager ClearTaskResource start");
    {
        lock_guard<mutex> lock(taskManagerMutex_);
        isActive_ = false;
        if (taskManager_ != nullptr) {
            taskManager_->CancelAllTasks();
            taskManager_.reset();
        }
    }
    {
        lock_guard<mutex> lock(encoderManagerMutex_);
        isActive_ = false;
        if (videoEncoderManager_ != nullptr) {
            videoEncoderManager_->CancelAllTasks();
            videoEncoderManager_.reset();
        }
    }
    {
        lock_guard<mutex> lock(startTimeMutex_);
        mPStartTimeMap_.clear();
    }
    {
        lock_guard<mutex> lock(endTimeMutex_);
        mPEndTimeMap_.clear();
    }
    MEDIA_INFO_LOG("AvcodecTaskManager ClearTaskResource end");
}

void AvcodecTaskManager::SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount)
{
    MEDIA_INFO_LOG("AvcodecTaskManager SetVideoBufferCount enter");
    preBufferDuration_ = static_cast<int64_t>(preBufferCount) * ONE_BILLION / VIDEO_FRAME_RATE;
    postBufferDuration_ = static_cast<int64_t>(postBufferCount) * ONE_BILLION / VIDEO_FRAME_RATE;
}
} // namespace CameraStandard
} // namespace OHOS