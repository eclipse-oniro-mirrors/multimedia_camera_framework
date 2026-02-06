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
#include "audio_capturer_session.h"
#include "audio_record.h"
#include "audio_video_muxer.h"
#include "audio_deferred_process.h"
#include "utils/camera_log.h"
#include "external_window.h"
#include "frame_record.h"
#include "native_avbuffer.h"
#include "native_avbuffer_info.h"
#include "native_buffer_inner.h"
#include "sample_info.h"
#include "native_mfmagic.h"
#include "sync_fence.h"

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
    ClearTaskResource();
}

AvcodecTaskManager::AvcodecTaskManager(
    sptr<AudioCapturerSession> audioCaptureSession, VideoCodecType type, ColorSpace colorSpace) :
    videoCodecType_(type), colorSpace_(colorSpace)
{
    CAMERA_SYNC_TRACE;
    audioCapturerSession_ = audioCaptureSession;
    audioEncoder_ = make_unique<AudioEncoder>();
    // Create Task Manager
    videoEncoder_ = make_shared<VideoEncoder>(type, colorSpace);
}

AvcodecTaskManager::AvcodecTaskManager(wptr<Surface> movingSurface, shared_ptr<Size> size,
    sptr<AudioTaskManager> audioTaskManager, VideoCodecType type, ColorSpace colorSpace)
    :videoCodecType_(type), colorSpace_(colorSpace), movingSurface_(movingSurface), size_(size)
{
    CAMERA_SYNC_TRACE;
    audioTaskManager_ = audioTaskManager;
    audioEncoder_ = make_unique<AudioEncoder>();
    // Create Task Manager
    videoEncoder_ = make_shared<VideoEncoder>(type, colorSpace);
}

void AvcodecTaskManager::AsyncInitVideoCodec()
{
    MEDIA_INFO_LOG("AvcodecTaskManager AsyncInitVideoCodec enter");
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    std::thread([thisPtr]() {
        if (thisPtr->videoEncoder_) {
            thisPtr->videoEncoder_->SetVideoCodec(thisPtr->size_, 0);
        } else {
            MEDIA_ERR_LOG("init videoCodec faild");
        }
    }).detach();
}

shared_ptr<TaskManager>& AvcodecTaskManager::GetTaskManager()
{
    lock_guard<mutex> lock(taskManagerMutex_);
    bool shouldCreateTaskManager = taskManager_ == nullptr && isActive_.load();
    if (shouldCreateTaskManager) {
        taskManager_ = make_unique<TaskManager>("AvcodecTaskManager", DEFAULT_THREAD_NUMBER, false);
    }
    return taskManager_;
}

shared_ptr<TaskManager>& AvcodecTaskManager::GetEncoderManager()
{
    lock_guard<mutex> lock(encoderManagerMutex_);
    bool shouldCreateVideoTaskManager = videoEncoderManager_ == nullptr && isActive_.load();
    if (shouldCreateVideoTaskManager) {
        videoEncoderManager_ = make_unique<TaskManager>("VideoTaskManager", DEFAULT_ENCODER_THREAD_NUMBER, false);
    }
    return videoEncoderManager_;
}

void AvcodecTaskManager::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    // LCOV_EXCL_START
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    auto encodeManager = GetEncoderManager();
    CHECK_RETURN(!encodeManager);
    videoEncoder_->TsVecInsert(frameRecord->GetTimeStamp());
    encodeManager->SubmitTask([thisPtr, frameRecord, cacheCallback]() {
        CAMERA_SYNC_TRACE;
        CHECK_RETURN(thisPtr == nullptr);
        CHECK_RETURN(!thisPtr->videoEncoder_ || !frameRecord);
        {
            std::lock_guard<std::mutex> encodeLock(thisPtr->startAvcodecMutex_);
            if (thisPtr->videoEncoder_->CheckIfRestartNeeded()) {
                thisPtr->videoEncoder_->RestartVideoCodec(frameRecord->GetFrameSize(), frameRecord->GetRotation());
            }
        }
        sptr<Surface> movingSurface = thisPtr->movingSurface_.promote();
        if (movingSurface) {
            sptr<SurfaceBuffer> codecDetachBuf;
            thisPtr->videoEncoder_->DetachCodecBuffer(codecDetachBuf, frameRecord);
            SurfaceError surfaceRet = movingSurface->AttachBufferToQueue(codecDetachBuf);
            CHECK_EXECUTE(surfaceRet != SURFACE_ERROR_OK,
                MEDIA_ERR_LOG("movingSurface AttachBuffer, surfaceRet = %{public}d, timestamp:%{public}llu", surfaceRet,
                    (long long unsigned)frameRecord->GetTimeStamp()));
            surfaceRet = movingSurface->ReleaseBuffer(codecDetachBuf, SyncFence::INVALID_FENCE);
            CHECK_EXECUTE(surfaceRet != SURFACE_ERROR_OK,
                MEDIA_ERR_LOG("movingSurface ReleaseBuffer, surfaceRet = %{public}d", surfaceRet));
        }
        bool isEncodeSuccess = thisPtr->videoEncoder_->EncodeSurfaceBuffer(frameRecord);
        CHECK_PRINT_ELOG(!isEncodeSuccess, "EncodeVideoBuffer faild");
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
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::SubmitTask(function<void()> task)
{
    auto taskManager = GetTaskManager();
    CHECK_RETURN(!taskManager);
    taskManager->SubmitTask(task);
}

void AvcodecTaskManager::SetVideoFd(int64_t timestamp, shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId)
{
    lock_guard<mutex> lock(videoFdMutex_);
    MEDIA_INFO_LOG("Set timestamp: %{public}" PRIu64 ", captureId: %{public}d", timestamp, captureId);
    videoFdMap_.insert(std::make_pair(captureId, std::make_pair(timestamp, photoAssetProxy)));
    MEDIA_INFO_LOG("video map size:%{public}zu", videoFdMap_.size());
    cvEmpty_.notify_all();
}

void AvcodecTaskManager::SetDeferredVideoEnhanceFlag(int32_t captureId, uint32_t deferredVideoEnhanceFlag)
{
    // LCOV_EXCL_START
    lock_guard<mutex> lock(deferredVideoEnhanceMutex_);
    CHECK_RETURN(mDeferredVideoEnhanceMap_.count(captureId) != 0);
    MEDIA_INFO_LOG("Deferred Video Enhance Flag is %{public}u", deferredVideoEnhanceFlag);
    mDeferredVideoEnhanceMap_.insert(make_pair(captureId, deferredVideoEnhanceFlag));
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::SetVideoId(int32_t captureId, std::string videoId)
{
    // LCOV_EXCL_START
    std::lock_guard<mutex> lock(videoIdMutex_);
    CHECK_RETURN(mVideoIdMap_.count(captureId) != 0);
    MEDIA_INFO_LOG("The Video ID is %{public}s", videoId.c_str());
    mVideoIdMap_.insert(make_pair(captureId, videoId));
    // LCOV_EXCL_STOP
}

uint32_t AvcodecTaskManager::GetDeferredVideoEnhanceFlag(int32_t captureId)
{
    // LCOV_EXCL_START
    lock_guard<mutex> lock(deferredVideoEnhanceMutex_);
    MEDIA_DEBUG_LOG("AvcodecTaskManager::GetDeferredVideoEnhanceFlag captureId is %{public}d ", captureId);
    CHECK_RETURN_RET_DLOG(mDeferredVideoEnhanceMap_.count(captureId), mDeferredVideoEnhanceMap_[captureId],
        "set deferred video enhance flag is %{public}u", mDeferredVideoEnhanceMap_[captureId]);
    MEDIA_DEBUG_LOG("don't get DeferredVideoEnhanceFlag");
    return 0;
    // LCOV_EXCL_STOP
}

std::string AvcodecTaskManager::GetVideoId(int32_t captureId)
{
    // LCOV_EXCL_START
    lock_guard<mutex> lock(videoIdMutex_);
    MEDIA_DEBUG_LOG("AvcodecTaskManager::GetVideoId captureId is %{public}d ", captureId);
    CHECK_RETURN_RET_DLOG(mVideoIdMap_.count(captureId) && mVideoIdMap_[captureId].size() != 0, mVideoIdMap_[captureId],
        "set video ID is %{public}s", mVideoIdMap_[captureId].c_str());
    MEDIA_DEBUG_LOG("don't get VideoId");
    return "";
    // LCOV_EXCL_STOP
}

constexpr inline float MovingPhotoNanosecToMillisec(int64_t nanosec)
{
    // LCOV_EXCL_START
    return static_cast<float>(nanosec) / 1000000.0f;
    // LCOV_EXCL_STOP
}

sptr<AudioVideoMuxer> AvcodecTaskManager::CreateAVMuxer(vector<sptr<FrameRecord>> frameRecords, int32_t captureRotation,
    vector<sptr<FrameRecord>>& choosedBuffer, int32_t captureId, int64_t& backTimestamp)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    unique_lock<mutex> lock(videoFdMutex_);
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    if (videoFdMap_.find(captureId) == videoFdMap_.end()) {
        bool waitResult = false;
        waitResult = cvEmpty_.wait_for(lock, std::chrono::milliseconds(GET_FD_EXPIREATION_TIME),
            [thisPtr, captureId] { return thisPtr->videoFdMap_.find(captureId) != thisPtr->videoFdMap_.end(); });
        CHECK_RETURN_RET(!waitResult || videoFdMap_.find(captureId) == videoFdMap_.end(), nullptr);
    }
    sptr<AudioVideoMuxer> muxer = new AudioVideoMuxer();
    OH_AVOutputFormat format = AV_OUTPUT_FORMAT_MPEG_4;
    int64_t timestamp = videoFdMap_[captureId].first;
    auto photoAssetProxy = videoFdMap_[captureId].second;
    ChooseVideoBuffer(frameRecords, choosedBuffer, timestamp, captureId, backTimestamp);
    muxer->Create(format, photoAssetProxy, videoTypeMap_[captureId]);
    muxer->SetRotation(captureRotation);
    if (!choosedBuffer.empty()) {
        CHECK_RETURN_RET_ELOG(choosedBuffer.front() == nullptr, nullptr, "choosedBuffer.front() is null");
        muxer->SetCoverTime(MovingPhotoNanosecToMillisec(
            std::min(timestamp, backTimestamp) - choosedBuffer.front()->GetTimeStamp()));
        muxer->SetStartTime(MovingPhotoNanosecToMillisec(choosedBuffer.front()->GetTimeStamp()));
        muxer->SetDeferredVideoEnhanceFlag(GetDeferredVideoEnhanceFlag(captureId));
        muxer->SetVideoId(GetVideoId(captureId));
        CHECK_EXECUTE(videoEncoder_ != nullptr,
            muxer->SetSqr(videoEncoder_->GetEncoderBitrate(), videoEncoder_->GetBframeAbility()));
    }
    auto formatVideo = make_shared<Format>();
    MEDIA_INFO_LOG("CreateAVMuxer videoCodecType_ = %{public}d", videoCodecType_);
    formatVideo->PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, videoCodecType_
        == VideoCodecType::VIDEO_ENCODE_TYPE_HEVC ? OH_AVCODEC_MIMETYPE_VIDEO_HEVC : OH_AVCODEC_MIMETYPE_VIDEO_AVC);
    CHECK_RETURN_RET_ELOG(videoEncoder_ == nullptr, nullptr, "videoEncoder_ is null");
    bool isHevcAndHdrSupported =
        videoCodecType_ == VideoCodecType::VIDEO_ENCODE_TYPE_HEVC && videoEncoder_->IsHdr(colorSpace_);
    if (isHevcAndHdrSupported) {
        formatVideo->PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_IS_HDR_VIVID, IS_HDR_VIVID);
    }
    CHECK_RETURN_RET_ELOG(frameRecords[0] == nullptr || frameRecords[0]->GetFrameSize() == nullptr, nullptr,
        "AvcodecTaskManager::CreateAVMuxer GetFrameSize is null");
    formatVideo->PutIntValue(MediaDescriptionKey::MD_KEY_WIDTH, frameRecords[0]->GetFrameSize()->width);
    formatVideo->PutIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, frameRecords[0]->GetFrameSize()->height);
    formatVideo->PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, VIDEO_FRAME_RATE);
    int videoTrackId = -1;
    muxer->AddTrack(videoTrackId, formatVideo, VIDEO_TRACK);
    int audioTrackId = -1;
    auto formatAudio = make_shared<Format>();
    formatAudio->PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, OH_AVCODEC_MIMETYPE_AUDIO_AAC);
    formatAudio->PutIntValue(MediaDescriptionKey::MD_KEY_SAMPLE_RATE, SAMPLERATE_32000);
    formatAudio->PutIntValue(MediaDescriptionKey::MD_KEY_CHANNEL_COUNT, DEFAULT_CHANNEL_COUNT);
    formatAudio->PutIntValue(MediaDescriptionKey::MD_KEY_PROFILE, DEFAULT_PROFILE);
    muxer->AddTrack(audioTrackId, formatAudio, AUDIO_TRACK);
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
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::FinishMuxer(sptr<AudioVideoMuxer> muxer, int32_t captureId)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("doMxuer video is finished");
    CHECK_RETURN(!muxer);
    muxer->Stop();
    muxer->Release();
    std::shared_ptr<PhotoAssetIntf> proxy = muxer->GetPhotoAssetProxy();
    MEDIA_INFO_LOG("PhotoAssetProxy notify enter videotype:%{public}d", static_cast<int32_t>(videoTypeMap_[captureId]));
    CHECK_RETURN(!proxy);
    proxy->NotifyVideoSaveFinished(videoTypeMap_[captureId]);
    {
        lock_guard<mutex> lock(videoFdMutex_);
        videoFdMap_.erase(captureId);
    }
    if (audioTaskManager_) {
        int32_t retCode = audioTaskManager_->ClearProcessedAudioCache(captureId);
        CHECK_PRINT_ELOG(retCode != CAMERA_OK, "ClearProcessedAudioCache failed");
        audioTaskManager_->RemovePreviousCaptureForTimeMap(captureId);
    }
    MEDIA_INFO_LOG("finishMuxer end, videoFdMap_ size is %{public}zu", videoFdMap_.size());
    // LCOV_EXCL_STOP
}

bool AvcodecTaskManager::isEmptyVideoFdMap()
{
    // LCOV_EXCL_START
    lock_guard<mutex> lock(videoFdMutex_);
    return videoFdMap_.empty();
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::DoMuxerVideo(vector<sptr<FrameRecord>> frameRecords, uint64_t taskName,
    int32_t captureRotation, int32_t captureId) __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(frameRecords.empty(), "DoMuxerVideo error of empty encoded frame");
    // LCOV_EXCL_START
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    auto taskManager = GetTaskManager();
    CHECK_RETURN_ELOG(taskManager == nullptr, "GetTaskManager is null");
    GetTaskManager()->SubmitTask([thisPtr, frameRecords, captureRotation, captureId]() {
        CAMERA_SYNC_TRACE;
        MEDIA_INFO_LOG("CreateAVMuxer with %{public}zu, captureId: %{public}d", frameRecords.size(), captureId);
        vector<sptr<FrameRecord>> choosedBuffer;
        int64_t backTimestamp;
        sptr<AudioVideoMuxer> muxer =
            thisPtr->CreateAVMuxer(frameRecords, captureRotation, choosedBuffer, captureId, backTimestamp);
        CHECK_RETURN_ELOG(muxer == nullptr, "CreateAVMuxer failed");
        if (choosedBuffer.empty()) {
            lock_guard<mutex> lock(thisPtr->videoFdMutex_);
            thisPtr->videoFdMap_.erase(captureId);
            MEDIA_ERR_LOG("choosed empty buffer, videoFdMap_ size is %{public}zu", thisPtr->videoFdMap_.size());
            return;
        }
        CHECK_RETURN_ELOG(thisPtr->videoEncoder_->GetXpsBuffer() == nullptr, "Xps is nullptr!");
        auto result = muxer->WriteSampleBuffer(thisPtr->videoEncoder_->GetXpsBuffer(), VIDEO_TRACK);
        MEDIA_DEBUG_LOG("VIDEO_TRACK write sample result %{public}d", result);
        int64_t videoStartTime = choosedBuffer.front()->GetTimeStamp();
        map<int64_t, int32_t> retMap;
        for (size_t index = 0; index < choosedBuffer.size(); index++) {
            MEDIA_DEBUG_LOG("VIDEO_TRACK write sample index %{public}zu", index);
            shared_ptr<Media::AVBuffer> buffer = choosedBuffer[index]->encodedBuffer;
            {
                int32_t ret = AV_ERR_OK;
                std::lock_guard<std::mutex> lock(choosedBuffer[index]->bufferMutex_);
                CHECK_CONTINUE_WLOG(buffer == nullptr, "video encodedBuffer is null");
                buffer->pts_ = NanosecToMicrosec(choosedBuffer[index]->GetTimeStamp() - videoStartTime);
                MEDIA_DEBUG_LOG("choosed buffer timestamp:%{public}" PRIu64 ", pts:%{public}" PRIi64,
                    choosedBuffer[index]->GetTimeStamp(), choosedBuffer[index]->encodedBuffer->pts_);
                ret = muxer->WriteSampleBuffer(buffer, VIDEO_TRACK);
                retMap[choosedBuffer[index]->GetTimeStamp()] = ret;
            }
        }
        std::sort(choosedBuffer.begin(), choosedBuffer.end(),
            [](sptr<FrameRecord> a, sptr<FrameRecord> b) { return a->GetTimeStamp() < b->GetTimeStamp(); });
        for (size_t index = 0; index < choosedBuffer.size(); index++) {
            MEDIA_DEBUG_LOG("META_TRACK write sample index %{public}zu", index);
            sptr<SurfaceBuffer> metaSurfaceBuffer = choosedBuffer[index]->GetMetaBuffer();
            auto ptr = retMap.find(choosedBuffer[index]->GetTimeStamp());
            if (metaSurfaceBuffer && ptr != retMap.end() && ptr->second == AV_ERR_OK) {
                shared_ptr<AVBuffer> metaAvBuffer = AVBuffer::CreateAVBuffer(metaSurfaceBuffer);
                metaAvBuffer->pts_ = NanosecToMicrosec(choosedBuffer[index]->GetTimeStamp() - videoStartTime);
                MEDIA_DEBUG_LOG("metaAvBuffer pts_ %{public}llu, avBufferSize: %{public}d",
                    (long long unsigned)(metaAvBuffer->pts_), metaAvBuffer->memory_->GetSize());
                muxer->WriteSampleBuffer(metaAvBuffer, META_TRACK);
            } else {
                CHECK_EXECUTE(ptr != retMap.end(), MEDIA_ERR_LOG("metaSurfaceBuffer ret %{public}d", ptr->second));
            }
            choosedBuffer[index]->UnLockMetaBuffer();
        }
        thisPtr->CollectAudioBuffer(choosedBuffer, muxer, true);
        thisPtr->FinishMuxer(muxer, captureId);
    });
    // LCOV_EXCL_STOP
}

size_t AvcodecTaskManager::FindIdrFrameIndex(vector<sptr<FrameRecord>> frameRecords,
    int64_t clearVideoEndTime, int64_t shutterTime, int32_t captureId)
{
    // LCOV_EXCL_START
    bool isDeblurStartTime = false;
    std::unique_lock<mutex> startTimeLock(startTimeMutex_);
    int64_t clearVideoStartTime = shutterTime - preBufferDuration_;
    bool isConditionsMet = mPStartTimeMap_.count(captureId) && mPStartTimeMap_[captureId] <= shutterTime
        && mPStartTimeMap_[captureId] > clearVideoStartTime;
    CHECK_EXECUTE(isConditionsMet, {
        MEDIA_INFO_LOG("set deblur start time is %{public}" PRIu64, mPStartTimeMap_[captureId]);
        clearVideoStartTime = mPStartTimeMap_[captureId];
        MEDIA_INFO_LOG("clearVideoEndTime is %{public}" PRIu64, NanosecToMicrosec(clearVideoEndTime));
        int64_t absoluteValue = abs(clearVideoEndTime - clearVideoStartTime);
        int64_t deblurThreshold = 264000000L;
        isDeblurStartTime = absoluteValue < deblurThreshold;
    });
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
            bool isIdrAndBetweenClearAndShutterTime = frame->IsIDRFrame() &&
                frame->GetTimeStamp() >= clearVideoStartTime && frame->GetTimeStamp() < shutterTime;
            if (isIdrAndBetweenClearAndShutterTime) {
                MEDIA_INFO_LOG("FindIdrFrameIndex after start time");
                idrIndex = index;
                break;
            }
            idrIndex = 0;
        }
    }
    return idrIndex;
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::IgnoreDeblur(vector<sptr<FrameRecord>> frameRecords,
    vector<sptr<FrameRecord>> &choosedBuffer, int64_t shutterTime)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("IgnoreDeblur enter");
    choosedBuffer.clear();
    CHECK_RETURN(frameRecords.empty());
    auto it = find_if(
        frameRecords.begin(), frameRecords.end(), [](const sptr<FrameRecord>& frame) { return frame->IsIDRFrame(); });
    int64_t firstIdrTimeStamp = 0;
    if (it != frameRecords.end() && *it != nullptr) {
        firstIdrTimeStamp = (*it)->GetTimeStamp();
    }
    size_t frameCount = 0;
    for (; it != frameRecords.end(); ++it) {
        CHECK_CONTINUE_ELOG(*it == nullptr, "current framerecord is nullptr");
        int64_t timeStamp = (*it)->GetTimeStamp();
        bool isIgnoreDeblurFrame = frameCount < MAX_FRAME_COUNT && (timeStamp - firstIdrTimeStamp < MAX_NANOSEC_RANGE);
        CHECK_EXECUTE(isIgnoreDeblurFrame, {
          choosedBuffer.emplace_back(*it);
          ++frameCount;
        });
    }
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::ChooseVideoBuffer(vector<sptr<FrameRecord>> frameRecords,
    vector<sptr<FrameRecord>> &choosedBuffer, int64_t shutterTime, int32_t captureId, int64_t& backTimestamp)
{
    CHECK_RETURN_ELOG(frameRecords.empty(), "frameRecords is empty!");
    // LCOV_EXCL_START
    choosedBuffer.clear();
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
    size_t idrIndex = FindIdrFrameIndex(frameRecords, clearVideoEndTime, shutterTime, captureId);
    size_t frameCount = 0;
    int64_t idrIndexTimeStamp = frameRecords[idrIndex]->GetTimeStamp();
    MEDIA_INFO_LOG("ChooseVideoBuffer::after choose idrIndex:%{public}zu, timestamp:%{public}" PRIu64, idrIndex,
        idrIndexTimeStamp);
    for (size_t index = idrIndex; index < frameRecords.size(); ++index) {
        auto frame = frameRecords[index];
        int64_t timestamp = frame->GetTimeStamp();
        bool isBeforeEndTimeAndUnderMaxFrameCount = timestamp <= clearVideoEndTime && frameCount < MAX_FRAME_COUNT
            && (timestamp - idrIndexTimeStamp < MAX_NANOSEC_RANGE);
        CHECK_EXECUTE(isBeforeEndTimeAndUnderMaxFrameCount, {
            choosedBuffer.push_back(frame);
            ++frameCount;
        });
    }
    if (choosedBuffer.size() < MIN_FRAME_RECORD_BUFFER_SIZE || !frameRecords[idrIndex]->IsIDRFrame()) {
        IgnoreDeblur(frameRecords, choosedBuffer, shutterTime);
    }
    auto size = CalComplete(choosedBuffer.size());
    MEDIA_INFO_LOG("CalComplete: %{public}d", size);
    bool Bability = false;
    CHECK_EXECUTE(videoEncoder_ != nullptr, Bability = videoEncoder_->GetBframeAbility());
    CHECK_EXECUTE(size > 0 && Bability, choosedBuffer.erase(choosedBuffer.end() - size, choosedBuffer.end()));
    CHECK_RETURN_ELOG(choosedBuffer.empty(), "ChooseVideoBuffer is empty");
    backTimestamp = choosedBuffer.back()->GetTimeStamp();
    MEDIA_INFO_LOG("ChooseVideoBuffer with size %{public}zu, frontBuffer timeStamp: %{public}" PRIu64 ", "
                   "backBuffer timeStamp: %{public}" PRIu64,
        choosedBuffer.size(), choosedBuffer.front()->GetTimeStamp(), backTimestamp);
    std::sort(choosedBuffer.begin(), choosedBuffer.end(),
        [](sptr<FrameRecord> a, sptr<FrameRecord> b) { return a->muxerIndex_ < b->muxerIndex_; });
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::WaitForAudioRecordFinished(vector<sptr<FrameRecord>>& choosedBuffer)
{
    // LCOV_EXCL_START
    CHECK_RETURN_ELOG(choosedBuffer.empty(), "WaitForAudioRecordFinished choosedBuffer is empty");
    MEDIA_DEBUG_LOG("AvcodecTaskManager::WaitForAudioRecordFinished enter");
    int64_t endChooseBufferTime = NanosecToMillisec(choosedBuffer.back()->GetTimeStamp());
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    for (size_t count = 0; count < WAIT_AUDIO_PROCESS; count++) {
        std::unique_lock<std::mutex> lock(audioProcessMutex_);
        audioProcessFinish_.wait_for(lock, std::chrono::milliseconds(WAIT_AUDIO_PROCESSED_EXPIREATION_TIME),
            [thisPtr, endChooseBufferTime] {
                int64_t endCacheTime = 0;
                bool isExecuted = thisPtr && thisPtr->audioTaskManager_;
                if (isExecuted) {
                    std::lock_guard<std::mutex> lock(thisPtr->audioTaskManager_->audioCacheMutex_);
                    auto &audioCache = thisPtr->audioTaskManager_->GetProcessedAudioRecordCache();
                    CHECK_EXECUTE(!audioCache.empty() && audioCache.back(),
                        endCacheTime = audioCache.back()->GetTimeStamp());
                }
                return endCacheTime >= endChooseBufferTime;
        });
    }
    MEDIA_DEBUG_LOG("AvcodecTaskManager::WaitForAudioRecordFinished end");
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::CollectAudioBuffer(vector<sptr<FrameRecord>>& choosedBuffer,
    sptr<AudioVideoMuxer> muxer, bool isNeedEncode)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(choosedBuffer.empty(), "CollectAudioBuffer choosedBuffer is empty");
    WaitForAudioRecordFinished(choosedBuffer);
    CHECK_RETURN_ELOG(!audioTaskManager_, "audioTaskManager_ is nullptr");
    std::lock_guard<std::mutex> lock(audioTaskManager_->audioCacheMutex_);
    vector<sptr<AudioRecord>> &audioRecordVec = audioTaskManager_->GetProcessedAudioRecordCache();
    CHECK_RETURN_ELOG(audioRecordVec.empty(),
        "AvcodecTaskManager::CollectAudioBuffer audioRecordVec is empty");
    MEDIA_INFO_LOG("CollectAudioBuffer start with size %{public}zu", audioRecordVec.size());
    int64_t videoStartTime = NanosecToMillisec(choosedBuffer.front()->GetTimeStamp());
    int64_t videoEndTime = NanosecToMillisec(choosedBuffer.back()->GetTimeStamp());
    vector<sptr<AudioRecord>> processedAudioRecords;
    vector<sptr<AudioRecord>> encodeAudioRecords;
    for (auto audioRecord : audioRecordVec) {
        if (audioRecord->GetTimeStamp() >= videoStartTime && audioRecord->GetTimeStamp() < videoEndTime) {
            processedAudioRecords.emplace_back(audioRecord);
            encodeAudioRecords.emplace_back(new AudioRecord(audioRecord->GetTimeStamp()));
        }
    }
    CHECK_EXECUTE(audioTaskManager_ && !processedAudioRecords.empty() && !encodeAudioRecords.empty(),
        audioTaskManager_->ProcessAudioBufferToMuted(processedAudioRecords, encodeAudioRecords));
    bool isEncodeSuccess = false;
    CHECK_RETURN_ELOG(!audioEncoder_ || encodeAudioRecords.empty() || !muxer,
        "CollectAudioBuffer cannot find useful data");
    // LCOV_EXCL_START
    if (isNeedEncode) {
        isEncodeSuccess = audioEncoder_->EncodeAudioBuffer(encodeAudioRecords);
        MEDIA_DEBUG_LOG("encode audio buffer result %{public}d", isEncodeSuccess);
    }
    size_t maxFrameCount = std::min(encodeAudioRecords.size(), MAX_AUDIO_FRAME_COUNT);
    for (size_t index = 0; index < maxFrameCount; index++) {
        OH_AVCodecBufferAttr attr = { 0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE };
        OH_AVBuffer* buffer = encodeAudioRecords[index]->encodedBuffer;
        CHECK_CONTINUE_WLOG(buffer == nullptr, "audio encodedBuffer is null");
        OH_AVBuffer_GetBufferAttr(buffer, &attr);
        attr.pts = static_cast<int64_t>(index * AUDIO_FRAME_INTERVAL);
        if (encodeAudioRecords.size() > 0) {
            if (index == encodeAudioRecords.size() - 1) {
                attr.flags = AVCODEC_BUFFER_FLAGS_EOS;
            }
        }
        OH_AVBuffer_SetBufferAttr(buffer, &attr);
        muxer->WriteSampleBuffer(buffer->buffer_, AUDIO_TRACK);
    }
    MEDIA_INFO_LOG("CollectAudioBuffer finished");
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::Release()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AvcodecTaskManager release start");
    CHECK_EXECUTE(videoEncoder_ != nullptr, videoEncoder_->Release());
    videoEncoder_ = nullptr;
    CHECK_EXECUTE(audioEncoder_ != nullptr, audioEncoder_->Release());
    audioEncoder_ = nullptr;
    unique_lock<mutex> lock(videoFdMutex_);
    MEDIA_INFO_LOG("AvcodecTaskManager::Release videoFdMap_ size is %{public}zu", videoFdMap_.size());
    for (auto videoFdPair : videoFdMap_) {
        shared_ptr<PhotoAssetIntf> photoAssetProxy = videoFdPair.second.second;
        if (photoAssetProxy) {
            // LCOV_EXCL_START
            photoAssetProxy.reset();
            // LCOV_EXCL_STOP
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
        // LCOV_EXCL_START
        videoEncoder_->Stop();
        // LCOV_EXCL_STOP
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
    {
        lock_guard<mutex> lock(deferredVideoEnhanceMutex_);
        mDeferredVideoEnhanceMap_.clear();
    }
    {
        lock_guard<mutex> lock(videoIdMutex_);
        mVideoIdMap_.clear();
    }
    MEDIA_INFO_LOG("AvcodecTaskManager ClearTaskResource end");
}

void AvcodecTaskManager::SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("AvcodecTaskManager SetVideoBufferCount enter");
    preBufferDuration_ = static_cast<int64_t>(preBufferCount) * ONE_BILLION / VIDEO_FRAME_RATE;
    postBufferDuration_ = static_cast<int64_t>(postBufferCount) * ONE_BILLION / VIDEO_FRAME_RATE;
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::RecordVideoType(int32_t captureId, VideoType type)
{
    lock_guard<mutex> lock(videoTypeMutex_);
    videoTypeMap_[captureId] = type;
}

AudioDeferredProcessSingle::~AudioDeferredProcessSingle()
{
    MEDIA_INFO_LOG("AudioDeferredProcessSingle destructor");
    std::lock_guard<mutex> lock(deferredProcessMutex_);
    audioDeferredProcessPtr_ = nullptr;
}

void AudioDeferredProcessSingle::DestroyAudioDeferredProcess()
{
    std::lock_guard<mutex> lock(deferredProcessMutex_);
    audioDeferredProcessPtr_ = nullptr;
}

void AudioDeferredProcessSingle::TimerDestroyAudioDeferredProcess()
{
    std::unique_lock<mutex> lock(deferredProcessMutex_, std::try_to_lock);
    CHECK_RETURN(!lock.owns_lock());
    audioDeferredProcessPtr_ = nullptr;
}

AudioDeferredProcessSingle::AudioDeferredProcessSingle()
{
    MEDIA_INFO_LOG("AudioDeferredProcessSingle constructor");
}

AudioDeferredProcessSingle& AudioDeferredProcessSingle::GetInstance()
{
    static AudioDeferredProcessSingle audioDeferredProcessSingle;
    return audioDeferredProcessSingle;
}

void AudioDeferredProcessSingle::ConfigAndProcess(sptr<AudioCapturerSession> audioCapturerSession,
    vector<sptr<AudioRecord>>& audioRecords, vector<sptr<AudioRecord>>& processedAudioRecords)
{
    std::lock_guard<mutex> lock(deferredProcessMutex_);
    if (audioDeferredProcessPtr_ == nullptr) {
        CreateAudioDeferredProcess(audioCapturerSession);
    }
    CHECK_RETURN(!audioDeferredProcessPtr_);
    audioDeferredProcessPtr_->Process(audioRecords, processedAudioRecords);
}

void AudioDeferredProcessSingle::CreateAudioDeferredProcess(sptr<AudioCapturerSession> audioCapturerSession)
{
    MEDIA_INFO_LOG("AudioDeferredProcessSingle::create audioDeferredProcessPtr_.");
    CHECK_RETURN_ELOG(!audioCapturerSession, "CreateAudioDeferredProcess audioCaptureSession is nullptr");
    audioDeferredProcessPtr_ = std::make_unique<AudioDeferredProcess>();
    audioDeferredProcessPtr_->StoreOptions(
        audioCapturerSession->deferredInputOptions_, audioCapturerSession->deferredOutputOptions_);
    CHECK_RETURN(audioDeferredProcessPtr_->GetOfflineEffectChain() != 0);
    CHECK_RETURN(audioDeferredProcessPtr_->ConfigOfflineAudioEffectChain() != 0);
    CHECK_RETURN(audioDeferredProcessPtr_->PrepareOfflineAudioEffectChain() != 0);
    CHECK_RETURN(audioDeferredProcessPtr_->GetMaxBufferSize(audioCapturerSession->deferredInputOptions_,
                                                            audioCapturerSession->deferredOutputOptions_) != 0);
}

void AudioDeferredProcessSingle::ProcessMutedAudioBufferForVecs(sptr<AudioCapturerSession> audioCapturerSession,
    vector<sptr<AudioRecord>>& audioRecords, vector<sptr<AudioRecord>>& encodeAudioRecords)
{
    MEDIA_DEBUG_LOG("AudioDeferredProcessSingle::ProcessMutedAudioBufferForVecs enter");
    std::lock_guard<mutex> lock(deferredProcessMutex_);
    if (audioDeferredProcessPtr_ == nullptr) {
        CreateAudioDeferredProcess(audioCapturerSession);
    }
    CHECK_RETURN_ELOG(!audioDeferredProcessPtr_,
                      "AudioDeferredProcessSingle::ProcessMutedAudioBufferForVecs audioDeferredProcessPtr_ is nullptr");
    audioDeferredProcessPtr_->SetMutedAudioRecordForVecs(audioRecords, encodeAudioRecords);
}

AudioTaskManager::AudioTaskManager(sptr<AudioCapturerSession> audioCaptureSession)
    : arrivalAudioBufferQueue_("audioArrivalCache", AUDIO_RECORD_CACHE_SIZE)
{
    CAMERA_SYNC_TRACE;
    audioCapturerSession_ = audioCaptureSession;
    MEDIA_DEBUG_LOG("AudioTaskManager is called");
}

AudioTaskManager::~AudioTaskManager()
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("~AudioTaskManager is called");
    Release();
    ClearTaskResource();
}

void AudioTaskManager::Release()
{
    CAMERA_SYNC_TRACE;
    CHECK_EXECUTE(timerId_ != 0, CameraTimer::GetInstance().Unregister(timerId_));
    AudioDeferredProcessSingle& audioDeferredProcessSingle = AudioDeferredProcessSingle::GetInstance();
    audioDeferredProcessSingle.DestroyAudioDeferredProcess();
    {
        std::lock_guard<std::mutex> lock(captureIdToTimMutex_);
        curCaptureIdToTimeMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(audioCacheMutex_);
        processedAudioRecordCache_.clear();
    }

    arrivalAudioBufferQueue_.Clear();
    ClearTaskResource();
}

void AudioTaskManager::ClearTaskResource()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AudioTaskManager ClearTaskResource start");
    {
        lock_guard<mutex> lock(audioTaskManagerMutex_);
        isAudioTaskActive_ = false;
        if (audioProcessTaskManager_ != nullptr) {
            audioProcessTaskManager_->CancelAllTasks();
            audioProcessTaskManager_.reset();
        }
    }
    {
        lock_guard<mutex> lock(audioProcessManagerMutex_);
        isAudioTaskActive_ = false;
        if (audioRecordProcessManager_ != nullptr) {
            audioRecordProcessManager_->CancelAllTasks();
            audioRecordProcessManager_.reset();
        }
    }
}

void AudioTaskManager::SubmitTask(function<void()> task)
{
    auto audioTaskManager = GetAudioTaskManager();
    CHECK_RETURN(!audioTaskManager);
    audioTaskManager->SubmitTask(task);
}

int32_t AudioTaskManager::ClearProcessedAudioCache(int32_t captureId)
{
    int32_t startTimeStamp = 0;
    {
        std::lock_guard<std::mutex> lock(captureIdToTimMutex_);
        auto &captureIdTimeMap = GetCurrentCaptureIdToTimeMap();
        CHECK_RETURN_RET_ELOG(captureIdTimeMap.empty(), -1, "Current captureIdTimeMap is empty");
        auto itr = captureIdTimeMap.find(captureId);
        CHECK_RETURN_RET_ELOG(itr == captureIdTimeMap.end(), -1, "Current captureId not found in map");
        startTimeStamp = itr->second;
    }
    {
        std::lock_guard<std::mutex> lock(audioCacheMutex_);
        auto &processedAudioRecordCache = GetProcessedAudioRecordCache();
        CHECK_RETURN_RET_ELOG(processedAudioRecordCache.empty(), -1,
                              "Current processedAudioRecordCache is empty");
        processedAudioRecordCache.erase(std::remove_if(processedAudioRecordCache.begin(),
            processedAudioRecordCache.end(), [startTimeStamp](const auto &audioRecord) {
                return audioRecord->GetTimeStamp() < startTimeStamp;
            }), processedAudioRecordCache.end());
    }
    return CAMERA_OK;
}

void AudioTaskManager::RemovePreviousCaptureForTimeMap(int32_t captureId)
{
    std::lock_guard<std::mutex> lock(captureIdToTimMutex_);
    auto &audioCaptureIdToTimeMap = GetCurrentCaptureIdToTimeMap();
    CHECK_EXECUTE(audioCaptureIdToTimeMap.size() >= 2, {
        auto lastItr = --audioCaptureIdToTimeMap.end();
        audioCaptureIdToTimeMap.erase(audioCaptureIdToTimeMap.begin(), lastItr);
        MEDIA_DEBUG_LOG("RemovePreviousCaptureForTimeMap sucess");
    });
}

shared_ptr<TaskManager>& AudioTaskManager::GetAudioTaskManager()
{
    lock_guard<mutex> lock(audioTaskManagerMutex_);
    bool shouldCreateTaskManager = audioProcessTaskManager_ == nullptr && isAudioTaskActive_.load();
    if (shouldCreateTaskManager) {
        audioProcessTaskManager_ = make_unique<TaskManager>("AudioTaskManager",
                                                            DEFAULT_AUDIO_TASK_THREAD_NUMBER, false);
    }
    return audioProcessTaskManager_;
}

shared_ptr<TaskManager>& AudioTaskManager::GetAudioProcessManager()
{
    lock_guard<mutex> lock(audioProcessManagerMutex_);
    bool shouldCreateTaskManager = audioRecordProcessManager_ == nullptr && isAudioTaskActive_.load();
    if (shouldCreateTaskManager) {
        audioRecordProcessManager_ = make_unique<TaskManager>("AudioProcessTaskManager",
                                                              DEFAULT_PROCESSED_THREAD_NUMBER, false);
    }
    return audioRecordProcessManager_;
}

void AudioTaskManager::RegisterAudioBuffeArrivalCallback(int64_t startTimeStamp)
{
    MEDIA_DEBUG_LOG("AudioTaskManager::RegisterAudioBuffeArrivalCallback time :%{public}" PRIu64, startTimeStamp);
    int64_t endTime = NanosecToMillisec(startTimeStamp + MAX_NANOSEC_RANGE);
    int64_t startTime = NanosecToMillisec(startTimeStamp);
    if (audioCapturerSession_) {
        auto weakThis = wptr<AudioTaskManager>(this);
        CHECK_RETURN_ELOG(weakThis == nullptr, "RegisterAudioBuffeArrivalCallback audioTaskManager is nullptr");
        audioCapturerSession_->ExecuteOnceRecord(startTime, endTime,
            [weakThis](sptr<AudioRecord> audioRecord, bool isFinished) {
                auto sharedThis = weakThis.promote();
                CHECK_RETURN_ELOG(sharedThis == nullptr, "RegisterAudioBuffeArrivalCallback sharedThis is nullptr");
                sharedThis->OnAudioBufferArrival(audioRecord, isFinished);
            });
    }
}

void AudioTaskManager::OnAudioBufferArrival(sptr<AudioRecord>& audioRecord, bool isFinished)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("AudioTaskManager::OnAudioBufferArrival timeStamp: %{public}" PRIu64, audioRecord->GetTimeStamp());
    if (arrivalAudioBufferQueue_.Full()) {
        sptr<AudioRecord> audioRecord = arrivalAudioBufferQueue_.Pop();
        CHECK_EXECUTE(audioRecord->IsFinishCache() && audioRecord->GetFinishProcessedStatus(),
                      audioRecord->ReleaseAudioBuffer());
    }
    CHECK_RETURN(!audioRecord);
    arrivalAudioBufferQueue_.Push(audioRecord);
    MEDIA_DEBUG_LOG("AudioTaskManager::OnAudioBufferArrival current size: %{public}zu",
                    arrivalAudioBufferQueue_.Size());
    CHECK_RETURN(!isFinished && arrivalAudioBufferQueue_.Size() % AUDIO_PROCESS_MATCH_SIZE != 0);
    if (isFinished && arrivalAudioBufferQueue_.Size() % AUDIO_PROCESS_MATCH_SIZE != 0) {
        size_t number = arrivalAudioBufferQueue_.Size() % AUDIO_PROCESS_MATCH_SIZE;
        while (number > 0) {
            sptr<AudioRecord> backAudioRecord = arrivalAudioBufferQueue_.PopBack();
            CHECK_EXECUTE(backAudioRecord->IsFinishCache() && backAudioRecord->GetFinishProcessedStatus(),
                          backAudioRecord->ReleaseAudioBuffer());
            number--;
        }
    }
    MEDIA_DEBUG_LOG("AudioTaskManager::OnAudioBufferArrival enter process size: %{public}zu",
                    arrivalAudioBufferQueue_.Size());
    if (isFinished && !isBufferArrivalFinished_) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto thisPtr = sptr<AudioTaskManager>(this);
        CHECK_RETURN_ELOG(!thisPtr, "OnAudioBufferArrival current audioTaskManager is nullptr");
        for (size_t count = 0; count < AUDIO_PROCESS_MATCH_SIZE; count++) {
            arrivalVarible_.wait_for(
                lock, std::chrono::milliseconds(WAIT_AUDIO_PROCESSED_DURATION_TIME),
                [thisPtr] { return thisPtr->GetIsBufferArrivalFinished(); });
        }
    }
    CHECK_RETURN_ELOG(!isFinished && !isBufferArrivalFinished_,
                      "AudioTaskManager::OnAudioBufferArrival proceesed failed");
    SetIsBufferArrivalFinished(false);
    ProcessAudioFromAudioBufferQueue();
    // LCOV_EXCL_STOP
}

void AudioTaskManager::ProcessAudioFromAudioBufferQueue()
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("AudioTaskManager::ProcessAudioFromAudioBufferQueue enter");
    auto processTaskManager = GetAudioProcessManager();
    auto weakThis = wptr<AudioTaskManager>(this);
    CHECK_RETURN_ELOG(weakThis == nullptr || processTaskManager == nullptr,
                      "ProcessAudioFromAudioBufferQueue failed");
    processTaskManager->SubmitTask([weakThis]() {
        CAMERA_SYNC_TRACE;
        auto sharedThis = weakThis.promote();
        CHECK_RETURN_ELOG(sharedThis == nullptr, "ProcessAudioFromAudioBufferQueue current sharedThis is nullptr");
        vector<sptr<AudioRecord>> audioRecords = sharedThis->GetArrivalAudioBufferQueue().GetAllElements();
        CHECK_RETURN_ELOG(audioRecords.size() == 0, "ProcessAudioFromAudioBufferQueue currenter audioRecords is empty");
        auto &arrivalAudiBufferQueue = sharedThis->GetArrivalAudioBufferQueue();
        for (size_t index = 0; index < audioRecords.size(); index++) {
            CHECK_EXECUTE(arrivalAudiBufferQueue.Front()->GetTimeStamp() <= audioRecords.back()->GetTimeStamp(),
                          arrivalAudiBufferQueue.Pop());
        }
        MEDIA_INFO_LOG("AudioTaskManager::ProcessAudioFromAudioBufferQueue audioRecords.size(): %{public}zu",
                       audioRecords.size());
        vector<sptr<AudioRecord>> audioRecordVec;
        for (auto ptr : audioRecords) {
            audioRecordVec.emplace_back(new AudioRecord(ptr->GetTimeStamp()));
        }
        AudioDeferredProcessSingle &audioDeferredProcessSingle = AudioDeferredProcessSingle::GetInstance();
        CHECK_RETURN_ELOG(!sharedThis || !sharedThis->audioCapturerSession_,
                          "ProcessAudioFromAudioBufferQueue current sharedThis is nullptr");
        audioDeferredProcessSingle.ConfigAndProcess(
            sharedThis->audioCapturerSession_, audioRecords, audioRecordVec);
        sharedThis->SetTimerForAudioDeferredProcess();
        for (auto &record : audioRecords) {
            CHECK_EXECUTE(record != nullptr, record->SetFinishedProcessedStatus(true));
        }
        {
            std::lock_guard<std::mutex> lock(sharedThis->audioCacheMutex_);
            auto &processedAudioRecordCache = sharedThis->GetProcessedAudioRecordCache();
            processedAudioRecordCache.insert(processedAudioRecordCache.end(),
                audioRecordVec.begin(), audioRecordVec.end());
            std::sort(processedAudioRecordCache.begin(), processedAudioRecordCache.end(),
                [](const sptr<AudioRecord> &audioRecordA, const sptr<AudioRecord> &audioRecordB) {
                    return audioRecordA->GetTimeStamp() < audioRecordB->GetTimeStamp();
                });
        }
        sharedThis->SetIsBufferArrivalFinished(true);
        MEDIA_INFO_LOG("AudioTaskManager::ProcessAudioFromAudioBufferQueue isFinished %{public}d",
                       sharedThis->isBufferArrivalFinished_.load());
    });
    MEDIA_DEBUG_LOG("AudioTaskManager::ProcessAudioFromAudioBufferQueue end");
    // LCOV_EXCL_STOP
}

void AudioTaskManager::ProcessAudioBuffer(int32_t captureId, int64_t startTimeStamp)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("AudioTaskManager::ProcessAudioBuffer enter captureId: %{public}d,"
                   "startTimeStamp: %{public}" PRIu64 ", curCaptureIdToTimeMap_: %{public}zu", captureId,
                   startTimeStamp, curCaptureIdToTimeMap_.size());
    auto audioCapturerSession = GetAudioCaptureSession();
    CHECK_RETURN_ELOG(!audioCapturerSession, "current audioCapturerSession is nullptr");
    {
        std::lock_guard<std::mutex> lock(captureIdToTimMutex_);
        if (!curCaptureIdToTimeMap_.empty() && !audioCapturerSession->GetProcessedCbFunc()) {
            auto last_itr = curCaptureIdToTimeMap_.rbegin();
            if (NanosecToMillisec(startTimeStamp) <= (last_itr->second + MAX_AUDIO_NANOSEC_RANGE)
                && !audioCapturerSession->GetProcessedCbFunc()) {
                audioCapturerSession->UpdateCaptureTimeRangeForEnd(
                    NanosecToMillisec(startTimeStamp + MAX_NANOSEC_RANGE));
                curCaptureIdToTimeMap_[captureId] = NanosecToMillisec(startTimeStamp);
                return;
            }
        }
        CHECK_EXECUTE(audioCapturerSession && !audioCapturerSession->GetProcessedCbFunc(),
                      audioCapturerSession->SetAudioBufferCallback(nullptr));
        curCaptureIdToTimeMap_[captureId] = NanosecToMillisec(startTimeStamp);
    }
    RegisterAudioBuffeArrivalCallback(startTimeStamp);
    PrepareAudioBuffer(startTimeStamp);
    // LCOV_EXCL_STOP
}

void AudioTaskManager::PrepareAudioBuffer(int64_t startTime)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    int64_t startTimeStamp = NanosecToMillisec(startTime);
    int64_t endTimeStamp = NanosecToMillisec(startTime + MAX_NANOSEC_RANGE);
    if (audioCapturerSession_) {
        std::vector<sptr<AudioRecord>> audioRecords;
        audioCapturerSession_->GetAudioRecords(startTimeStamp, endTimeStamp, audioRecords);
        for (auto &audioRecord : audioRecords) {
            arrivalAudioBufferQueue_.Push(audioRecord);
        }
    }
    // LCOV_EXCL_STOP
}

void AudioTaskManager::ProcessAudioBufferToMuted(vector<sptr<AudioRecord>>& audioRecords,
                                                 vector<sptr<AudioRecord>>& encodeAudioRecords)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("AudioTaskManager::ProcessAudioBufferToMuted enter");
    AudioDeferredProcessSingle &audioDeferredProcessSingle = AudioDeferredProcessSingle::GetInstance();
    if (audioCapturerSession_) {
        audioDeferredProcessSingle.ProcessMutedAudioBufferForVecs(audioCapturerSession_,
                                                                  audioRecords, encodeAudioRecords);
    }
    SetTimerForAudioDeferredProcess();
    // LCOV_EXCL_STOP
}

void AudioTaskManager::SetTimerForAudioDeferredProcess()
{
    auto weakThis = wptr<AudioTaskManager>(this);
    if (timerId_) {
        MEDIA_INFO_LOG("audioDP release time reset, %{public}u", timerId_);
        CameraTimer::GetInstance().Unregister(timerId_);
    }
    timerId_ = CameraTimer::GetInstance().Register([weakThis]()-> void {
        auto sharedThis = weakThis.promote();
        CHECK_RETURN(sharedThis == nullptr);
        AudioDeferredProcessSingle& audioDeferredProcessSingle = AudioDeferredProcessSingle::GetInstance();
        audioDeferredProcessSingle.TimerDestroyAudioDeferredProcess();
        MEDIA_INFO_LOG("AvcodecTaskManager::delete audioDeferredProcessPtr_.");
        sharedThis->timerId_ = 0;
    }, RELEASE_WAIT_TIME, true);
}
} // namespace CameraStandard
} // namespace OHOS