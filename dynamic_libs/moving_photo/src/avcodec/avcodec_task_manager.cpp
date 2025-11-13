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
#include "frame_record.h"
#include "native_avbuffer.h"
#include "native_avbuffer_info.h"
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

AvcodecTaskManager::AvcodecTaskManager(sptr<AudioCapturerSession> audioCaptureSession,
    VideoCodecType type, ColorSpace colorSpace) : videoCodecType_(type), colorSpace_(colorSpace)
{
    CAMERA_SYNC_TRACE;
    #ifdef MOVING_PHOTO_ADD_AUDIO
    audioCapturerSession_ = audioCaptureSession;
    audioEncoder_ = make_unique<AudioEncoder>();
    #endif
    // Create Task Manager
    videoEncoder_ = make_shared<VideoEncoder>(type, colorSpace);
}

AvcodecTaskManager::AvcodecTaskManager(wptr<Surface> movingSurface, shared_ptr<Size> size,
    sptr<AudioCapturerSession> audioCaptureSession, VideoCodecType type, ColorSpace colorSpace)
    :videoCodecType_(type), colorSpace_(colorSpace), movingSurface_(movingSurface), size_(size)
{
    CAMERA_SYNC_TRACE;
#ifdef MOVING_PHOTO_ADD_AUDIO
    audioCapturerSession_ = audioCaptureSession;
    audioEncoder_ = make_unique<AudioEncoder>();
#endif
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
    if (taskManager_ == nullptr && isActive_.load()) {
        taskManager_ = make_unique<TaskManager>("AvcodecTaskManager", DEFAULT_THREAD_NUMBER, false);
    }
    return taskManager_;
}

shared_ptr<TaskManager>& AvcodecTaskManager::GetEncoderManager()
{
    lock_guard<mutex> lock(encoderManagerMutex_);
    if (videoEncoderManager_ == nullptr && isActive_.load()) {
        videoEncoderManager_ = make_unique<TaskManager>("VideoTaskManager", DEFAULT_ENCODER_THREAD_NUMBER, false);
    }
    return videoEncoderManager_;
}

void AvcodecTaskManager::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    auto encodeManager = GetEncoderManager();
    CHECK_RETURN(!encodeManager);
    videoEncoder_->TsVecInsert(frameRecord->GetTimeStamp());
    encodeManager->SubmitTask([thisPtr, frameRecord, cacheCallback]() {
        CAMERA_SYNC_TRACE;
        CHECK_RETURN(thisPtr == nullptr);
        CHECK_RETURN(!thisPtr->videoEncoder_ || !frameRecord);
        sptr<Surface> movingSurface = thisPtr->movingSurface_.promote();
        if (movingSurface) {
            sptr<SurfaceBuffer> codecDetachBuf;
            thisPtr->videoEncoder_->DetachCodecBuffer(codecDetachBuf, frameRecord);
            SurfaceError surfaceRet = movingSurface->AttachBufferToQueue(codecDetachBuf);
            CHECK_PRINT_ELOG(surfaceRet != SURFACE_ERROR_OK, "movingSurface AttachBuffer faild");
            surfaceRet = movingSurface->ReleaseBuffer(codecDetachBuf, SyncFence::INVALID_FENCE);
            CHECK_PRINT_ELOG(surfaceRet != SURFACE_ERROR_OK, "movingSurface ReleaseBuffer faild");
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
        CHECK_EXECUTE(cacheCallback, cacheCallback(frameRecord, isEncodeSuccess));
    });
}

void AvcodecTaskManager::SubmitTask(function<void()> task)
{
    auto taskManager = GetTaskManager();
    CHECK_EXECUTE(taskManager, taskManager->SubmitTask(task));
}

void AvcodecTaskManager::SetVideoFd(
    int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t captureId)
{
    lock_guard<mutex> lock(videoFdMutex_);
    MEDIA_INFO_LOG("Set timestamp: %{public}" PRIu64 ", captureId: %{public}d", timestamp, captureId);
    videoFdMap_.insert(std::make_pair(captureId, std::make_pair(timestamp, photoAssetProxy)));
    MEDIA_INFO_LOG("video map size:%{public}zu", videoFdMap_.size());
    cvEmpty_.notify_all();
}

constexpr inline float MovingPhotoNanosecToMillisec(int64_t nanosec)
{
    return static_cast<float>(nanosec) / 1000000.0f;
}

sptr<AudioVideoMuxer> AvcodecTaskManager::CreateAVMuxer(vector<sptr<FrameRecord>> frameRecords, int32_t captureRotation,
    vector<sptr<FrameRecord>> &choosedBuffer, int32_t captureId)
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
    ChooseVideoBuffer(frameRecords, choosedBuffer, timestamp, captureId);
    muxer->Create(format, photoAssetProxy);
    muxer->SetRotation(captureRotation);
    CHECK_EXECUTE(!choosedBuffer.empty(),
        {
            muxer->SetCoverTime(MovingPhotoNanosecToMillisec(std::min(timestamp,
                choosedBuffer.back()->GetTimeStamp()) - choosedBuffer.front()->GetTimeStamp()));
            muxer->SetStartTime(MovingPhotoNanosecToMillisec(choosedBuffer.front()->GetTimeStamp()));
            CHECK_EXECUTE(videoEncoder_ != nullptr,
            muxer->SetSqr(videoEncoder_->GetEncoderBitrate(), videoEncoder_->GetBframeAbility()));
        }
    );
    auto formatVideo = make_shared<Format>();
    MEDIA_INFO_LOG("CreateAVMuxer videoCodecType_ = %{public}d", videoCodecType_);
    formatVideo->PutStringValue(MediaDescriptionKey::MD_KEY_CODEC_MIME, videoCodecType_
        == VIDEO_ENCODE_TYPE_HEVC ? OH_AVCODEC_MIMETYPE_VIDEO_HEVC : OH_AVCODEC_MIMETYPE_VIDEO_AVC);
    if (videoCodecType_ == VIDEO_ENCODE_TYPE_HEVC && videoEncoder_->IsHdr(colorSpace_)) {
        formatVideo->PutIntValue(MediaDescriptionKey::MD_KEY_VIDEO_IS_HDR_VIVID, IS_HDR_VIVID);
    }
    CHECK_RETURN_RET_ELOG(frameRecords.empty(), nullptr, "frameRecords is empty");
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
    formatAudio->PutIntValue(MediaDescriptionKey::MD_KEY_PROFILE, DEFAULT_PROFILE);
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
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::FinishMuxer(sptr<AudioVideoMuxer> muxer, int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("doMxuer video is finished");
    CHECK_RETURN(!muxer);
    muxer->Stop();
    muxer->Release();
    std::shared_ptr<PhotoAssetIntf> proxy = muxer->GetPhotoAssetProxy();
    MEDIA_INFO_LOG("PhotoAssetProxy notify enter");
    CHECK_RETURN(!proxy);
    proxy->NotifyVideoSaveFinished();
    lock_guard<mutex> lock(videoFdMutex_);
    videoFdMap_.erase(captureId);
    MEDIA_INFO_LOG("finishMuxer end, videoFdMap_ size is %{public}zu", videoFdMap_.size());
}

bool AvcodecTaskManager::isEmptyVideoFdMap()
{
    lock_guard<mutex> lock(videoFdMutex_);
    return videoFdMap_.empty();
}

void AvcodecTaskManager::DoMuxerVideo(vector<sptr<FrameRecord>> frameRecords, uint64_t taskName,
    int32_t captureRotation, int32_t captureId) __attribute__((no_sanitize("cfi")))
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_ELOG(frameRecords.empty(), "DoMuxerVideo error of empty encoded frame");
    auto thisPtr = sptr<AvcodecTaskManager>(this);
    auto taskManager = GetTaskManager();
    CHECK_RETURN_ELOG(taskManager == nullptr, "GetTaskManager is null");
    GetTaskManager()->SubmitTask([thisPtr, frameRecords, captureRotation, captureId]() {
        CAMERA_SYNC_TRACE;
        MEDIA_INFO_LOG("CreateAVMuxer with %{public}zu", frameRecords.size());
        vector<sptr<FrameRecord>> choosedBuffer;
        sptr<AudioVideoMuxer> muxer = thisPtr->CreateAVMuxer(frameRecords, captureRotation, choosedBuffer, captureId);
        CHECK_RETURN_ELOG(muxer == nullptr, "CreateAVMuxer failed");
        if (choosedBuffer.empty()) {
            lock_guard<mutex> lock(thisPtr->videoFdMutex_);
            thisPtr->videoFdMap_.erase(captureId);
            MEDIA_ERR_LOG("choosed empty buffer, videoFdMap_ size is %{public}zu", thisPtr->videoFdMap_.size());
            return;
        }
        auto result = muxer->WriteSampleBuffer(thisPtr->videoEncoder_->GetXpsBuffer(), VIDEO_TRACK);
        MEDIA_DEBUG_LOG("write sample result %{public}d", result);
        int64_t videoStartTime = choosedBuffer.front()->GetTimeStamp();
        for (size_t index = 0; index < choosedBuffer.size(); index++) {
            MEDIA_DEBUG_LOG("write sample index %{public}zu", index);
            shared_ptr<Media::AVBuffer> buffer = choosedBuffer[index]->encodedBuffer;
            {
                std::lock_guard<std::mutex> lock(choosedBuffer[index]->bufferMutex_);
                CHECK_CONTINUE_WLOG(buffer == nullptr, "video encodedBuffer is null");
                buffer->pts_ = NanosecToMicrosec(choosedBuffer[index]->GetTimeStamp() - videoStartTime);
                MEDIA_DEBUG_LOG("choosed buffer pts:%{public}" PRIu64 ",flag:%{public}d,dts:%{public}" PRId64
                                ",muxerIndex:%{public}" PRId64,
                    choosedBuffer[index]->GetTimeStamp(), buffer->flag_, buffer->pts_,
                    choosedBuffer[index]->GetMuxerIndex());
                muxer->WriteSampleBuffer(buffer, VIDEO_TRACK);
            }
            sptr<SurfaceBuffer> metaSurfaceBuffer = frameRecords[index]->GetMetaBuffer();
            if (metaSurfaceBuffer) {
                shared_ptr<AVBuffer> metaAvBuffer = AVBuffer::CreateAVBuffer(metaSurfaceBuffer);
                 metaAvBuffer->pts_ = buffer->pts_;
                MEDIA_DEBUG_LOG("metaAvBuffer pts_ %{public}llu, avBufferSize: %{public}d",
                    (long long unsigned)(metaAvBuffer->pts_), metaAvBuffer->memory_->GetSize());
                muxer->WriteSampleBuffer(metaAvBuffer, META_TRACK);
            } else {
                MEDIA_ERR_LOG("metaSurfaceBuffer is nullptr");
            }
        }
        #ifdef MOVING_PHOTO_ADD_AUDIO
        // CollectAudioBuffer
        vector<sptr<AudioRecord>> audioRecords;
        vector<sptr<AudioRecord>> processedAudioRecords;
        thisPtr->PrepareAudioBuffer(choosedBuffer, audioRecords, processedAudioRecords);
        thisPtr->CollectAudioBuffer(processedAudioRecords, muxer);
        #endif
        thisPtr->FinishMuxer(muxer, captureId);
    });
}


void AvcodecTaskManager::NotifyEOS()
{
    MEDIA_INFO_LOG("AvcodecTaskManager::NotifyEOS() start");
    videoEncoder_->NotifyEndOfStream();
    MEDIA_INFO_LOG("AvcodecTaskManager::NotifyEOS() end");
}

size_t AvcodecTaskManager::FindIdrFrameIndex(vector<sptr<FrameRecord>> frameRecords, int64_t clearVideoEndTime,
    int64_t shutterTime, int32_t captureId)
{
    // LCOV_EXCL_START
    bool isDeblurStartTime = false;
    std::unique_lock<mutex> startTimeLock(startTimeMutex_);
    int64_t clearVideoStartTime = shutterTime - preBufferDuration_;
    if (mPStartTimeMap_.count(captureId) && mPStartTimeMap_[captureId] <= shutterTime
        && mPStartTimeMap_[captureId] > clearVideoStartTime) {
        MEDIA_INFO_LOG("set deblur start time is %{public}" PRIu64, mPStartTimeMap_[captureId]);
        clearVideoStartTime = mPStartTimeMap_[captureId];
        MEDIA_INFO_LOG("clearVideoEndTime is %{public}" PRIu64, NanosecToMicrosec(clearVideoEndTime));
        int64_t absoluteValue = abs(clearVideoEndTime - clearVideoStartTime);
        int64_t deblurThreshold = 264000000L;
        isDeblurStartTime = absoluteValue < deblurThreshold;
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
            if (frame->IsIDRFrame() && frame->GetTimeStamp() >= clearVideoStartTime &&
                frame->GetTimeStamp() < shutterTime) {
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
    MEDIA_INFO_LOG("IgnoreDeblur enter");
    choosedBuffer.clear();
    CHECK_RETURN(frameRecords.empty());
    auto it = find_if(
        frameRecords.begin(), frameRecords.end(), [](const sptr<FrameRecord>& frame) { return frame->IsIDRFrame(); });
    int64_t firstIdrTimeStamp = 0;
    if (it != frameRecords.end()) {
        firstIdrTimeStamp = it->GetRefPtr()->GetTimeStamp();
    }
    size_t frameCount = 0;
    while (it != frameRecords.end()) {
        int64_t timeStamp = it->GetRefPtr()->GetTimeStamp();
        bool isIgnoreDeblurFrame = frameCount < MAX_FRAME_COUNT && timeStamp - firstIdrTimeStamp < MAX_NANOSEC_RANGE;
        CHECK_EXECUTE(isIgnoreDeblurFrame, {
          choosedBuffer.emplace_back(*it);
          ++frameCount;
        });
        ++it;
    }
}

void AvcodecTaskManager::ChooseVideoBuffer(vector<sptr<FrameRecord>> frameRecords,
    vector<sptr<FrameRecord>> &choosedBuffer, int64_t shutterTime, int32_t captureId)
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
    MEDIA_DEBUG_LOG("ChooseVideoBuffer::idrIndex:%{public}" PRIu64, idrIndex);
    size_t frameCount = 0;
    int64_t idrIndexTimeStamp = frameRecords[idrIndex]->GetTimeStamp();
    for (size_t index = idrIndex; index < frameRecords.size(); ++index) {
        auto frame = frameRecords[index];
        int64_t timestamp = frame->GetTimeStamp();
        bool isBeforeEndTimeAndUnderMaxFrameCount = timestamp <= clearVideoEndTime && frameCount < MAX_FRAME_COUNT
            && timestamp - idrIndexTimeStamp < MAX_NANOSEC_RANGE;
        CHECK_EXECUTE(isBeforeEndTimeAndUnderMaxFrameCount, {
            choosedBuffer.push_back(frame);
            MEDIA_DEBUG_LOG("ChooseVideoBuffer::after choose index:%{public}" PRIu64 ", timestamp:%{public}" PRIu64
                            ",pts:%{public}" PRIu64 ",flag:%{public}u",
                index, frame->GetTimeStamp(), frame->encodedBuffer->pts_, frame->encodedBuffer->flag_);
            ++frameCount;
        });
    }

    CHECK_EXECUTE(choosedBuffer.size() < MIN_FRAME_RECORD_BUFFER_SIZE || !frameRecords[idrIndex]->IsIDRFrame(),
        IgnoreDeblur(frameRecords, choosedBuffer, shutterTime));
    MEDIA_INFO_LOG("ChooseVideoBuffer with size %{public}zu, frontBuffer timeStamp: %{public}" PRIu64 ", "
        "backBuffer timeStamp: %{public}" PRIu64, choosedBuffer.size(), choosedBuffer.front()->GetTimeStamp(),
        choosedBuffer.back()->GetTimeStamp());
    
    std::sort(choosedBuffer.begin(), choosedBuffer.end(), [](sptr<FrameRecord> a, sptr<FrameRecord> b) {
        return a->muxerIndex_ < b->muxerIndex_;
    });
    for (auto ptr:choosedBuffer) {
        MEDIA_INFO_LOG("ChooseVideoBuffer timestamp:%{public}" PRIu64, ptr->GetTimeStamp());
    }
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::PrepareAudioBuffer(vector<sptr<FrameRecord>>& choosedBuffer,
    vector<sptr<AudioRecord>>& audioRecords, vector<sptr<AudioRecord>>& processedAudioRecords)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    int64_t videoStartTime = choosedBuffer.front()->GetTimeStamp();
    if (audioCapturerSession_) {
        int64_t startTime = NanosecToMillisec(videoStartTime);
        int64_t endTime = NanosecToMillisec(choosedBuffer.back()->GetTimeStamp());
        audioCapturerSession_->GetAudioRecords(startTime, endTime, audioRecords);
        for (auto ptr: audioRecords) {
            processedAudioRecords.emplace_back(new AudioRecord(ptr->GetTimeStamp()));
        }
        std::lock_guard<mutex> lock(deferredProcessMutex_);
        if (audioDeferredProcess_ == nullptr) {
            audioDeferredProcess_ = std::make_shared<AudioDeferredProcess>();
            CHECK_RETURN(!audioDeferredProcess_);
            audioDeferredProcess_->StoreOptions(audioCapturerSession_->deferredInputOptions_,
                audioCapturerSession_->deferredOutputOptions_);
            CHECK_RETURN(audioDeferredProcess_->GetOfflineEffectChain() != 0);
            CHECK_RETURN(audioDeferredProcess_->ConfigOfflineAudioEffectChain() != 0);
            CHECK_RETURN(audioDeferredProcess_->PrepareOfflineAudioEffectChain() != 0);
            CHECK_RETURN(audioDeferredProcess_->GetMaxBufferSize(audioCapturerSession_->deferredInputOptions_,
                audioCapturerSession_->deferredOutputOptions_) != 0);
        }
        audioDeferredProcess_->Process(audioRecords, processedAudioRecords);
        auto weakThis = wptr<AvcodecTaskManager>(this);
        if (timerId_) {
            MEDIA_INFO_LOG("audioDP release time reset, %{public}u", timerId_);
            CameraTimer::GetInstance().Unregister(timerId_);
        }
        auto curObject = audioDeferredProcess_;
        timerId_ = CameraTimer::GetInstance().Register([weakThis, curObject]()-> void {
            auto sharedThis = weakThis.promote();
            CHECK_RETURN(sharedThis == nullptr);
            std::unique_lock<mutex> lock(sharedThis->deferredProcessMutex_, std::try_to_lock);
            CHECK_RETURN(curObject != sharedThis->audioDeferredProcess_);
            CHECK_RETURN(!lock.owns_lock());
            sharedThis->audioDeferredProcess_ = nullptr;
            sharedThis->timerId_ = 0;
        }, RELEASE_WAIT_TIME, true);
    }
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::CollectAudioBuffer(vector<sptr<AudioRecord>> audioRecordVec, sptr<AudioVideoMuxer> muxer)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CollectAudioBuffer start with size %{public}zu", audioRecordVec.size());
    bool isEncodeSuccess = false;
    CHECK_RETURN_ELOG(!audioEncoder_ || audioRecordVec.empty() || !muxer,
        "CollectAudioBuffer cannot find useful data");
    // LCOV_EXCL_START
    isEncodeSuccess = audioEncoder_->EncodeAudioBuffer(audioRecordVec);
    MEDIA_DEBUG_LOG("encode audio buffer result %{public}d", isEncodeSuccess);
    size_t maxFrameCount = std::min(audioRecordVec.size(), MAX_AUDIO_FRAME_COUNT);
    for (size_t index = 0; index < maxFrameCount; index++) {
        OH_AVCodecBufferAttr attr = { 0, 0, 0, AVCODEC_BUFFER_FLAGS_NONE };
        OH_AVBuffer* buffer = audioRecordVec[index]->encodedBuffer;
        CHECK_CONTINUE_WLOG(buffer == nullptr, "audio encodedBuffer is null");
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
    // LCOV_EXCL_STOP
}

void AvcodecTaskManager::Release()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AvcodecTaskManager release start");
    CHECK_EXECUTE(videoEncoder_ != nullptr, videoEncoder_->Release());
    CHECK_EXECUTE(audioEncoder_ != nullptr, audioEncoder_->Release());
    CHECK_EXECUTE(timerId_ != 0, CameraTimer::GetInstance().Unregister(timerId_));
    audioDeferredProcess_ = nullptr;
    unique_lock<mutex> lock(videoFdMutex_);
    MEDIA_INFO_LOG("videoFdMap_ size is %{public}zu", videoFdMap_.size());
    videoFdMap_.clear();
    MEDIA_INFO_LOG("AvcodecTaskManager release end");
}

void AvcodecTaskManager::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("AvcodecTaskManager Stop start");
    CHECK_EXECUTE(videoEncoder_ != nullptr, videoEncoder_->Release());
    CHECK_EXECUTE(audioEncoder_ != nullptr, audioEncoder_->Release());
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