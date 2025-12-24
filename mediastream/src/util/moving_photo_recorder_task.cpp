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

#include "moving_photo_recorder_task.h"
#include "camera_log.h"
#include "moving_photo_engine_context.h"
#include "video_buffer_wrapper.h"
#include "datetime_ex.h"
#include <utility>

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {

constexpr uint32_t GET_FD_EXPIREATION_TIME = 2000;

MovingPhotoRecorderTask::MovingPhotoRecorderTask(
    sptr<MovingPhotoRecorderTaskManager> taskManager,
    int32_t rotation, int32_t captureId, int32_t usableCnt)
    : taskManager_(wptr<MovingPhotoRecorderTaskManager>(taskManager)),
      rotation_(rotation), captureId_(captureId), taskId_(captureId), usableCnt_(usableCnt) {
    MEDIA_INFO_LOG("MovingPhotoRecorderTask::MovingPhotoRecorderTask taskId: %{public}d "
        "maxSize: %{public}d rotation: %{public}d", taskId_, usableCnt_, rotation_);
}

MovingPhotoRecorderTask::~MovingPhotoRecorderTask()
{
    MEDIA_INFO_LOG("MovingPhotoRecorderTask::~MovingPhotoRecorderTask id:%{public}d", captureId_);
    videoBufferWrapperList_.clear();
    encodedBufferList_.clear();
}

void MovingPhotoRecorderTask::DrainImage(sptr<VideoBufferWrapper> videoBufferWrapper)
{
    CHECK_RETURN(usableCnt_ <= 0);
    MEDIA_INFO_LOG("MovingPhotoRecorderTask::DrainImage taskId:%{public}d", GetTaskId());
    OnDrainImage(videoBufferWrapper);
    if (--usableCnt_ == 0) {
        DrainFinish(true);
    }
}

void MovingPhotoRecorderTask::OnDrainImage(sptr<VideoBufferWrapper> videoBufferWrapper)
{
    CHECK_RETURN(videoBufferWrapper == nullptr);
    int64_t bufferId = videoBufferWrapper->GetBufferId();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        videoBufferWrapperList_.push_back(videoBufferWrapper);
    }
    {
        std::lock_guard<std::mutex> lock(bufferSetLock_);
        bufferSet_.insert(bufferId);
        MEDIA_INFO_LOG("OnDrainImage taskId:%{public}d set-size:%{public}zu", GetTaskId(), bufferSet_.size());
    }
        
    auto taskManager = taskManager_.promote();
    int32_t taskId = GetTaskId();
    if (videoBufferWrapper->IsIdle() && taskManager) {
        MEDIA_INFO_LOG("OnDrainImage Idle taskId:%{public}d bufferId:%{public}" PRId64, taskId, bufferId);
        taskManager->EncodeBuffer(videoBufferWrapper);
    } else if (videoBufferWrapper->IsFinishEncode() && taskManager) {
        MEDIA_INFO_LOG("OnDrainImage FinishEncode taskId:%{public}d bufferId:%{public}" PRId64, taskId, bufferId);
        taskManager->OnBufferEncodedNoLock(videoBufferWrapper, videoBufferWrapper->IsEncoded());
    } else if (videoBufferWrapper->IsReadyConvert()) {
        MEDIA_INFO_LOG("OnDrainImage ReadyConvert taskId:%{public}d bufferId:%{public}" PRId64, taskId, bufferId);
    } else {
        MEDIA_INFO_LOG("OnDrainImage Invalid status taskId:%{public}d bufferId:%{public}" PRId64, taskId, bufferId);
    }
}

void MovingPhotoRecorderTask::DrainFinish(bool isFinished)
{
    OnDrainImageFinish(isFinished);
}

std::pair<int64_t, std::shared_ptr<PhotoAssetIntf>> GetEmptyPair() {
    return {0, nullptr};
}

std::pair<int64_t, shared_ptr<PhotoAssetIntf>> MovingPhotoRecorderTask::GetPhotoAsset()
{
    auto taskManager = taskManager_.promote();
    CHECK_RETURN_RET_ELOG(taskManager == nullptr, GetEmptyPair(), "taskManager is nullptr");
    return taskManager_->GetPhotoAsset(GetTaskId());
}

bool MovingPhotoRecorderTask::GetStartTime(int64_t& startTime)
{   
    auto taskManager = taskManager_.promote();
    CHECK_RETURN_RET_ELOG(taskManager == nullptr, false, "taskManager is nullptr");
    return taskManager->GetStartTime(GetTaskId(), startTime);
}

bool MovingPhotoRecorderTask::GetEndTime(int64_t& endTime)
{
    auto taskManager = taskManager_.promote();
    CHECK_RETURN_RET_ELOG(taskManager == nullptr, false, "taskManager is nullptr");
    return taskManager->GetStartTime(GetTaskId(), endTime);
}

bool MovingPhotoRecorderTask::GetDeferredVideoEnhanceFlag(uint32_t& flag)
{
    auto taskManager = taskManager_.promote();
    CHECK_RETURN_RET_ELOG(taskManager == nullptr, false, "taskManager is nullptr");
    return taskManager->GetDeferredVideoEnhanceFlag(GetTaskId(), flag);
}

bool MovingPhotoRecorderTask::GetVideoId(std::string& videoId)
{
    auto taskManager = taskManager_.promote();
    CHECK_RETURN_RET_ELOG(taskManager == nullptr, false, "taskManager is nullptr");
    return taskManager->GetVideoId(GetTaskId(), videoId);
}

void MovingPhotoRecorderTask::OnAllBufferEncoded()
{
    MEDIA_INFO_LOG("MovingPhotoRecorderTask::OnAllBufferEncoded taskId:%{public}d %{public}zu/%{public}zu", GetTaskId(),
        encodedBufferList_.size(), videoBufferWrapperList_.size());
    videoBufferWrapperList_.clear();
    std::sort(videoBufferWrapperList_.begin(), videoBufferWrapperList_.end(),
              [](const sptr<VideoBufferWrapper> &a, const sptr<VideoBufferWrapper> &b) {
                return a->GetTimestamp() < b->GetTimestamp();
              });
    auto taskManager = taskManager_.promote();
    CHECK_RETURN_ELOG(taskManager == nullptr, "taskManager is null");
    taskManager->CreateMuxerTask(this);
    MarkNeedRemove();
}

void MovingPhotoRecorderTask::OnDrainImageFinish(bool isFinished)
{
    MEDIA_INFO_LOG("OnDrainImageFinish E taskId:%{public}d", GetTaskId());
    auto taskManager = taskManager_.promote();
    CHECK_RETURN_ELOG(taskManager == nullptr, "taskManager is nullptr");
    drainImageFinish_ = true;
    for (auto &videoBufferWrapper : videoBufferWrapperList_) {
        CHECK_EXECUTE(videoBufferWrapper->IsFinishEncode(),
            OnBufferEncoded(videoBufferWrapper, videoBufferWrapper->IsEncoded()));
    }
}

void MovingPhotoRecorderTask::OnBufferEncoded(sptr<VideoBufferWrapper> videoBufferWrapper, bool encodeResult)
{
    std::lock_guard<std::mutex> lock(bufferSetLock_);
    CHECK_RETURN(isAbort_);
    CHECK_RETURN_ELOG(videoBufferWrapper == nullptr, "videoBufferWrapper is invalid");
    int64_t bufferId = videoBufferWrapper->GetBufferId();
    auto it = bufferSet_.find(bufferId);
    CHECK_RETURN(it == bufferSet_.end());
    bufferSet_.erase(bufferId);
    MEDIA_INFO_LOG("OnBufferEncoded E taskId:%{public}d bufferId:%{public}" PRId64
        " encodeResult:%{public}d set-size::%{public}zu", GetTaskId(), bufferId, encodeResult, bufferSet_.size());
    CHECK_PRINT_ELOG(!encodeResult, "OnBufferEncoded encodeResult is fail");
    CHECK_EXECUTE(encodeResult && videoBufferWrapper->GetEncodedBuffer(),
        encodedBufferList_.push_back(videoBufferWrapper));
    CHECK_EXECUTE(IsAllBufferEncoded(), OnAllBufferEncoded());
}

void MovingPhotoRecorderTask::OnVideoSaveFinish()
{
    MEDIA_INFO_LOG("MovingPhotoRecorderTask::OnVideoSaveFinish E taskId:%{public}d", GetTaskId());
    auto photoAssetProxy = GetPhotoAsset().second;
    CHECK_RETURN_ELOG(photoAssetProxy == nullptr, "photoAssetProxy is nullptr");
    photoAssetProxy->NotifyVideoSaveFinished(VideoType::ORIGIN_VIDEO);
    MEDIA_INFO_LOG("MovingPhotoRecorderTask::OnVideoSaveFinish X taskId:%{public}d", GetTaskId());
}

void MovingPhotoRecorderTask::AbortCapture()
{
    isAbort_ = true;
}

//----------------------------------------------------------------------------------------------------------------------

void MovingPhotoRecorderTaskManager::StopDrainOut()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& task : taskList_) {
        CHECK_EXECUTE(task, task->DrainFinish(false));
    }
}

bool MovingPhotoRecorderTaskManager::IsEmpty()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return taskList_.empty();
}

void MovingPhotoRecorderTaskManager::GetAudioRecords(
    std::vector<sptr<VideoBufferWrapper>>& choosedBufferList, std::vector<sptr<AudioBufferWrapper>>& audioRecords)
{
    CHECK_RETURN_ELOG(choosedBufferList.empty(), "choosedVideoBufferList is nullptr");
    int64_t startTime = NanosecToMillisec(choosedBufferList.front()->GetTimestamp());
    int64_t endTime = NanosecToMillisec(choosedBufferList.back()->GetTimestamp());
    auto engineContext = GetEngineContext();
    CHECK_RETURN_ELOG(engineContext == nullptr, "engineContext is nullptr");
    MEDIA_INFO_LOG("GetAudioRecords enter");
    auto audioCacheFilter = engineContext->GetAudioCacheFilter();
    CHECK_RETURN_ELOG(audioCacheFilter == nullptr, "audioCacheFilter is nullptr");
    audioCacheFilter->GetAudioRecords(startTime, endTime, audioRecords);
}

void MovingPhotoRecorderTaskManager::CreateMuxerTask(sptr<MovingPhotoRecorderTask> task)
{
    auto engineContext = GetEngineContext();
    CHECK_RETURN_ELOG(engineContext == nullptr, "engineContext is nullptr");
    MEDIA_INFO_LOG("CreateMuxerTask enter");
    auto muxerFilter = engineContext->GetMovingPhotoMuxerFilter();
    CHECK_RETURN_ELOG(muxerFilter == nullptr, "muxerFilter is nullptr");
    muxerFilter->CreateMuxerTask(task);
}

MovingPhotoRecorderTaskManager::~MovingPhotoRecorderTaskManager()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        taskList_.clear();
    }
    {
        std::lock_guard<mutex> lock(photoAssetMutex_);
        photoAssetMap_.clear();
    }
    startTimeMap_.Clear();
    endTimeMap_.Clear();
    deferredVideoEnhanceFlagMap_.Clear();
    videoIdMap_.Clear();
}

sptr<MovingPhotoRecorderTask> MovingPhotoRecorderTaskManager::CreateTask(
    int32_t rotation, int32_t captureId, int32_t maxSize)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto task = sptr<MovingPhotoRecorderTask>::MakeSptr(this, rotation, captureId, maxSize);
    taskList_.push_back(task);
    MEDIA_INFO_LOG("CreateTask insert in taskList, taskId:%{public}d", captureId);
    return task;
}

void MovingPhotoRecorderTaskManager::DrainImage(sptr<VideoBufferWrapper> videoBufferWrapper)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_RETURN(taskList_.empty());
    MEDIA_INFO_LOG("MovingPhotoRecorderTaskManager::DrainImage taskList size: %{public}zu", taskList_.size());
    for (auto& task : taskList_) {
        CHECK_EXECUTE(task, task->DrainImage(videoBufferWrapper));
    }
}

void MovingPhotoRecorderTaskManager::EncodeBuffer(sptr<VideoBufferWrapper> videoBufferWrapper)
{
    auto engineContext = GetEngineContext();
    CHECK_RETURN_ELOG(engineContext == nullptr, "engineContext is nullptr");
    auto videoEncoderFilter = engineContext->GetVideoEncoderFilter();
    CHECK_RETURN_ELOG(videoEncoderFilter == nullptr, "videoEncoderFilter is nullptr");
    auto thisPtr = wptr<MovingPhotoRecorderTaskManager>(this);
    videoBufferWrapper->SetReadyConvert();
    videoEncoderFilter->EncodeVideoBuffer(
        videoBufferWrapper, [thisPtr](sptr<VideoBufferWrapper> buffer, bool encodeResult) {
        MEDIA_DEBUG_LOG("EncodeVideoBuffer EncodeCallback E");
        auto taskManager = thisPtr.promote();
        CHECK_EXECUTE(taskManager, thisPtr->OnBufferEncoded(buffer, encodeResult));
    });
}

bool MovingPhotoRecorderTaskManager::IsPhotoAssetSaved(int32_t taskId)
{
    return photoAssetMap_.find(taskId) != photoAssetMap_.end();
}

std::pair<int64_t, shared_ptr<PhotoAssetIntf>> MovingPhotoRecorderTaskManager::GetPhotoAsset(int32_t taskId)
{
    std::unique_lock<mutex> lock(photoAssetMutex_);
    auto it = photoAssetMap_.find(taskId);
    if (it == photoAssetMap_.end()) {
        auto thisPtr = wptr<MovingPhotoRecorderTaskManager>(this);
        bool waitResult = cvEmpty_.wait_for(lock, std::chrono::milliseconds(GET_FD_EXPIREATION_TIME),
            [thisPtr, taskId] { return thisPtr->IsPhotoAssetSaved(taskId); });
        CHECK_RETURN_RET(!waitResult || !IsPhotoAssetSaved(taskId), GetEmptyPair());
    }
    return photoAssetMap_[taskId];
}

void MovingPhotoRecorderTaskManager::OnBufferEncodedNoLock(
    sptr<VideoBufferWrapper> videoBufferWrapper, bool encodeResult)
{
    for (auto it = taskList_.begin(); it != taskList_.end();) {
        sptr<MovingPhotoRecorderTask> task = *it;
        if (task == nullptr) {
            it = taskList_.erase(it);
            continue;
        }
        task->OnBufferEncoded(videoBufferWrapper, encodeResult);
        if (task->IsNeedRemove()) {
            it  = taskList_.erase(it);
            MEDIA_INFO_LOG("RemoveTask taskId:%{public}d", task->GetTaskId());
        } else {
            it++;
        }
    }
}

void MovingPhotoRecorderTaskManager::OnBufferEncoded(sptr<VideoBufferWrapper> videoBufferWrapper, bool encodeResult)
{
    std::lock_guard<std::mutex> lock(mutex_);
    OnBufferEncodedNoLock(videoBufferWrapper, encodeResult);
}

void MovingPhotoRecorderTaskManager::GetChooseVideoBuffer(
    sptr<MovingPhotoRecorderTask> task, std::vector<sptr<VideoBufferWrapper>>& chosenVideoBuffers)
{
    constexpr uint32_t MAX_FRAME_COUNT = 90;
    constexpr size_t MIN_FRAME_RECORD_BUFFER_SIZE = 9;

    std::vector<sptr<VideoBufferWrapper>> bufferList;
    task->GetEncodedBufferList(bufferList);
    int64_t shutterTime = GetPhotoAsset(task->GetTaskId()).first;
    CHECK_RETURN_ELOG(bufferList.empty(), "bufferList is empty!");
    chosenVideoBuffers.clear();
    int64_t endTime;
    bool isFindEndTime = GetEndTime(task->GetTaskId(), endTime);
    int64_t clearVideoEndTime = shutterTime + postBufferDuration_;
    if (isFindEndTime && endTime >= shutterTime && endTime < clearVideoEndTime) {
        MEDIA_INFO_LOG("set deblur end time is %{public}" PRIu64, endTime);
        clearVideoEndTime = endTime;
    }

    MEDIA_INFO_LOG("GetChooseVideoBuffer captureId : %{public}d, shutterTime : %{public}" PRIu64 ", "
        "clearVideoEndTime : %{public}" PRIu64, task->GetCaptureId(), shutterTime, clearVideoEndTime);

    size_t idrIndex = FindIdrFrameIndex(task, bufferList, clearVideoEndTime, shutterTime);
    size_t frameCount = 0;
    for (size_t index = idrIndex; index < bufferList.size(); ++index) {
        auto frame = bufferList[index];
        int64_t timestamp = frame->GetTimestamp();
        if (timestamp <= clearVideoEndTime && frameCount < MAX_FRAME_COUNT) {
            chosenVideoBuffers.push_back(frame);
            ++frameCount;
        }
    }
    if (chosenVideoBuffers.size() < MIN_FRAME_RECORD_BUFFER_SIZE || !bufferList[idrIndex]->IsIDRFrame()) {
        IgnoreDeblur(bufferList, chosenVideoBuffers, shutterTime);
    }
    MEDIA_INFO_LOG("ChooseVideoBuffer with size %{public}zu", chosenVideoBuffers.size());

}

size_t MovingPhotoRecorderTaskManager::FindIdrFrameIndex(sptr<MovingPhotoRecorderTask> task,
    vector<sptr<VideoBufferWrapper>> bufferList, int64_t clearVideoEndTime, int64_t shutterTime)
{
    bool isDeblurStartTime = false;
    int32_t captureId = task->GetCaptureId();
    int64_t startTime;
    bool isFindStartTime = GetStartTime(task->GetTaskId(), startTime);
    int64_t clearVideoStartTime = shutterTime - preBufferDuration_;
    if (isFindStartTime && startTime <= shutterTime && startTime > clearVideoStartTime) {
        MEDIA_INFO_LOG("set deblur start time is %{public}" PRIu64, startTime);
        clearVideoStartTime = startTime;
        MEDIA_INFO_LOG("clearVideoEndTime is %{public}" PRIu64, NanosecToMicrosec(clearVideoEndTime));
        int64_t absoluteValue = abs(clearVideoEndTime - clearVideoStartTime);
        int64_t deblurThreshold = 264000000L;
        isDeblurStartTime = absoluteValue < deblurThreshold;
    }

    MEDIA_INFO_LOG("FindIdrFrameIndex captureId : %{public}d, clearVideoStartTime : %{public}" PRIu64,
        captureId, clearVideoStartTime);
    size_t idrIndex = bufferList.size();
    if (isDeblurStartTime) {
        for (size_t index = 0; index < bufferList.size(); ++index) {
            auto frame = bufferList[index];
            if (frame->IsIDRFrame() && frame->GetTimestamp() <= clearVideoStartTime) {
                MEDIA_INFO_LOG("FindIdrFrameIndex before start time");
                idrIndex = index;
            }
        }
    }
    if (idrIndex == bufferList.size()) {
        for (size_t index = 0; index < bufferList.size(); ++index) {
            auto frame = bufferList[index];
            if (frame->IsIDRFrame() && frame->GetTimestamp() >= clearVideoStartTime &&
                frame->GetTimestamp() < shutterTime) {
                MEDIA_INFO_LOG("FindIdrFrameIndex after start time");
                idrIndex = index;
                break;
            }
            idrIndex = 0;
        }
    }
    return idrIndex;
}

void MovingPhotoRecorderTaskManager::IgnoreDeblur(vector<sptr<VideoBufferWrapper>>& bufferList,
    vector<sptr<VideoBufferWrapper>> &choosedBufferList, int64_t shutterTime)
{
    MEDIA_INFO_LOG("IgnoreDeblur enter");
    choosedBufferList.clear();
    if (!bufferList.empty()) {
        auto it = find_if(bufferList.begin(), bufferList.end(),
            [](const sptr<VideoBufferWrapper>& frame) { return frame->IsIDRFrame(); });
        while (it != bufferList.end()) {
            choosedBufferList.emplace_back(*it);
            ++it;
        }
    }
}

void MovingPhotoRecorderTaskManager::InsertPhotoAsset(
    int64_t timestamp, shared_ptr<PhotoAssetIntf> photoAssetProxy, int32_t taskId)
{
    MEDIA_INFO_LOG("InsertPhotoAsset taskId: %{public}d", taskId);
    std::lock_guard<mutex> lock(photoAssetMutex_);
    photoAssetMap_.insert(std::make_pair(taskId, std::make_pair(timestamp, photoAssetProxy)));
    cvEmpty_.notify_all();
}

bool MovingPhotoRecorderTaskManager::GetStartTime(int32_t taskId, int64_t& startTime)
{
    return startTimeMap_.Find(taskId, startTime);
}

bool MovingPhotoRecorderTaskManager::GetEndTime(int32_t taskId, int64_t& endTime)
{
    return endTimeMap_.Find(taskId, endTime);
}

bool MovingPhotoRecorderTaskManager::GetDeferredVideoEnhanceFlag(int32_t taskId, uint32_t& flag)
{
    return deferredVideoEnhanceFlagMap_.Find(taskId, flag);
}

bool MovingPhotoRecorderTaskManager::GetVideoId(int32_t taskId, std::string& videoId)
{
    return videoIdMap_.Find(taskId, videoId);
}

void MovingPhotoRecorderTaskManager::SetVideoBufferDuration(int64_t preBufferDuration, uint32_t postBufferDuration)
{
    preBufferDuration_ = preBufferDuration;
    postBufferDuration_ = postBufferDuration;
    MEDIA_INFO_LOG("SetVideoBufferDuration success, preBufferDuration_ : %{public}" PRId64 
        ", postBufferDuration_ : %{public}" PRId64, preBufferDuration_, postBufferDuration_);
}

void MovingPhotoRecorderTaskManager::InsertStartTime(int32_t taskId, int64_t startTime)
{
    bool ret = startTimeMap_.Insert(taskId, startTime);
    CHECK_RETURN(!ret);
    MEDIA_INFO_LOG("InsertStartTime success, taskId : %{public}d, startTime : %{public}" PRId64, taskId, startTime);
}

void MovingPhotoRecorderTaskManager::InsertEndTime(int32_t taskId, int64_t endTime)
{
    bool ret = endTimeMap_.Insert(taskId, endTime);
    CHECK_RETURN(!ret);
    MEDIA_INFO_LOG("InsertEndTime success, taskId : %{public}d, endTime : %{public}" PRId64, taskId, endTime);
}

void MovingPhotoRecorderTaskManager::InsertDeferredVideoEnhanceFlag(int32_t taskId, uint32_t flag)
{
    bool ret = deferredVideoEnhanceFlagMap_.Insert(taskId, flag);
    CHECK_RETURN(!ret);
    MEDIA_INFO_LOG("InsertDeferredVideoEnhanceFlag success, taskId : %{public}d, flag : %{public}u", taskId, flag);
}

void MovingPhotoRecorderTaskManager::InsertVideoId(int32_t taskId, std::string videoId)
{
    bool ret = videoIdMap_.Insert(taskId, videoId);
    CHECK_RETURN(!ret);
    MEDIA_INFO_LOG("InsertVideoId success, taskId : %{public}d, videoId : %{public}s", taskId, videoId.c_str());
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP