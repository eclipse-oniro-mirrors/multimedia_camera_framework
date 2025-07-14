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
#include <iomanip>
#include "moving_photo_proxy.h"
#include "utils/camera_log.h"
#include "datetime_ex.h"

namespace OHOS {
namespace CameraStandard {
typedef MovingPhotoIntf* (*CreateMovingPhotoIntf)();

MovingPhotoProxy::MovingPhotoProxy(
    std::shared_ptr<Dynamiclib> movingPhotoLib, sptr<MovingPhotoIntf> movingPhotoIntf)
    : movingPhotoLib_(movingPhotoLib), movingPhotoIntf_(movingPhotoIntf)
{
    MEDIA_DEBUG_LOG("MovingPhotoProxy constructor");
    CHECK_RETURN_ELOG(movingPhotoLib_ == nullptr, "movingPhotoLib_ is nullptr");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
}

MovingPhotoProxy::~MovingPhotoProxy()
{
    MEDIA_DEBUG_LOG("MovingPhotoProxy destructor");
}

void MovingPhotoProxy::Release()
{
    CameraDynamicLoader::FreeDynamicLibDelayed(MOVING_PHOTO_SO, LIB_DELAYED_UNLOAD_TIME);
}

sptr<MovingPhotoProxy> MovingPhotoProxy::CreateMovingPhotoProxy()
{
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(MOVING_PHOTO_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "Failed to load moving photo library");

    CreateMovingPhotoIntf createMovingPhotoIntf =
        (CreateMovingPhotoIntf)dynamiclib->GetFunction("createMovingPhotoIntf");
    CHECK_RETURN_RET_ELOG(
        createMovingPhotoIntf == nullptr, nullptr, "Failed to get createMovingPhotoIntf function");

    MovingPhotoIntf* movingPhotoIntf = createMovingPhotoIntf();
    CHECK_RETURN_RET_ELOG(
        movingPhotoIntf == nullptr, nullptr, "Failed to create MovingPhotoIntf instance");

    sptr<MovingPhotoProxy> movingPhotoProxy =
        new MovingPhotoProxy(dynamiclib, sptr<MovingPhotoIntf>(movingPhotoIntf));
    return movingPhotoProxy;
}

void MovingPhotoProxy::CreateAvcodecTaskManager(VideoCodecType type, int32_t colorSpace)
{
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager start, type: %{public}d, colorSpace: %{public}d",
        static_cast<int32_t>(type), colorSpace);
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->CreateAvcodecTaskManager(type, colorSpace);
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager success");
}

bool MovingPhotoProxy::IsTaskManagerExist()
{
    MEDIA_DEBUG_LOG("IsTaskManagerExist start");
    CHECK_RETURN_RET_ELOG(movingPhotoIntf_ == nullptr, false, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->IsTaskManagerExist();
}

void MovingPhotoProxy::ReleaseTaskManager()
{
    MEDIA_DEBUG_LOG("ReleaseTaskManager start");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->ReleaseTaskManager();
}

void MovingPhotoProxy::SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount)
{
    MEDIA_DEBUG_LOG("SetVideoBufferDuration start, preBufferCount: %{public}u, postBufferCount: %{public}u",
        preBufferCount, postBufferCount);
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetVideoBufferDuration(preBufferCount, postBufferCount);
    MEDIA_DEBUG_LOG("SetVideoBufferDuration success");
}

void MovingPhotoProxy::SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy,
    int32_t captureId)
{
    MEDIA_DEBUG_LOG("SetVideoFd start, timestamp: %{public}" PRIu64 ", captureId: %{public}d",
        timestamp, captureId);
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetVideoFd(timestamp, photoAssetProxy, captureId);
    MEDIA_DEBUG_LOG("SetVideoFd success");
}

void MovingPhotoProxy::SubmitTask(std::function<void()> task)
{
    MEDIA_DEBUG_LOG("SubmitTask start");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SubmitTask(task);
    MEDIA_DEBUG_LOG("SubmitTask success");
}

void MovingPhotoProxy::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    MEDIA_DEBUG_LOG("EncodeVideoBuffer start");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->EncodeVideoBuffer(frameRecord, cacheCallback);
    MEDIA_DEBUG_LOG("EncodeVideoBuffer success");
}

void MovingPhotoProxy::DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t rotation,
    int32_t captureId)
{
    MEDIA_DEBUG_LOG("DoMuxerVideo start, taskName: %{public}" PRIu64 ", rotation: %{public}d, captureId: %{public}d",
        taskName, rotation, captureId);
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
    MEDIA_DEBUG_LOG("DoMuxerVideo success");
}

bool MovingPhotoProxy::isEmptyVideoFdMap()
{
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap start");
    CHECK_RETURN_RET_ELOG(movingPhotoIntf_ == nullptr, true, "movingPhotoIntf_ is nullptr");
    bool result = movingPhotoIntf_->isEmptyVideoFdMap();
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap success, result: %{public}d", result);
    return result;
}

void MovingPhotoProxy::TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertStartTime start, captureId: %{public}d, startTimeStamp: %{public}" PRIu64,
        captureId, startTimeStamp);
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->TaskManagerInsertStartTime(captureId, startTimeStamp);
    MEDIA_DEBUG_LOG("TaskManagerInsertStartTime success");
    return;
}

void MovingPhotoProxy::TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertEndTime start, captureId: %{public}d, endTimeStamp: %{public}" PRIu64,
        captureId, endTimeStamp);
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->TaskManagerInsertEndTime(captureId, endTimeStamp);
    MEDIA_DEBUG_LOG("TaskManagerInsertEndTime success");
    return;
}

void MovingPhotoProxy::CreateAudioSession()
{
    MEDIA_DEBUG_LOG("CreateAudioSession start");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->CreateAudioSession();
    MEDIA_DEBUG_LOG("CreateAudioSession success");
}

bool MovingPhotoProxy::IsAudioSessionExist()
{
    MEDIA_DEBUG_LOG("IsAudioSessionExist start");
    CHECK_RETURN_RET_ELOG(movingPhotoIntf_ == nullptr, false, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->IsAudioSessionExist();
}

bool MovingPhotoProxy::StartAudioCapture()
{
    MEDIA_DEBUG_LOG("StartAudioCapture start");
    CHECK_RETURN_RET_ELOG(movingPhotoIntf_ == nullptr, false, "movingPhotoIntf_ is nullptr");
    bool result = movingPhotoIntf_->StartAudioCapture();
    MEDIA_DEBUG_LOG("StartAudioCapture success, result: %{public}d", result);
    return result;
}

void MovingPhotoProxy::StopAudioCapture()
{
    MEDIA_DEBUG_LOG("StopAudioCapture start");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->StopAudioCapture();
    MEDIA_DEBUG_LOG("StopAudioCapture success");
}

void MovingPhotoProxy::CreateMovingPhotoVideoCache()
{
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache start");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->CreateMovingPhotoVideoCache();
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache success");
}

bool MovingPhotoProxy::IsVideoCacheExist()
{
    MEDIA_DEBUG_LOG("IsVideoCacheExist start");
    CHECK_RETURN_RET_ELOG(movingPhotoIntf_ == nullptr, false, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->IsVideoCacheExist();
}

void MovingPhotoProxy::ReleaseVideoCache()
{
    MEDIA_DEBUG_LOG("ReleaseVideoCache start");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->ReleaseVideoCache();
}

void MovingPhotoProxy::OnDrainFrameRecord(sptr<FrameRecord> frame)
{
    MEDIA_DEBUG_LOG("OnDrainFrameRecord start");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->OnDrainFrameRecord(frame);
    MEDIA_DEBUG_LOG("OnDrainFrameRecord success");
}

void MovingPhotoProxy::GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
    uint64_t taskName, int32_t rotation, int32_t captureId)
{
    MEDIA_DEBUG_LOG("GetFrameCachedResult start");
    CHECK_RETURN_ELOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->GetFrameCachedResult(frameRecords, taskName, rotation, captureId);
    MEDIA_DEBUG_LOG("GetFrameCachedResult success");
}
} // namespace CameraStandard
} // namespace OHOS