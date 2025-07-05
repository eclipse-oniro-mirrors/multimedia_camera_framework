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
static std::string g_lastDisplayName = "";
static int32_t g_saveIndex = 0;
std::string CreateDisplayName(const std::string& suffix)
{
    struct tm currentTime;
    std::string formattedTime = "";
    if (GetSystemCurrentTime(&currentTime)) {
        std::stringstream ss;
        ss << prefix << std::setw(yearWidth) << std::setfill(placeholder) << currentTime.tm_year + startYear
           << std::setw(otherWidth) << std::setfill(placeholder) << (currentTime.tm_mon + 1)
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_mday
           << connector << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_hour
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_min
           << std::setw(otherWidth) << std::setfill(placeholder) << currentTime.tm_sec;
        formattedTime = ss.str();
    } else {
        MEDIA_ERR_LOG("Failed to get current time.");
    }
    if (g_lastDisplayName == formattedTime) {
        g_saveIndex++;
        formattedTime = formattedTime + connector + std::to_string(g_saveIndex);
        MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
        return formattedTime;
    }
    g_lastDisplayName = formattedTime;
    g_saveIndex = 0;
    MEDIA_INFO_LOG("CreateDisplayName is %{private}s", formattedTime.c_str());
    return formattedTime;
}

MovingPhotoProxy::MovingPhotoProxy(
    std::shared_ptr<Dynamiclib> movingPhotoLib, sptr<MovingPhotoIntf> movingPhotoIntf)
    : movingPhotoLib_(movingPhotoLib), movingPhotoIntf_(movingPhotoIntf)
{
    MEDIA_DEBUG_LOG("MovingPhotoProxy constructor");
    CHECK_ERROR_RETURN_LOG(movingPhotoLib_ == nullptr, "movingPhotoLib_ is nullptr");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
}

MovingPhotoProxy::~MovingPhotoProxy()
{
    MEDIA_DEBUG_LOG("MovingPhotoProxy destructor");
    CHECK_EXECUTE(movingPhotoIntf_ != nullptr, movingPhotoIntf_ = nullptr);
    CHECK_EXECUTE(movingPhotoLib_ != nullptr, movingPhotoLib_ = nullptr);
    MEDIA_DEBUG_LOG("MovingPhotoProxy destructor end");
}

void MovingPhotoProxy::Release()
{
    CameraDynamicLoader::FreeDynamicLibDelayed(MOVING_PHOTO_SO, LIB_DELAYED_UNLOAD_TIME);
}

sptr<MovingPhotoProxy> MovingPhotoProxy::CreateMovingPhotoProxy()
{
    std::shared_ptr<Dynamiclib> dynamiclib = CameraDynamicLoader::GetDynamiclib(MOVING_PHOTO_SO);
    CHECK_ERROR_RETURN_RET_LOG(dynamiclib == nullptr, nullptr, "Failed to load moving photo library");

    CreateMovingPhotoIntf createMovingPhotoIntf =
        (CreateMovingPhotoIntf)dynamiclib->GetFunction("createMovingPhotoIntf");
    CHECK_ERROR_RETURN_RET_LOG(
        createMovingPhotoIntf == nullptr, nullptr, "Failed to get createMovingPhotoIntf function");

    MovingPhotoIntf* movingPhotoIntf = createMovingPhotoIntf();
    CHECK_ERROR_RETURN_RET_LOG(
        movingPhotoIntf == nullptr, nullptr, "Failed to create MovingPhotoIntf instance");

    sptr<MovingPhotoProxy> movingPhotoProxy =
        new MovingPhotoProxy(dynamiclib, sptr<MovingPhotoIntf>(movingPhotoIntf));
    return movingPhotoProxy;
}

void MovingPhotoProxy::CreateCameraServerProxy()
{
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->CreateCameraServerProxy();
    MEDIA_DEBUG_LOG("CreateCameraServerProxy success");
}

void MovingPhotoProxy::ReadFromParcel(MessageParcel& parcel)
{
    MEDIA_DEBUG_LOG("ReadFromParcel start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->ReadFromParcel(parcel);
    MEDIA_DEBUG_LOG("ReadFromParcel success");
}

void MovingPhotoProxy::SetDisplayName(const std::string& displayName)
{
    MEDIA_DEBUG_LOG("SetDisplayName start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetDisplayName(displayName);
    MEDIA_DEBUG_LOG("SetDisplayName success");
}

int32_t MovingPhotoProxy::GetCaptureId() const
{
    MEDIA_DEBUG_LOG("GetCaptureId start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, 0, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->GetCaptureId();
}

void MovingPhotoProxy::SetShootingMode(int32_t mode)
{
    MEDIA_DEBUG_LOG("SetShootingMode start, mode: %{public}d", mode);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetShootingMode(mode);
    MEDIA_DEBUG_LOG("SetShootingMode success");
}

std::string MovingPhotoProxy::GetPhotoId() const
{
    MEDIA_DEBUG_LOG("GetPhotoId start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, "", "movingPhotoIntf_ is nullptr");
    return  movingPhotoIntf_->GetPhotoId();
}

int32_t MovingPhotoProxy::GetBurstSeqId() const
{
    MEDIA_DEBUG_LOG("GetBurstSeqId start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, -1, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->GetBurstSeqId();
}

void MovingPhotoProxy::SetBurstInfo(const std::string& burstKey, bool isCoverPhoto)
{
    MEDIA_DEBUG_LOG("SetBurstInfo start, burstKey: %{public}s, isCoverPhoto: %{public}d",
        burstKey.c_str(), isCoverPhoto);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetBurstInfo(burstKey, isCoverPhoto);
    MEDIA_DEBUG_LOG("SetBurstInfo success");
}

std::string MovingPhotoProxy::GetTitle() const
{
    MEDIA_DEBUG_LOG("GetTitle start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, "", "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->GetTitle();
}

std::string MovingPhotoProxy::GetExtension() const
{
    MEDIA_DEBUG_LOG("GetExtension start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, "", "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->GetExtension();
}

PhotoQuality MovingPhotoProxy::GetPhotoQuality() const
{
    MEDIA_DEBUG_LOG("GetPhotoQuality start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, PhotoQuality::LOW,
        "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->GetPhotoQuality();
}

int32_t MovingPhotoProxy::GetFormat() const
{
    MEDIA_DEBUG_LOG("GetFormat start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, 0, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->GetFormat();
}

void MovingPhotoProxy::SetStageVideoTaskStatus(uint8_t status)
{
    MEDIA_DEBUG_LOG("SetStageVideoTaskStatus start, status: %{public}d", status);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetStageVideoTaskStatus(status);
    MEDIA_DEBUG_LOG("SetStageVideoTaskStatus success");
}

void MovingPhotoProxy::CreateAvcodecTaskManager(VideoCodecType type, int32_t colorSpace)
{
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager start, type: %{public}d, colorSpace: %{public}d",
        static_cast<int32_t>(type), colorSpace);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->CreateAvcodecTaskManager(type, colorSpace);
    MEDIA_DEBUG_LOG("CreateAvcodecTaskManager success");
}

bool MovingPhotoProxy::IsTaskManagerExist()
{
    MEDIA_DEBUG_LOG("IsTaskManagerExist start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, false, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->IsTaskManagerExist();
}

void MovingPhotoProxy::ReleaseTaskManager()
{
    MEDIA_DEBUG_LOG("ReleaseTaskManager start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->ReleaseTaskManager();
}

void MovingPhotoProxy::SetVideoBufferDuration(uint32_t preBufferCount, uint32_t postBufferCount)
{
    MEDIA_DEBUG_LOG("SetVideoBufferDuration start, preBufferCount: %{public}u, postBufferCount: %{public}u",
        preBufferCount, postBufferCount);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetVideoBufferDuration(preBufferCount, postBufferCount);
    MEDIA_DEBUG_LOG("SetVideoBufferDuration success");
}

void MovingPhotoProxy::SetVideoFd(int64_t timestamp, std::shared_ptr<PhotoAssetIntf> photoAssetProxy,
    int32_t captureId)
{
    MEDIA_DEBUG_LOG("SetVideoFd start, timestamp: %{public}" PRIu64 ", captureId: %{public}d",
        timestamp, captureId);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetVideoFd(timestamp, photoAssetProxy, captureId);
    MEDIA_DEBUG_LOG("SetVideoFd success");
}

void MovingPhotoProxy::SetLatitude(double latitude)
{
    MEDIA_DEBUG_LOG("SetLatitude start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "CameraServerPhotoProxy not created");
    movingPhotoIntf_->SetLatitude(latitude);
    MEDIA_DEBUG_LOG("SetLatitude success");
}

void MovingPhotoProxy::SetLongitude(double longitude)
{
    MEDIA_DEBUG_LOG("SetLongitude start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "CameraServerPhotoProxy not created");
    movingPhotoIntf_->SetLongitude(longitude);
    MEDIA_DEBUG_LOG("SetLongitude success");
}

void MovingPhotoProxy::GetServerPhotoProxyInfo(sptr<OHOS::SurfaceBuffer>& surfaceBuffer)
{
    MEDIA_DEBUG_LOG("GetServerPhotoProxyInfo start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->GetServerPhotoProxyInfo(surfaceBuffer);
    MEDIA_DEBUG_LOG("GetServerPhotoProxyInfo success");
}

void MovingPhotoProxy::SetFormat(int32_t format)
{
    MEDIA_DEBUG_LOG("SetFormat start, format: %{public}d", format);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetFormat(format);
    MEDIA_DEBUG_LOG("SetFormat success");
}

void MovingPhotoProxy::SetImageFormat(int32_t imageFormat)
{
    MEDIA_DEBUG_LOG("SetImageFormat start, imageFormat: %{public}d", imageFormat);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetImageFormat(imageFormat);
    MEDIA_DEBUG_LOG("SetImageFormat success");
}

void MovingPhotoProxy::SetIsVideo(bool isVideo)
{
    MEDIA_DEBUG_LOG("SetIsVideo start, isVideo: %{public}d", isVideo);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SetIsVideo(isVideo);
    MEDIA_DEBUG_LOG("SetIsVideo success");
}

void MovingPhotoProxy::SubmitTask(std::function<void()> task)
{
    MEDIA_DEBUG_LOG("SubmitTask start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->SubmitTask(task);
    MEDIA_DEBUG_LOG("SubmitTask success");
}

void MovingPhotoProxy::EncodeVideoBuffer(sptr<FrameRecord> frameRecord, CacheCbFunc cacheCallback)
{
    MEDIA_DEBUG_LOG("EncodeVideoBuffer start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->EncodeVideoBuffer(frameRecord, cacheCallback);
    MEDIA_DEBUG_LOG("EncodeVideoBuffer success");
}

void MovingPhotoProxy::DoMuxerVideo(std::vector<sptr<FrameRecord>> frameRecords, uint64_t taskName, int32_t rotation,
    int32_t captureId)
{
    MEDIA_DEBUG_LOG("DoMuxerVideo start, taskName: %{public}" PRIu64 ", rotation: %{public}d, captureId: %{public}d",
        taskName, rotation, captureId);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->DoMuxerVideo(frameRecords, taskName, rotation, captureId);
    MEDIA_DEBUG_LOG("DoMuxerVideo success");
}

bool MovingPhotoProxy::isEmptyVideoFdMap()
{
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, true, "movingPhotoIntf_ is nullptr");
    bool result = movingPhotoIntf_->isEmptyVideoFdMap();
    MEDIA_DEBUG_LOG("isEmptyVideoFdMap success, result: %{public}d", result);
    return result;
}

void MovingPhotoProxy::TaskManagerInsertStartTime(int32_t captureId, int64_t startTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertStartTime start, captureId: %{public}d, startTimeStamp: %{public}" PRIu64,
        captureId, startTimeStamp);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->TaskManagerInsertStartTime(captureId, startTimeStamp);
    MEDIA_DEBUG_LOG("TaskManagerInsertStartTime success");
    return;
}

void MovingPhotoProxy::TaskManagerInsertEndTime(int32_t captureId, int64_t endTimeStamp)
{
    MEDIA_DEBUG_LOG("TaskManagerInsertEndTime start, captureId: %{public}d, endTimeStamp: %{public}" PRIu64,
        captureId, endTimeStamp);
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->TaskManagerInsertEndTime(captureId, endTimeStamp);
    MEDIA_DEBUG_LOG("TaskManagerInsertEndTime success");
    return;
}

void MovingPhotoProxy::CreateAudioSession()
{
    MEDIA_DEBUG_LOG("CreateAudioSession start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->CreateAudioSession();
    MEDIA_DEBUG_LOG("CreateAudioSession success");
}

bool MovingPhotoProxy::IsAudioSessionExist()
{
    MEDIA_DEBUG_LOG("IsAudioSessionExist start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, false, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->IsAudioSessionExist();
}

bool MovingPhotoProxy::StartAudioCapture()
{
    MEDIA_DEBUG_LOG("StartAudioCapture start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, false, "movingPhotoIntf_ is nullptr");
    bool result = movingPhotoIntf_->StartAudioCapture();
    MEDIA_DEBUG_LOG("StartAudioCapture success, result: %{public}d", result);
    return result;
}

void MovingPhotoProxy::StopAudioCapture()
{
    MEDIA_DEBUG_LOG("StopAudioCapture start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->StopAudioCapture();
    MEDIA_DEBUG_LOG("StopAudioCapture success");
}

void MovingPhotoProxy::CreateMovingPhotoVideoCache()
{
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->CreateMovingPhotoVideoCache();
    MEDIA_DEBUG_LOG("CreateMovingPhotoVideoCache success");
}

bool MovingPhotoProxy::IsVideoCacheExist()
{
    MEDIA_DEBUG_LOG("IsVideoCacheExist start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, false, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->IsVideoCacheExist();
}

void MovingPhotoProxy::ReleaseVideoCache()
{
    MEDIA_DEBUG_LOG("ReleaseVideoCache start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->ReleaseVideoCache();
}

void MovingPhotoProxy::OnDrainFrameRecord(sptr<FrameRecord> frame)
{
    MEDIA_DEBUG_LOG("OnDrainFrameRecord start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->OnDrainFrameRecord(frame);
    MEDIA_DEBUG_LOG("OnDrainFrameRecord success");
}

void MovingPhotoProxy::GetFrameCachedResult(std::vector<sptr<FrameRecord>> frameRecords,
    uint64_t taskName, int32_t rotation, int32_t captureId)
{
    MEDIA_DEBUG_LOG("GetFrameCachedResult start");
    CHECK_ERROR_RETURN_LOG(movingPhotoIntf_ == nullptr, "movingPhotoIntf_ is nullptr");
    movingPhotoIntf_->GetFrameCachedResult(frameRecords, taskName, rotation, captureId);
    MEDIA_DEBUG_LOG("GetFrameCachedResult success");
}
sptr<PhotoProxy> MovingPhotoProxy::GetCameraServerPhotoProxy() const
{
    MEDIA_DEBUG_LOG("GetCameraServerPhotoProxy start");
    CHECK_ERROR_RETURN_RET_LOG(movingPhotoIntf_ == nullptr, nullptr, "movingPhotoIntf_ is nullptr");
    return movingPhotoIntf_->GetCameraServerPhotoProxy();
}

} // namespace CameraStandard
} // namespace OHOS