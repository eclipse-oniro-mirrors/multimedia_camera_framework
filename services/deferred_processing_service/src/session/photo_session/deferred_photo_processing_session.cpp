/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "deferred_photo_processing_session.h"

#include "dp_utils.h"
#include "dps.h"
#include "dps_event_report.h"
#include "photo_command.h"
#include "sync_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredPhotoProcessingSession::DeferredPhotoProcessingSession(const int32_t userId)
    : userId_(userId)
{
    DP_DEBUG_LOG("entered. userId: %{public}d", userId_);
}

DeferredPhotoProcessingSession::~DeferredPhotoProcessingSession()
{
    DP_DEBUG_LOG("entered.");
    imageIds_.clear();
}

int32_t DeferredPhotoProcessingSession::BeginSynchronize()
{
    DP_INFO_LOG("DPS_PHOTO: BeginSynchronize.");
    std::lock_guard<std::mutex> lock(mutex_);
    inSync_.store(true);
    const std::string imageId = "default";
    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_BEGIN_SYNCHRONIZE);
    return DP_OK;
}

int32_t DeferredPhotoProcessingSession::EndSynchronize()
{
    DP_INFO_LOG("DPS_PHOTO: EndSynchronize photo job num: %{public}d", static_cast<int32_t>(imageIds_.size()));
    std::lock_guard<std::mutex> lock(mutex_);
    if (inSync_.load()) {
        auto ret = DPS_SendCommand<PhotoSyncCommand>(userId_, imageIds_);
        inSync_.store(false);
        imageIds_.clear();
        DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, ret, "photo synchronize failed, ret: %{public}d", ret);
        
        const std::string imageId = "default";
        ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_END_SYNCHRONIZE);
    }
    return DP_OK;
}

int32_t DeferredPhotoProcessingSession::AddImage(const std::string& imageId, DpsMetadata& metadata, bool discardable)
{
    if (inSync_.load()) {
        std::lock_guard<std::mutex> lock(mutex_);
        DP_INFO_LOG("AddImage error, inSync!");
        auto info = std::make_shared<PhotoInfo>(discardable, metadata);
        imageIds_.emplace(imageId, info);
    } else {
        auto ret = DPS_SendCommand<AddPhotoCommand>(userId_, imageId, metadata, discardable);
        DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK,
            "DPS_PHOTO: add imageId: %{public}s failed. ret: %{public}d", imageId.c_str(), ret);
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE);
    return DP_OK;
}

int32_t DeferredPhotoProcessingSession::RemoveImage(const std::string& imageId, bool restorable)
{
    if (inSync_.load()) {
        DP_INFO_LOG("RemoveImage error, inSync!");
    } else {
        auto ret = DPS_SendCommand<RemovePhotoCommand>(userId_, imageId, restorable);
        DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK,
            "DPS_PHOTO: remove imageId: %{public}s failed. ret: %{public}d", imageId.c_str(), ret);
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_REMOVE_IMAGE);
    return DP_OK;
}

int32_t DeferredPhotoProcessingSession::RestoreImage(const std::string& imageId)
{
    if (inSync_.load()) {
        DP_INFO_LOG("RestoreImage error, inSync!");
    } else {
        auto ret = DPS_SendCommand<RestorePhotoCommand>(userId_, imageId);
        DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK,
            "DPS_PHOTO: restore imageId: %{public}s failed. ret: %{public}u", imageId.c_str(), ret);
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_RESTORE_IMAGE);
    return DP_OK;
}

int32_t DeferredPhotoProcessingSession::ProcessImage(const std::string& appName, const std::string& imageId)
{
    if (inSync_) {
        DP_INFO_LOG("ProcessImage error, inSync!");
    } else {
        auto ret = DPS_SendCommand<ProcessPhotoCommand>(userId_, imageId, appName);
        DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK,
            "DPS_PHOTO: process imageId: %{public}s failed. ret: %{public}u", imageId.c_str(), ret);
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_PROCESS_IMAGE);
    return 0;
}

int32_t DeferredPhotoProcessingSession::CancelProcessImage(const std::string& imageId)
{
    if (inSync_) {
        DP_INFO_LOG("CancelProcessImage error, inSync!");
    } else {
        auto ret = DPS_SendCommand<CancelProcessPhotoCommand>(userId_, imageId);
        DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK,
            "DPS_PHOTO: cance process imageId: %{public}s failed. ret: %{public}u", imageId.c_str(), ret);
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_CANCEL_PROCESS_IMAGE);
    return 0;
}

void DeferredPhotoProcessingSession::ReportEvent(const std::string& imageId, int32_t event)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.operatorStage = static_cast<uint32_t>(event);
    dpsEventInfo.imageId = imageId;
    dpsEventInfo.userId = userId_;
    uint64_t beginTime = GetTimestampMilli();
    switch (static_cast<int32_t>(event)) {
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_BEGIN_SYNCHRONIZE): {
            dpsEventInfo.synchronizeTimeBeginTime = beginTime;
            DPSEventReport::GetInstance().ReportOperateImage(imageId, userId_, dpsEventInfo);
            break;
        }
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_END_SYNCHRONIZE): {
            dpsEventInfo.synchronizeTimeEndTime = beginTime;
            DPSEventReport::GetInstance().ReportOperateImage(imageId, userId_, dpsEventInfo);
            break;
        }
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE): {
            dpsEventInfo.dispatchTimeBeginTime = beginTime;
            break;
        }
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_REMOVE_IMAGE): {
            dpsEventInfo.removeTimeBeginTime = beginTime;
            break;
        }
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_RESTORE_IMAGE): {
            dpsEventInfo.restoreTimeBeginTime = beginTime;
            break;
        }
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_PROCESS_IMAGE): {
            dpsEventInfo.processTimeBeginTime = beginTime;
            break;
        }
    }

    if (event == DeferredProcessingServiceInterfaceCode::DPS_BEGIN_SYNCHRONIZE) {
        return;
    } else if (event == DeferredProcessingServiceInterfaceCode::DPS_END_SYNCHRONIZE) {
        DPSEventReport::GetInstance().ReportImageProcessResult(imageId, userId_);
    } else {
        DPSEventReport::GetInstance().SetEventInfo(dpsEventInfo);
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS