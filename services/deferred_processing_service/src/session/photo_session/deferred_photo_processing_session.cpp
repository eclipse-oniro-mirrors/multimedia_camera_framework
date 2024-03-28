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

#include <vector>
#include <shared_mutex>
#include <iostream>
#include <set>
#include <memory>
#include "dp_log.h"
#include "basic_definitions.h"
#include "deferred_photo_processing_session.h"
#include "dps_event_report.h"
#include "steady_clock.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredPhotoProcessingSession::DeferredPhotoProcessingSession(int userId,
    std::shared_ptr<DeferredPhotoProcessor> processor, TaskManager* taskManager,
    sptr<IDeferredPhotoProcessingSessionCallback> callback)
    : userId_(userId),
      inSync_(false),
      processor_(processor),
      taskManager_(taskManager),
      callback_(callback),
      imageIds_()
{
    DP_DEBUG_LOG("DeferredPhotoProcessingSession enter.");
    (void)(userId_);
}

DeferredPhotoProcessingSession::~DeferredPhotoProcessingSession()
{
    DP_DEBUG_LOG("~DeferredPhotoProcessingSession enter.");
    processor_ = nullptr;
    taskManager_ = nullptr;
}

int32_t DeferredPhotoProcessingSession::BeginSynchronize()
{
    DP_INFO_LOG("BeginSynchronize enter.");
    inSync_ = true;
    const std::string imageId = "default";
    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_BEGIN_SYNCHRONIZE);
    return 0;
}

int32_t DeferredPhotoProcessingSession::EndSynchronize()
{
    DP_INFO_LOG("EndSynchronize enter.");

    inSync_ = false;
    std::vector<std::string> pendingImages;
    bool isSuccess = processor_->GetPendingImages(pendingImages);
    if (!isSuccess) {
        for (auto it = imageIds_.begin(); it != imageIds_.end();) {
            AddImage(it->first, it->second->metadata_, it->second->discardable_);
            it = imageIds_.erase(it);
        }
        const std::string imageId = "default";
        ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_END_SYNCHRONIZE);
        return 0;
    }
    std::set<std::string> hdiImageIds(pendingImages.begin(), pendingImages.end());
    for (auto it = imageIds_.begin(); it != imageIds_.end();) {
        if (hdiImageIds.count(it->first) != 0) {
            hdiImageIds.erase(it->first);
            AddImage(it->first, it->second->metadata_, it->second->discardable_);
            it = imageIds_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto& imageId : hdiImageIds) {
        RemoveImage(imageId, false);
    }
    for (auto it = imageIds_.begin(); it != imageIds_.end();) {
        callback_->OnError(it->first, ErrorCode::ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
        ++it;
    }
    imageIds_.clear();
    hdiImageIds.clear();
    const std::string imageId = "default";
    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_END_SYNCHRONIZE);
    return 0;
}

int32_t DeferredPhotoProcessingSession::AddImage(const std::string imageId, DpsMetadata& metadata, bool discardable)
{
    if (inSync_) {
        DP_INFO_LOG("AddImage error, inSync!");
        imageIds_[imageId] = std::make_shared<PhotoInfo>(discardable, metadata);
    } else {
        DP_INFO_LOG("AddImage enter.");
        taskManager_->SubmitTask([this, imageId, discardable, metadata]() {
            processor_->AddImage(imageId, discardable, const_cast<DpsMetadata&>(metadata));
        });
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE);
    return 0;
}

int32_t DeferredPhotoProcessingSession::RemoveImage(const std::string imageId, bool restorable)
{
    if (inSync_) {
        DP_INFO_LOG("RemoveImage error, inSync!");
    } else {
        DP_INFO_LOG("RemoveImage enter.");
        taskManager_->SubmitTask([this, imageId, restorable]() {
            processor_->RemoveImage(imageId, restorable);
        });
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_REMOVE_IMAGE);
    return 0;
}

int32_t DeferredPhotoProcessingSession::RestoreImage(const std::string imageId)
{
    if (inSync_) {
        DP_INFO_LOG("RestoreImage error, inSync!");
    } else {
        DP_INFO_LOG("RestoreImage enter.");
        taskManager_->SubmitTask([this, imageId]() {
            processor_->RestoreImage(imageId);
        });
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_RESTORE_IMAGE);
    return 0;
}

int32_t DeferredPhotoProcessingSession::ProcessImage(const std::string appName, const std::string imageId)
{
    if (inSync_) {
        DP_INFO_LOG("ProcessImage error, inSync!");
    } else {
        DP_INFO_LOG("ProcessImage enter.");
        taskManager_->SubmitTask([this, appName, imageId]() {
            processor_->ProcessImage(appName, imageId);
        });
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_PROCESS_IMAGE);
    return 0;
}

int32_t DeferredPhotoProcessingSession::CancelProcessImage(const std::string imageId)
{
    if (inSync_) {
        DP_INFO_LOG("CancelProcessImage error, inSync!");
    } else {
        DP_INFO_LOG("CancelProcessImage enter.");
        taskManager_->SubmitTask([this, imageId]() {
            processor_->CancelProcessImage(imageId);
        });
    }

    ReportEvent(imageId, DeferredProcessingServiceInterfaceCode::DPS_CANCEL_PROCESS_IMAGE);
    return 0;
}

sptr<IDeferredPhotoProcessingSession> CreateDeferredProcessingSession(int userId,
    std::shared_ptr<DeferredPhotoProcessor> processor, TaskManager* taskManager,
    sptr<IDeferredPhotoProcessingSessionCallback> callback)
{
    DP_INFO_LOG("CreateDeferredProcessingSession successful.");
    sptr<IDeferredPhotoProcessingSession> session(new DeferredPhotoProcessingSession(userId, processor,
        taskManager, callback));
    return session;
}

void DeferredPhotoProcessingSession::ReportEvent(const std::string& imageId, int32_t event)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.operatorStage = static_cast<uint32_t>(event);
    dpsEventInfo.imageId = imageId;
    dpsEventInfo.userId = userId_;
    uint64_t beginTime = SteadyClock::GetTimestampMilli();
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