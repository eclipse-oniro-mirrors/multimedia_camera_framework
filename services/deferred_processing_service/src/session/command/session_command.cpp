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

#include "session_command.h"

#include "dps.h"
#include "events_info.h"
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

SessionCommand::SessionCommand()
{
    DP_DEBUG_LOG("entered.");
}

SessionCommand::~SessionCommand()
{
    DP_DEBUG_LOG("entered.");
}

int32_t SessionCommand::Initialize()
{
    DP_CHECK_RETURN_RET(initialized_.load(), DP_OK);

    sessionManager_ = DPS_GetSessionManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(sessionManager_ == nullptr, DP_NULL_POINTER, "SessionManager is nullptr.");
    schedulerManager_ = DPS_GetSchedulerManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(schedulerManager_ == nullptr, DP_NULL_POINTER, "SchedulerManager is nullptr.");
    initialized_.store(true);
    return DP_OK;
}

AddPhotoSessionCommand::AddPhotoSessionCommand(const sptr<PhotoSessionInfo>& info) : photoInfo_(info)
{
    DP_DEBUG_LOG("entered.");
}

int32_t AddPhotoSessionCommand::Executing()
{
    int32_t ret = Initialize();
    DP_CHECK_RETURN_RET(ret != DP_OK, ret);

    sessionManager_->AddPhotoSession(photoInfo_);
    if (photoInfo_->isCreate_) {
        schedulerManager_->CreatePhotoProcessor(photoInfo_->GetUserId());
    }
    // 设置媒体库状态为空闲
    EventsInfo::GetInstance().SetMediaLibraryState(MediaLibraryStatus::MEDIA_LIBRARY_IDLE);
    EventsMonitor::GetInstance().NotifyEventToObervers(EventType::MEDIA_LIBRARY_STATUS_EVENT,
        MEDIA_LIBRARY_AVAILABLE);
    return DP_OK;
}
// LCOV_EXCL_START
DeletePhotoSessionCommand::DeletePhotoSessionCommand(const sptr<PhotoSessionInfo>& info) : photoInfo_(info)
{
    DP_DEBUG_LOG("entered.");
}

int32_t DeletePhotoSessionCommand::Executing()
{
    int32_t ret = Initialize();
    DP_CHECK_RETURN_RET(ret != DP_OK, ret);
    
    sessionManager_->DeletePhotoSession(photoInfo_->GetUserId());
    EventsMonitor::GetInstance().NotifyEventToObervers(EventType::MEDIA_LIBRARY_STATUS_EVENT,
        MEDIA_LIBRARY_DISCONNECTED);
    return DP_OK;
}
// LCOV_EXCL_STOP
#ifdef CAMERA_DEFERRED
AddVideoSessionCommand::AddVideoSessionCommand(const sptr<VideoSessionInfo>& info) : videoInfo_(info)
{
    DP_DEBUG_LOG("entered.");
}

int32_t AddVideoSessionCommand::Executing()
{
    int32_t ret = Initialize();
    DP_CHECK_RETURN_RET(ret != DP_OK, ret);
    
    sessionManager_->AddVideoSession(videoInfo_);
    if (videoInfo_->isCreate_) {
        schedulerManager_->CreateVideoProcessor(videoInfo_->GetUserId());
    }
    EventsMonitor::GetInstance().NotifyEventToObervers(EventType::MEDIA_LIBRARY_STATUS_EVENT,
        MEDIA_LIBRARY_AVAILABLE);
    return DP_OK;
}

DeleteVideoSessionCommand::DeleteVideoSessionCommand(const sptr<VideoSessionInfo>& info) : videoInfo_(info)
{
    DP_DEBUG_LOG("entered.");
}
// LCOV_EXCL_START
int32_t DeleteVideoSessionCommand::Executing()
{
    int32_t ret = Initialize();
    DP_CHECK_RETURN_RET(ret != DP_OK, ret);
    
    sessionManager_->DeleteVideoSession(videoInfo_->GetUserId());
    EventsMonitor::GetInstance().NotifyEventToObervers(EventType::MEDIA_LIBRARY_STATUS_EVENT,
        MEDIA_LIBRARY_DISCONNECTED);
    return DP_OK;
}
#endif
// LCOV_EXCL_STOP
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS