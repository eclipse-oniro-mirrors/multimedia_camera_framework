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

#include "deferred_photo_processor.h"

#include "dp_log.h"
#include "dp_utils.h"
#include "dps_event_report.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredPhotoProcessor::DeferredPhotoProcessor(const int32_t userId,
    const std::shared_ptr<PhotoJobRepository>& repository, const std::shared_ptr<PhotoPostProcessor>& postProcessor,
    const std::weak_ptr<IImageProcessCallbacks>& callback)
    : userId_(userId), repository_(repository), postProcessor_(postProcessor), callback_(callback)
{
    DP_DEBUG_LOG("entered.");
}

DeferredPhotoProcessor::~DeferredPhotoProcessor()
{
    DP_DEBUG_LOG("entered.");
}

void DeferredPhotoProcessor::Initialize()
{
    DP_DEBUG_LOG("entered.");
    postProcessor_->Initialize();
    postProcessor_->SetCallback(weak_from_this());
}

void DeferredPhotoProcessor::AddImage(const std::string& imageId, bool discardable, DpsMetadata& metadata)
{
    DP_DEBUG_LOG("entered.");
    repository_->AddDeferredJob(imageId, discardable, metadata);
}

void DeferredPhotoProcessor::RemoveImage(const std::string& imageId, bool restorable)
{
    DP_DEBUG_LOG("entered.");
    auto item = requestedImages_.find(imageId);
    if (item != requestedImages_.end()) {
        requestedImages_.erase(item);
    }
    DP_CHECK_ERROR_RETURN_LOG(repository_ == nullptr, "repository_ is nullptr");

    if (restorable == false) {
        if (repository_->GetJobStatus(imageId) == PhotoJobStatus::RUNNING) {
            DP_CHECK_ERROR_RETURN_LOG(postProcessor_ == nullptr, "postProcessor_ is nullptr, RemoveImage failed.");
            postProcessor_->Interrupt();
        }
        DP_CHECK_ERROR_RETURN_LOG(postProcessor_ == nullptr, "postProcessor_ is nullptr, RemoveImage failed.");
        postProcessor_->RemoveImage(imageId);
    }
    repository_->RemoveDeferredJob(imageId, restorable);
}

void DeferredPhotoProcessor::RestoreImage(const std::string& imageId)
{
    DP_DEBUG_LOG("entered.");
    repository_->RestoreJob(imageId);
}

void DeferredPhotoProcessor::ProcessImage(const std::string& appName, const std::string& imageId)
{
    DP_DEBUG_LOG("entered.");
    if (!repository_->IsOfflineJob(imageId)) {
        DP_INFO_LOG("DPS_PHOTO: imageId is not offlineJob %{public}s", imageId.c_str());
        return;
    }
    requestedImages_.insert(imageId);
    bool isImageIdValid = repository_->RequestJob(imageId);
    if (!isImageIdValid) {
        if (auto callback = callback_.lock()) {
            callback->OnError(userId_, imageId, DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
        }
    } else {
        if (repository_->GetJobPriority(postedImageId_) != PhotoJobPriority::HIGH) {
            Interrupt();
        }
    }
}

void DeferredPhotoProcessor::CancelProcessImage(const std::string& imageId)
{
    DP_DEBUG_LOG("entered.");
    requestedImages_.erase(imageId);
    repository_->CancelJob(imageId);
}

void DeferredPhotoProcessor::OnProcessDone(const int32_t userId, const std::string& imageId,
    const std::shared_ptr<BufferInfo>& bufferInfo)
{
    DP_INFO_LOG("DPS_PHOTO: userId: %{public}d, imageId: %{public}s.", userId, imageId.c_str());
    //如果已经非高优先级，且任务结果不是全质量的图，那么不用返回给上层了，等下次出全质量图再返回
    if (!(bufferInfo->IsHighQuality())) {
        DP_INFO_LOG("not high quality photo");
        if ((repository_->GetJobPriority(imageId) != PhotoJobPriority::HIGH)) {
            DP_INFO_LOG("not high quality and not high priority, need retry");
            repository_->SetJobPending(imageId);
            return;
        } else {
            DP_INFO_LOG("not high quality, but high priority, and process as normal job before, need retry");
            if (repository_->GetJobRunningPriority(imageId) != PhotoJobPriority::HIGH) {
                repository_->SetJobPending(imageId);
                return;
            }
        }
    }
    if (auto callback = callback_.lock()) {
        callback->OnProcessDone(userId, imageId, bufferInfo);
        repository_->SetJobCompleted(imageId);
    }
}

void DeferredPhotoProcessor::OnProcessDoneExt(const int32_t userId, const std::string& imageId,
    const std::shared_ptr<BufferInfoExt>& bufferInfo)
{
    DP_INFO_LOG("DPS_PHOTO: userId: %{public}d, imageId: %{public}s.", userId, imageId.c_str());
    //如果已经非高优先级，且任务结果不是全质量的图，那么不用返回给上层了，等下次出全质量图再返回
    if (!(bufferInfo->IsHighQuality())) {
        DP_INFO_LOG("not high quality photo");
        if ((repository_->GetJobPriority(imageId) != PhotoJobPriority::HIGH)) {
            DP_INFO_LOG("not high quality and not high priority, need retry");
            repository_->SetJobPending(imageId);
            return;
        } else {
            DP_INFO_LOG("not high quality, but high priority, and process as normal job before, need retry");
            if (repository_->GetJobRunningPriority(imageId) != PhotoJobPriority::HIGH) {
                repository_->SetJobPending(imageId);
                return;
            }
        }
    }
    if (auto callback = callback_.lock()) {
        callback->OnProcessDoneExt(userId, imageId, bufferInfo);
        repository_->SetJobCompleted(imageId);
    }
}

void DeferredPhotoProcessor::OnError(const int32_t userId, const std::string& imageId, DpsError errorCode)
{
    DP_INFO_LOG("DPS_PHOTO: userId: %{public}d, imageId: %{public}s, error: %{public}d.",
        userId, imageId.c_str(), errorCode);
    if (errorCode == DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED &&
        repository_->GetJobPriority(imageId) == PhotoJobPriority::HIGH &&
        requestedImages_.count(imageId) != 0) {
        repository_->SetJobPending(imageId);
        return;
    }

    if (!IsFatalError(errorCode)) {
        if (repository_->GetJobPriority(imageId) == PhotoJobPriority::HIGH) {
            if (repository_->GetJobRunningPriority(imageId) != PhotoJobPriority::HIGH) {
                repository_->SetJobPending(imageId);
                return;
            }
        } else {
            repository_->SetJobFailed(imageId);
            return;
        }
    }
    if (auto callback = callback_.lock()) {
        callback->OnError(userId, imageId, errorCode);
        repository_->SetJobFailed(imageId);
    }
}

void DeferredPhotoProcessor::OnStateChanged(const int32_t userId, DpsStatus statusCode)
{
    DP_DEBUG_LOG("DPS_PHOTO: userId: %{public}d, statusCode: %{public}d.", userId, statusCode);
}

void DeferredPhotoProcessor::PostProcess(const DeferredPhotoWorkPtr& work)
{
    auto executionMode = work->GetExecutionMode();
    postedImageId_ = work->GetDeferredPhotoJob()->GetImageId();
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s, executionMode: %{public}d", postedImageId_.c_str(), executionMode);
    auto item = requestedImages_.find(postedImageId_);
    if (item != requestedImages_.end()) {
        requestedImages_.erase(item);
    }
    repository_->SetJobRunning(postedImageId_);
    postProcessor_->SetExecutionMode(executionMode);
    postProcessor_->ProcessImage(postedImageId_);
    DPSEventReport::GetInstance().ReportImageModeChange(executionMode);
}

void DeferredPhotoProcessor::SetDefaultExecutionMode()
{
    DP_DEBUG_LOG("entered.");
    postProcessor_->SetDefaultExecutionMode();
}

void DeferredPhotoProcessor::Interrupt()
{
    DP_DEBUG_LOG("entered.");
    postProcessor_->Interrupt();
}

int32_t DeferredPhotoProcessor::GetConcurrency(ExecutionMode mode)
{
    DP_DEBUG_LOG("entered.");
    return postProcessor_->GetConcurrency(mode);
}

bool DeferredPhotoProcessor::GetPendingImages(std::vector<std::string>& pendingImages)
{
    DP_DEBUG_LOG("entered.");
    bool isSuccess = postProcessor_->GetPendingImages(pendingImages);
    if (isSuccess) {
        return true;
    }
    return false;
}

bool DeferredPhotoProcessor::IsFatalError(DpsError errorCode)
{
    DP_DEBUG_LOG("entered, code: %{public}d", errorCode);
    if (errorCode == DpsError::DPS_ERROR_IMAGE_PROC_FAILED ||
        errorCode == DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID ||
        errorCode == DpsError::DPS_ERROR_IMAGE_PROC_HIGH_TEMPERATURE) {
        return true;
    } else {
        return false;
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS