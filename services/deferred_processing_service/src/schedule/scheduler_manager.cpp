/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "scheduler_manager.h"

#include "dp_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
std::shared_ptr<SchedulerManager> SchedulerManager::Create()
{
    DP_DEBUG_LOG("entered.");
    return CreateShared<SchedulerManager>();
}

SchedulerManager::SchedulerManager()
{
    DP_DEBUG_LOG("entered.");
}

SchedulerManager::~SchedulerManager()
{
    DP_DEBUG_LOG("entered.");
    photoPosts_.clear();
    photoController_.clear();
    photoProcessors_.clear();
    videoPosts_.clear();
    videoController_.clear();
    videoProcessors_.clear();
}

int32_t SchedulerManager::Initialize()
{
    DP_DEBUG_LOG("entered.");
    return DP_OK;
}

std::shared_ptr<PhotoPostProcessor> SchedulerManager::GetPhotoPostProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto item = photoPosts_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(item == photoPosts_.end(), nullptr,
        "PhotoPostProcessor not found for userId: %{public}d.", userId);
    return item->second;
}

std::shared_ptr<DeferredPhotoProcessor> SchedulerManager::GetPhotoProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto item = photoProcessors_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(item == photoProcessors_.end(), nullptr,
        "PhotoProcessors not found for userId: %{public}d.", userId);
    return item->second;
}


void SchedulerManager::CreatePhotoProcessor(const int32_t userId,
    const std::shared_ptr<IImageProcessCallbacks>& callbacks)
{
    DP_INFO_LOG("entered");
    auto photoRepository = std::make_shared<PhotoJobRepository>(userId);
    auto photoPost = CreateShared<PhotoPostProcessor>(userId);
    auto photoProcessor = CreateShared<DeferredPhotoProcessor>(userId, photoRepository, photoPost, callbacks);
    auto photoController = CreateShared<DeferredPhotoController>(userId, photoRepository, photoProcessor);
    photoController->Initialize();
    photoPosts_[userId] = photoPost;
    photoProcessors_[userId] = photoProcessor;
    photoController_[userId] = photoController;
}

std::shared_ptr<VideoPostProcessor> SchedulerManager::GetVideoPostProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto it = videoPosts_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == videoPosts_.end(), nullptr,
        "VideoPostProcessor not found for userId: %{public}d", userId);

    return it->second;
}

std::shared_ptr<DeferredVideoProcessor> SchedulerManager::GetVideoProcessor(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto it = videoProcessors_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == videoProcessors_.end(), nullptr,
        "VideoProcessor not found for userId: %{public}d", userId);

    return it->second;
}

std::shared_ptr<DeferredVideoController> SchedulerManager::GetVideoController(const int32_t userId)
{
    DP_DEBUG_LOG("entered.");
    auto it = videoController_.find(userId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == videoController_.end(), nullptr,
        "VideoController not found for userId: %{public}d", userId);

    return it->second;
}

void SchedulerManager::CreateVideoProcessor(const int32_t userId,
    const std::shared_ptr<IVideoProcessCallbacks>& callbacks)
{
    DP_DEBUG_LOG("entered.");
    auto videoRepository = std::make_shared<VideoJobRepository>(userId);
    auto videoPost = CreateShared<VideoPostProcessor>(userId);
    auto videoProcessor = CreateShared<DeferredVideoProcessor>(videoRepository, videoPost, callbacks);
    auto videoController = CreateShared<DeferredVideoController>(userId, videoRepository, videoProcessor);
    videoController->Initialize();
    videoPosts_[userId] = videoPost;
    videoProcessors_[userId] = videoProcessor;
    videoController_[userId] = videoController;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS