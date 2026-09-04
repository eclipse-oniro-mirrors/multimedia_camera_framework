/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "moving_photo_lifecycle_manager.h"
#include "camera_log.h"
#include "moving_photo_listener.h"
#include "moving_photo_video_cache.h"
#include "moving_photo_warp_grid_surface_wrapper.h"
#include "moving_photo_proxy.h"
#include "moving_photo_stage_eis_interface.h"

namespace OHOS {
namespace CameraStandard {

MovingPhotoLifecycleManager::MovingPhotoLifecycleManager()
{
    MEDIA_INFO_LOG("MovingPhotoLifecycleManager ctor is called");
}

MovingPhotoLifecycleManager::~MovingPhotoLifecycleManager()
{
    MEDIA_INFO_LOG("MovingPhotoLifecycleManager dtor is called");
    movingPhotoListener_ = nullptr;
    stageEisListener_ = nullptr;
    offlineSessionListener_ = nullptr;
    offlineSession_ = nullptr;
    videoCache_ = nullptr;
}

void MovingPhotoLifecycleManager::SetMovingPhotoListener(const sptr<MovingPhotoListener>& listener)
{
    MEDIA_INFO_LOG("MovingPhotoLifecycleManager::SetMovingPhotoListener is called");
    movingPhotoListener_ = listener;
}

void MovingPhotoLifecycleManager::SetStageEisListener(const sptr<MovingPhotoStageEisListener>& stageEisListener)
{
    MEDIA_INFO_LOG("MovingPhotoLifecycleManager::SetStageEisListener is called");
    stageEisListener_ = stageEisListener;
}

void MovingPhotoLifecycleManager::SetOfflineSessionListener(
    const sptr<MovingPhotoMediaOfflineSessionListener>& offlineSessionListener)
{
    MEDIA_INFO_LOG("MovingPhotoLifecycleManager::SetOfflineSessionListener is called");
    offlineSessionListener_ = offlineSessionListener;
}

void MovingPhotoLifecycleManager::SetOfflineSession(const sptr<MovingPhotoOfflineSessionIntf>& offlineSession)
{
    MEDIA_INFO_LOG("MovingPhotoLifecycleManager::SetOfflineSession is called");
    offlineSession_ = offlineSession;
}

void MovingPhotoLifecycleManager::SetVideoCache(const sptr<MovingPhotoVideoCache>& videoCache)
{
    MEDIA_INFO_LOG("MovingPhotoLifecycleManager::SetVideoCache is called");
    videoCache_ = videoCache;
}

} // namespace CameraStandard
} // namespace OHOS