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

#include "moving_photo_stage_eis_proxy.h"
#include "moving_photo_stage_eis_interface.h"
#include "camera_log.h"
#include "surface_buffer.h"

namespace OHOS::CameraStandard {
MovingPhotoOfflineSessionProxy::MovingPhotoOfflineSessionProxy(std::shared_ptr<Dynamiclib> lib,
                                                               sptr<MovingPhotoOfflineSessionIntf> intf)
    : stageEisLib_(lib),
      sessionIntf_(intf)
{
    MEDIA_INFO_LOG("MovingPhotoOfflineSessionProxy ctor is called");
}

MovingPhotoOfflineSessionProxy::~MovingPhotoOfflineSessionProxy()
{
    MEDIA_INFO_LOG("MovingPhotoOfflineSessionProxy dtor is called");
}

using CreateMovingPhotoOfflineSessionIntf = MovingPhotoOfflineSessionIntf *(*)();

sptr<MovingPhotoOfflineSessionProxy> MovingPhotoOfflineSessionProxy::CreateOfflineSessionProxy()
{
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(CAMERA_MOVING_PHOTO_OFFLINE_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "get dynamiclib fail");
    CreateMovingPhotoOfflineSessionIntf createMovingPhotoOfflineSessionIntf =
        (CreateMovingPhotoOfflineSessionIntf)dynamiclib->GetFunction("createMovingPhotoOfflineSessionIntf");
    CHECK_RETURN_RET_ELOG(createMovingPhotoOfflineSessionIntf == nullptr, nullptr,
                          "createMovingPhotoOfflineSessionIntf failed");
    MovingPhotoOfflineSessionIntf *movingPhotoOfflineSessionIntf = createMovingPhotoOfflineSessionIntf();
    CHECK_RETURN_RET_ELOG(movingPhotoOfflineSessionIntf == nullptr, nullptr,
                          "get movingPhotoOfflineSessionIntf failed");
    return sptr<MovingPhotoOfflineSessionProxy>::MakeSptr(
        dynamiclib, sptr<MovingPhotoOfflineSessionIntf>(movingPhotoOfflineSessionIntf));
}

void MovingPhotoOfflineSessionProxy::FreeOfflineSessionDelayed()
{
    CameraDynamicLoader::FreeDynamicLibDelayed(CAMERA_MOVING_PHOTO_OFFLINE_SO);
}

bool MovingPhotoOfflineSessionProxy::SetStageEisResultCb(wptr<MovingPhotoOfflineSessionCbIntf> callback)
{
    CHECK_RETURN_RET_ELOG(sessionIntf_ == nullptr, false, "sessionIntf_ is nullptr");
    return sessionIntf_->SetStageEisResultCb(callback);
}

void MovingPhotoOfflineSessionProxy::SetMovingPhotoMirror(bool isMirror)
{
    CHECK_RETURN_ELOG(sessionIntf_ == nullptr, "sessionIntf_ is nullptr");
    return sessionIntf_->SetMovingPhotoMirror(isMirror);
}

bool MovingPhotoOfflineSessionProxy::SetSurface(sptr<Surface> offlineEisSurface, sptr<Surface> offlineEisMetaSurface)
{
    CHECK_RETURN_RET_ELOG(sessionIntf_ == nullptr, false, "sessionIntf_ is nullptr");
    return sessionIntf_->SetSurface(offlineEisSurface, offlineEisMetaSurface);
}

int32_t MovingPhotoOfflineSessionProxy::PrepareSession(std::vector<int32_t> &movingPhotoStageProfile, bool isHDR,
                                                       int32_t isStart, int32_t sessionId)
{
    CHECK_RETURN_RET_ELOG(sessionIntf_ == nullptr, -1, "sessionIntf_ is nullptr");
    return sessionIntf_->PrepareSession(movingPhotoStageProfile, isHDR, isStart, sessionId);
}

int32_t MovingPhotoOfflineSessionProxy::RequestBuffer(sptr<SurfaceBuffer> fbcBuffer, sptr<SurfaceBuffer> warpGridBuffer,
                                                      sptr<SurfaceBuffer> metaBuffer, int64_t timeStamp)
{
    CHECK_RETURN_RET_ELOG(sessionIntf_ == nullptr, -1, "sessionIntf_ is nullptr");
    return sessionIntf_->RequestBuffer(fbcBuffer, warpGridBuffer, metaBuffer, timeStamp);
}
}