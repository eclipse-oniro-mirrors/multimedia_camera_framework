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

#ifndef MOVING_PHOTO_STAGE_EIS_INTERFACE_H
#define MOVING_PHOTO_STAGE_EIS_INTERFACE_H

#include "refbase.h"
#include "surface.h"
#include "surface_buffer.h"

namespace OHOS::CameraStandard {

enum class StageEisCode : int32_t { STAGEEIS_INVAILED = -1, STAGEEIS_OK = 0 };

class MovingPhotoOfflineSessionCbIntf : public RefBase {
public:
    virtual void EnqueueBuffer(sptr<SurfaceBuffer> stageEisBuffer, sptr<SurfaceBuffer> metaBuffer,
                               int64_t timeStamp) = 0;
    virtual sptr<SurfaceBuffer> GetBuffer(int64_t timeStamp) = 0;
    virtual sptr<SurfaceBuffer> GetMetaBuffer(int64_t timeStamp) = 0;
    virtual void OnOfflineSessionBufferDone(sptr<SurfaceBuffer> stageEisBuffer, int64_t timeStamp, bool isEosFlag) = 0;
    virtual void OnOfflineSessionMetaBufferDone(sptr<Surface> offlineEisMetaSurface, sptr<SurfaceBuffer> metaBuffer,
                                                int64_t timeStamp, bool isEosFlag) = 0;
};

class MovingPhotoOfflineSessionIntf : public RefBase {
public:
    virtual ~MovingPhotoOfflineSessionIntf() = default;
    virtual bool SetStageEisResultCb(wptr<MovingPhotoOfflineSessionCbIntf> callback) = 0;
    virtual void SetMovingPhotoMirror(bool isMirror) = 0;
    virtual bool SetSurface(sptr<Surface> offlineEisSurface, sptr<Surface> offlineEisMetaSurface) = 0;
    virtual int32_t PrepareSession(std::vector<int32_t> &movingPhotoStageProfile, bool isHDR, int32_t isStart,
                                   int32_t sessionId) = 0;
    virtual int32_t RequestBuffer(sptr<SurfaceBuffer> fbcBuffer, sptr<SurfaceBuffer> warpGridBuffer,
                                  sptr<SurfaceBuffer> metaBuffer, int64_t timeStamp) = 0;
};
}
#endif
