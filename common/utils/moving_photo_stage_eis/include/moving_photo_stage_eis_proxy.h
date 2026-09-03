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

#ifndef OHOS_CAMERA_MOVING_PHOTO_STAGE_EIS_PROXY_H
#define OHOS_CAMERA_MOVING_PHOTO_STAGE_EIS_PROXY_H

#include "moving_photo_stage_eis_interface.h"
#include "camera_dynamic_loader.h"
#include "refbase.h"

namespace OHOS::CameraStandard {
class MovingPhotoOfflineSessionProxy : public MovingPhotoOfflineSessionIntf {
public:
    explicit MovingPhotoOfflineSessionProxy(std::shared_ptr<Dynamiclib> lib, sptr<MovingPhotoOfflineSessionIntf> intf);
    ~MovingPhotoOfflineSessionProxy() override;
    static sptr<MovingPhotoOfflineSessionProxy> CreateOfflineSessionProxy();
    static void FreeOfflineSessionDelayed();
    bool SetStageEisResultCb(wptr<MovingPhotoOfflineSessionCbIntf> callback) override;
    void SetMovingPhotoMirror(bool isMirror) override;
    bool SetSurface(sptr<Surface> offlineEisSurface, sptr<Surface> offlineEisMetaSurface) override;
    int32_t PrepareSession(std::vector<int32_t> &movingPhotoStageProfile, bool isHDR, int32_t isStart,
                           int32_t seesionId) override;
    int32_t RequestBuffer(sptr<SurfaceBuffer> fbcBuffer, sptr<SurfaceBuffer> warpGridBuffer,
                          sptr<SurfaceBuffer> metaBuffer, int64_t timeStamp) override;

private:
    std::shared_ptr<Dynamiclib> stageEisLib_ = {nullptr};
    sptr<MovingPhotoOfflineSessionIntf> sessionIntf_ = {nullptr};
};
}
#endif