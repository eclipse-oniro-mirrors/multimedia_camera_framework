/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_CONTROL_CENTER_SESSION_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_CONTROL_CENTER_SESSION_TAIHE_H

#include "session/control_center_session.h"

#include "camera_worker_queue_keeper_taihe.h"
#include "camera_event_emitter_taihe.h"
#include "listener_base_taihe.h"
#include "camera_query_taihe.h"
#include "camera_security_utils_taihe.h"
#include "control_center_session.h"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class ControlCenterSessionImpl {
public:
    explicit ControlCenterSessionImpl(sptr<OHOS::CameraStandard::ControlCenterSession> obj)
    {
        if (obj != nullptr && OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(false)) {
            controlCenterSession_ = static_cast<OHOS::CameraStandard::ControlCenterSession*>(obj.GetRefPtr());
        }
    }
    array<double> GetSupportedVirtualApertures();
    double GetVirtualAperture();
    void SetVirtualAperture(double aperture);
    array<PhysicalAperture> GetSupportedPhysicalApertures();
    double GetPhysicalAperture();
    void SetPhysicalAperture(double aperture);
    array<BeautyType> GetSupportedBeautyTypes();
    array<int32_t> GetSupportedBeautyRange(BeautyType type);
    int32_t GetBeauty(BeautyType type);
    void SetBeauty(BeautyType type, int32_t value);
    array<PortraitThemeType> GetSupportedPortraitThemeTypes();
    bool IsPortraitThemeSupported();
    void SetPortraitThemeType(PortraitThemeType type);
    bool GetAutoFramingStatus();
    void EnableAutoFraming(bool enable);
    bool IsAutoFramingSupported();
    void ReleaseSync();

    static uint32_t controlCenterSessionTaskId_;

private:
    sptr<OHOS::CameraStandard::ControlCenterSession> controlCenterSession_ = nullptr;
};

struct ControlCenterSessionTaiheAsyncContext : public TaiheAsyncContext {
    ControlCenterSessionTaiheAsyncContext(std::string funcName, int32_t taskId) : TaiheAsyncContext(funcName, taskId){};

    ~ControlCenterSessionTaiheAsyncContext()
    {
        objectInfo = nullptr;
    }
    ControlCenterSessionImpl *objectInfo = nullptr;
};
}  // namespace Camera
}  // namespace Ani

#endif  // FRAMEWORKS_TAIHE_INCLUDE_CONTROL_CENTER_SESSION_TAIHE_H