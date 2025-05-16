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

#ifndef FRAMEWORKS_TAIHE_INCLUDE_SLOW_MOTION_SESSION_TAIHE_H
#define FRAMEWORKS_TAIHE_INCLUDE_SLOW_MOTION_SESSION_TAIHE_H

#include "ohos.multimedia.camera.proj.hpp"
#include "ohos.multimedia.camera.impl.hpp"
#include "session/camera_session_taihe.h"
#include "session/slow_motion_session.h"
#include "taihe/runtime.hpp"

namespace Ani {
namespace Camera {
using namespace OHOS;
using namespace ohos::multimedia::camera;

class SlowMotionStateListener : public OHOS::CameraStandard::SlowMotionStateCallback, public ListenerBase,
    public std::enable_shared_from_this<SlowMotionStateListener> {
public:
    explicit SlowMotionStateListener(ani_env* env) : ListenerBase(env)
    {
        SetSlowMotionState(OHOS::CameraStandard::SlowMotionState::DEFAULT);
    }
    ~SlowMotionStateListener() = default;
    void OnSlowMotionState(const OHOS::CameraStandard::SlowMotionState state) override;
private:
    void OnSlowMotionStateCb(const OHOS::CameraStandard::SlowMotionState state) const;
};

class SlowMotionVideoSessionImpl : public SessionImpl, public FlashQueryImpl, public ZoomQueryImpl {
public:
    explicit SlowMotionVideoSessionImpl(sptr<OHOS::CameraStandard::CaptureSession> &obj) : SessionImpl(obj),
        FlashQueryImpl(obj), ZoomQueryImpl(obj)
    {
        if (obj != nullptr) {
            slowMotionSession_ = static_cast<OHOS::CameraStandard::SlowMotionSession*>(obj.GetRefPtr());
        }
    }
    ~SlowMotionVideoSessionImpl() = default;
    std::shared_ptr<SlowMotionStateListener> slowMotionState_ = nullptr;
private:
    sptr<OHOS::CameraStandard::SlowMotionSession> slowMotionSession_ = nullptr;
    void RegisterSlowMotionStateCb(const std::string& eventName, std::shared_ptr<uintptr_t> callback,
        bool isOnce) override;
    void UnregisterSlowMotionStateCb(
        const std::string& eventName, std::shared_ptr<uintptr_t> callback) override;
};
} // namespace Camera
} // namespace Ani

#endif // FRAMEWORKS_TAIHE_INCLUDE_SLOW_MOTION_SESSION_TAIHE_H