/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef CINEMATIC_VIDEO_SESSION_NAPI_H
#define CINEMATIC_VIDEO_SESSION_NAPI_H

#include <memory>

#include "session/camera_session_for_sys_napi.h"
#include "session/cinematic_video_session.h"

namespace OHOS {
namespace CameraStandard {

static const char CINEMATIC_VIDEO_SESSION_NAPI_CLASS_NAME[] = "CinematicVideoSession";

class CinematicVideoSessionNapi : public CameraSessionForSysNapi {
public:
    CinematicVideoSessionNapi();
    ~CinematicVideoSessionNapi();
    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);

    static napi_value CinematicVideoSessionNapiConstructor(napi_env env, napi_callback_info info);
    static void CinematicVideoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);

    napi_env env_;
    napi_ref wrapper_;
    sptr<CinematicVideoSession> cinematicVideoSession_;
    static thread_local napi_ref constructor_;
};


} // namespace CameraStandard
} // namespace OHOS
#endif /* CINEMATIC_VIDEO_SESSION_NAPI_H */