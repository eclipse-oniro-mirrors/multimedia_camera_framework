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

#ifndef MACRO_VIDEO_SESSION_NAPI_H
#define MACRO_VIDEO_SESSION_NAPI_H

#include "session/camera_session_for_sys_napi.h"
#include "session/macro_video_session.h"

namespace OHOS {
namespace CameraStandard {
static const char MACRO_VIDEO_SESSION_NAPI_CLASS_NAME[] = "MacroVideoSession";
class MacroVideoSessionNapi : public CameraSessionForSysNapi {
public:
    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);
    MacroVideoSessionNapi();
    ~MacroVideoSessionNapi() override;

    static napi_value MacroVideoSessionNapiConstructor(napi_env env, napi_callback_info info);
    static void MacroVideoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);

    napi_env env_;
    sptr<MacroVideoSession> macroVideoSession_;
    static thread_local napi_ref sConstructor_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* MACRO_VIDEO_SESSION_NAPI_H */
