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

#ifndef MACRO_PHOTO_SESSION_NAPI_H
#define MACRO_PHOTO_SESSION_NAPI_H

#include "macro_photo_session.h"
#include "session/camera_session_napi.h"

namespace OHOS {
namespace CameraStandard {
static const char MACRO_PHOTO_SESSION_NAPI_CLASS_NAME[] = "MacroPhotoSession";
class MacroPhotoSessionNapi : public CameraSessionNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraSession(napi_env env);
    MacroPhotoSessionNapi();
    ~MacroPhotoSessionNapi() override;

    static napi_value MacroPhotoSessionNapiConstructor(napi_env env, napi_callback_info info);
    static void MacroPhotoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);

    napi_env env_;
    napi_ref wrapper_;
    sptr<MacroPhotoSession> macroPhotoSession_;
    static thread_local napi_ref sConstructor_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* MACRO_PHOTO_SESSION_NAPI_H */
