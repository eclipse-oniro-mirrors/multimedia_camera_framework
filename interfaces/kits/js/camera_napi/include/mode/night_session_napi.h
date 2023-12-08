/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef NIGHT_SESSION_NAPI_H_
#define NIGHT_SESSION_NAPI_H_

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "session/camera_session_napi.h"
#include "night_session.h"

namespace OHOS {
namespace CameraStandard {
static const char NIGHT_SESSION_NAPI_CLASS_NAME[] = "NightSession";
class NightSessionNapi : public CameraSessionNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraSession(napi_env env);
    NightSessionNapi();
    ~NightSessionNapi();

    static void NightSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value NightSessionNapiConstructor(napi_env env, napi_callback_info info);

    static napi_value GetSupportedExposureRange(napi_env env, napi_callback_info info);
    static napi_value GetExposure(napi_env env, napi_callback_info info);
    static napi_value SetExposure(napi_env env, napi_callback_info info);
    napi_env env_;
    napi_ref wrapper_;
    sptr<NightSession> nightSession_;
    static thread_local napi_ref sConstructor_;
};
}
}
#endif /* NIGHT_SESSION_NAPI_H_ */
