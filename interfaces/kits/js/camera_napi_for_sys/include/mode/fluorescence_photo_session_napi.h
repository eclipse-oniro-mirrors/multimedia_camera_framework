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

#ifndef FLUORESCENCE_PHOTO_SESSION_NAPI_H
#define FLUORESCENCE_PHOTO_SESSION_NAPI_H

#include "session/camera_session_for_sys_napi.h"
#include "session/fluorescence_photo_session.h"

namespace OHOS {
namespace CameraStandard {
static const char FLUORESCENCE_PHOTO_SESSION_NAPI_CLASS_NAME[] = "FluorescencePhotoSession";
class FluorescencePhotoSessionNapi : public CameraSessionForSysNapi {
public:
    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);
    FluorescencePhotoSessionNapi();
    ~FluorescencePhotoSessionNapi();
 
    static void FluorescencePhotoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value FluorescencePhotoSessionNapiConstructor(napi_env env, napi_callback_info info);
 
    napi_env env_;
    sptr<FluorescencePhotoSession> fluorescencePhotoSession_;
    static thread_local napi_ref sConstructor_;
};
}
}
#endif /* FLUORESCENCE_PHOTO_SESSION_NAPI_H */