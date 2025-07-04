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

#ifndef HIGH_RES_PHOTO_SESSION_NAPI_H
#define HIGH_RES_PHOTO_SESSION_NAPI_H

#include "session/camera_session_for_sys_napi.h"
#include "session/high_res_photo_session.h"

namespace OHOS {
namespace CameraStandard {
static const char HIGH_RES_PHOTO_SESSION_NAPI_CLASS_NAME[] = "HighResPhotoSession";
class HighResPhotoSessionNapi : public CameraSessionForSysNapi {
public:
    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);
    HighResPhotoSessionNapi();
    ~HighResPhotoSessionNapi();
 
    static void HighResPhotoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value HighResPhotoSessionNapiConstructor(napi_env env, napi_callback_info info);
 
    napi_env env_;
    sptr<HighResPhotoSession> highResPhotoSession_;
    static thread_local napi_ref sConstructor_;
};
}
}
#endif /* HIGH_RES_PHOTO_SESSION_NAPI_H */