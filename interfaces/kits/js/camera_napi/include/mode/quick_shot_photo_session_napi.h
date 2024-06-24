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

#ifndef QUICK_SHOT_PHOTO_SESSION_NAPI_H
#define QUICK_SHOT_PHOTO_SESSION_NAPI_H

#include "quick_shot_photo_session.h"
#include "session/camera_session_napi.h"

namespace OHOS {
namespace CameraStandard {
static const char QUICK_SHOT_PHOTO_SESSION_NAPI_CLASS_NAME[] = "QuickShotPhotoSession";
class QuickShotPhotoSessionNapi : public CameraSessionNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateCameraSession(napi_env env);
    QuickShotPhotoSessionNapi();
    ~QuickShotPhotoSessionNapi() override;

    static napi_value QuickShotPhotoSessionNapiConstructor(napi_env env, napi_callback_info info);
    static void QuickShotPhotoSessionNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);

    napi_env env_;
    napi_ref wrapper_;
    sptr<QuickShotPhotoSession> quickShotPhotoSession_;
    static thread_local napi_ref sConstructor_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif /* QUICK_SHOT_PHOTO_SESSION_NAPI_H */
