/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef PHOTO_SESSION_FOR_SYS_NAPI_H
#define PHOTO_SESSION_FOR_SYS_NAPI_H

#include "session/camera_session_for_sys_napi.h"
#include "session/photo_session_for_sys.h"

namespace OHOS {
namespace CameraStandard {
static const char PHOTO_SESSION_FOR_SYS_NAPI_CLASS_NAME[] = "PhotoSessionForSys";
class PhotoSessionForSysNapi : public CameraSessionForSysNapi {
public:
    static void Init(napi_env env);
    static napi_value CreateCameraSession(napi_env env);
    PhotoSessionForSysNapi();
    ~PhotoSessionForSysNapi();

    static void PhotoSessionForSysNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    static napi_value PhotoSessionForSysNapiConstructor(napi_env env, napi_callback_info info);

    napi_env env_;
    sptr<PhotoSessionForSys> photoSessionForSys_;
    static thread_local napi_ref sConstructor_;
protected:
    void RegisterPressureStatusCallbackListener(const std::string& eventName, napi_env env, napi_value callback,
        const std::vector<napi_value>& args, bool isOnce) override;
    void UnregisterPressureStatusCallbackListener(
        const std::string& eventName, napi_env env, napi_value callback, const std::vector<napi_value>& args) override;
};
}
}
#endif /* PHOTO_SESSION_FOR_SYS_NAPI_H */
