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
class LongExposureCallbackListener : public LongExposureCallback {
public:
    LongExposureCallbackListener(napi_env env) : env_(env) {}
    ~LongExposureCallbackListener() = default;
    void OnLongExposure(const uint32_t longExposureTime) override;
    void SaveCallbackReference(const std::string &eventType, napi_value callback, bool isOnce);
    void RemoveCallbackRef(napi_env env, napi_value callback);
    void RemoveAllCallbacks();

private:
    void OnLongExposureCallback(uint32_t longExposureTime) const;
    void OnLongExposureCallbackAsync(uint32_t longExposureTime) const;

    std::mutex mutex_;
    napi_env env_;
    mutable std::vector<std::shared_ptr<AutoRef>> longExposureCbList_;
};

struct LongExposureCallbackInfo {
    uint32_t longExposureTime_;
    const LongExposureCallbackListener* listener_;
    LongExposureCallbackInfo(uint32_t longExposureTime, const LongExposureCallbackListener* listener)
        : longExposureTime_(longExposureTime), listener_(listener) {}
};

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

    static napi_value TryAE(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Once(napi_env env, napi_callback_info info);
    static napi_value RegisterCallback(napi_env env, napi_value jsThis,
                                        const string &eventType, napi_value callback, bool isOnce);
    static napi_value UnregisterCallback(napi_env env, napi_value jsThis,
                                            const std::string &eventType, napi_value callback);
    static napi_value Off(napi_env env, napi_callback_info info);
    napi_env env_;
    napi_ref wrapper_;
    sptr<NightSession> nightSession_;
    std::shared_ptr<LongExposureCallbackListener> longExposureCallback_;

    static thread_local napi_ref sConstructor_;
};
}
}
#endif /* NIGHT_SESSION_NAPI_H_ */
