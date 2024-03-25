/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CAMERA_PICKER_NAPI_H
#define CAMERA_PICKER_NAPI_H
#include <atomic>
#include <memory>
#include <stdint.h>

#include "ability_context.h"
#include "camera_device.h"
#include "camera_napi_utils.h"
#include "ui_content.h"

namespace OHOS {
namespace CameraStandard {

typedef struct {
    std::string saveUri;
    CameraPosition cameraPosition;
    int videoDuration;
} PickerProfile;

enum class PickerMediaType : uint32_t { PHOTO, VIDEO };

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext);
    void SetSessionId(int32_t sessionId);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();
    void SendMessageBack();

    inline void WaitResultLock()
    {
        std::unique_lock<std::mutex> lock(cbMutex_);
        while (!isCallbackReturned_) {
            cbFinishCondition_.wait(lock);
        }
    }

    inline void NotifyResultLock()
    {
        std::unique_lock<std::mutex> lock(cbMutex_);
        cbFinishCondition_.notify_one();
    }

    inline int32_t GetResultCode()
    {
        return resultCode_;
    }

    inline std::string GetResultUri()
    {
        return resultUri_;
    }

    inline std::string GetResultMediaType()
    {
        if (resultMode_ == "VIDEO") {
            return "video";
        }
        return "photo";
    }

private:
    bool SetErrorCode(int32_t code);
    int32_t sessionId_ = 0;
    int32_t resultCode_ = 0;
    std::string resultUri_ = "";
    std::string resultMode_ = "";
    std::weak_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext_;
    std::condition_variable cbFinishCondition_;
    std::mutex cbMutex_;
    bool isCallbackReturned_ = false;
};

class CameraPickerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreatePickerMediaType(napi_env env);
    static napi_value CreatePickerProfile(napi_env env);
    static napi_value CreatePickerResult(napi_env env);

    static napi_value Pick(napi_env env, napi_callback_info info);

    static napi_value CameraPickerNapiConstructor(napi_env env, napi_callback_info info);
    static void CameraPickerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    CameraPickerNapi();
    ~CameraPickerNapi();

private:
    napi_env env_;
    napi_ref wrapper_;
    static thread_local uint32_t cameraPickerTaskId;
    static thread_local napi_ref sConstructor_;
    static thread_local napi_ref mediaTypeRef_;
};

struct CameraPickerAsyncContext : public AsyncContext {
    std::string resultUri;
    std::string errorMsg;
    PickerProfile pickerProfile;
    AAFwk::Want want;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    std::shared_ptr<UIExtensionCallback> uiExtCallback;
    int32_t resultCode;
    bool bRetBool;
};
} // namespace CameraStandard
} // namespace OHOS

#endif /* CAMERA_PICKER_NAPI_H */
