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
#include "context.h"
#include "ui_content.h"
#include "ui_extension_base/ui_extension_context.h"

namespace OHOS {
namespace CameraStandard {

typedef struct {
    std::string saveUri;
    CameraPosition cameraPosition;
    int videoDuration;
} PickerProfile;

enum class PickerContextType : uint32_t { UNKNOWN, UI_EXTENSION, ABILITY };
struct PickerContextProxy {
    PickerContextProxy(std::shared_ptr<AbilityRuntime::Context> context) : mContext_(context)
    {
        if (AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context) != nullptr) {
            type_ = PickerContextType::UI_EXTENSION;
        } else if (AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context) != nullptr) {
            type_ = PickerContextType::ABILITY;
        } else {
            type_ = PickerContextType::UNKNOWN;
        }
    }

    PickerContextType GetType()
    {
        return type_;
    }

    std::string GetBundleName()
    {
        auto context = mContext_.lock();
        if (context != nullptr) {
            return context->GetBundleName();
        }
        return "";
    }

    Ace::UIContent* GetUIContent()
    {
        auto context = mContext_.lock();
        if (context == nullptr) {
            return nullptr;
        }
        switch (type_) {
            case PickerContextType::UI_EXTENSION: {
                auto ctx = AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context);
                if (ctx != nullptr) {
                    return ctx->GetUIContent();
                }
                break;
            }
            case PickerContextType::ABILITY: {
                auto ctx = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
                if (ctx != nullptr) {
                    return ctx->GetUIContent();
                }
                break;
            }
            default:
                // Do nothing
                break;
        }
        return nullptr;
    }

private:
    std::weak_ptr<AbilityRuntime::Context> mContext_;
    PickerContextType type_ = PickerContextType::UNKNOWN;
};

enum class PickerMediaType : uint32_t { PHOTO, VIDEO };

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(std::shared_ptr<PickerContextProxy> contextProxy);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();
    void CloseWindow();

    inline void SetSessionId(int32_t sessionId)
    {
        sessionId_ = sessionId;
    }

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
    bool FinishPicker(int32_t code);
    int32_t sessionId_ = 0;
    int32_t resultCode_ = 0;
    std::string resultUri_ = "";
    std::string resultMode_ = "";
    std::shared_ptr<PickerContextProxy> contextProxy_;
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
    static thread_local uint32_t cameraPickerTaskId;
    static thread_local napi_ref sConstructor_;
    static thread_local napi_ref mediaTypeRef_;
};

struct CameraPickerAsyncContext : public AsyncContext {
    std::string resultUri;
    std::string errorMsg;
    PickerProfile pickerProfile;
    AAFwk::Want want;
    std::shared_ptr<PickerContextProxy> contextProxy;
    std::shared_ptr<UIExtensionCallback> uiExtCallback;
    int32_t resultCode;
    bool bRetBool;
};
} // namespace CameraStandard
} // namespace OHOS

#endif /* CAMERA_PICKER_NAPI_H */
