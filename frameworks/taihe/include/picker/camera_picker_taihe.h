/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_TAIHE_PICKER_CAMERA_PICKER_TAIHE_H
#define FRAMEWORKS_TAIHE_PICKER_CAMERA_PICKER_TAIHE_H
#include "ohos.multimedia.cameraPicker.proj.hpp"
#include "ohos.multimedia.cameraPicker.impl.hpp"
#include "taihe/runtime.hpp"
#include "ability_context.h"
#include "ui_content.h"
#include "camera_log.h"
#include "ui_extension_base/ui_extension_context.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::cameraPicker;
using namespace ohos::multimedia::camera;
using namespace OHOS;

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

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(std::shared_ptr<PickerContextProxy> contextProxy);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy);
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

struct CameraPickerAsyncContext {
    std::string resultUri;
    std::string errorMsg;
    AAFwk::Want want;
    std::shared_ptr<PickerContextProxy> contextProxy;
    std::shared_ptr<UIExtensionCallback> uiExtCallback;
    int32_t resultCode;
    bool bRetBool;
};

class CameraPickerJsAsyncContextImpl {
public:
    CameraPickerJsAsyncContextImpl(std::shared_ptr<CameraPickerAsyncContext> asyncCtx) : asyncCtx_(asyncCtx) {};
    ~CameraPickerJsAsyncContextImpl() = default;
    inline std::shared_ptr<CameraPickerAsyncContext> GetCameraPickerAsyncContext()
    {
        std::unique_lock<std::mutex> lock(Mutex_);
        return asyncCtx_;
    }

    int64_t GetSpecificImplPtr();
private:
    std::mutex Mutex_;
    std::shared_ptr<CameraPickerAsyncContext> asyncCtx_ = nullptr;
};
} // namespace Camera
} // namespace Ani
#endif // FRAMEWORKS_TAIHE_PICKER_CAMERA_PICKER_TAIHE_H