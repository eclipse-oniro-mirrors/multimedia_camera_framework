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
#include "camera_log.h"
#include "camera_napi_utils.h"
#include "js_native_api_types.h"
#include "ability.h"
#include "ability_context.h"
#include "ability_manager_client.h"
#include "int_wrapper.h"
#include "modal_ui_extension_config.h"
#include "napi_base_context.h"
#include "string_wrapper.h"
#include "ui_content.h"
#include "want.h"

namespace OHOS {
namespace CameraStandard {

typedef struct {
    string saveUri;
    CameraPosition cameraPosition;
    int videoDuration;
} VideoProfileForPicker;

typedef struct {
    string saveUri;
    CameraPosition cameraPosition;
} PhotoProfileForPicker;

struct CommonAsyncContext {
    explicit CommonAsyncContext(napi_env napiEnv);
    virtual ~CommonAsyncContext();
    napi_env env = nullptr;
    napi_status status = napi_invalid_arg;
    int32_t errCode = 0;
    napi_deferred deferred = nullptr;  // promise handle
    napi_ref callbackRef = nullptr;    // callback handle
    napi_async_work work = nullptr;    // work handle
};

struct UIExtensionRequestContext : public CommonAsyncContext {
    explicit UIExtensionRequestContext(napi_env env) : CommonAsyncContext(env) {};
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> context = nullptr;
    OHOS::AAFwk::Want requestWant;
};

static const char CAMERA_PICKER_NAPI_CLASS_NAME[] = "CameraPicker";

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(std::shared_ptr<UIExtensionRequestContext>& reqContext);
    void SetSessionId(int32_t sessionId);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();
    void SendMessageBack();

private:
    bool SetErrorCode(int32_t code);
    int32_t sessionId_ = 0;
    int32_t resultCode_ = 0;
    OHOS::AAFwk::Want resultWant_;
    std::shared_ptr<UIExtensionRequestContext> reqContext_ = nullptr;
    bool alreadyCallback_ = false;
};

class CameraPickerNapi {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreatePickerPhotoProfile(napi_env env);
    static napi_value CreatePickerVideoProfile(napi_env env);
    static napi_value CreatePickerResult(napi_env env);
    static napi_status AddNamedProperty(napi_env env, napi_value object,
                                        const std::string name, int32_t enumValue);
    static napi_value TakePhoto(napi_env env, napi_callback_info info);
    static napi_value RecordVideo(napi_env env, napi_callback_info info);
    static napi_value CameraPickerNapiConstructor(napi_env env, napi_callback_info info);
    static void CameraPickerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint);
    CameraPickerNapi();
    ~CameraPickerNapi();

private:
    napi_env env_;
    napi_ref wrapper_;
    static thread_local uint32_t cameraPickerTaskId;
    static thread_local napi_ref sConstructor_;
};

struct CameraPickerAsyncContext : public AsyncContext {
    CameraPickerNapi* objectInfo;
    std::string resultUri;
    std::string errorMsg;
    Ace::UIContent* uiContent;
    PhotoProfileForPicker photoProfile;
    VideoProfileForPicker videoProfile;
    AAFwk::Want want;
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    int32_t resultCode;
    bool bRetBool;
    ~CameraPickerAsyncContext()
    {
        objectInfo = nullptr;
    }
};
} // namespace CameraStandard
} // namespace OHOS

#endif /* CAMERA_PICKER_NAPI_H */
