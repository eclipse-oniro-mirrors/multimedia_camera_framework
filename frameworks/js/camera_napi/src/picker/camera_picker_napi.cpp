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

#include "picker/camera_picker_napi.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <new>
#include <vector>

#include "ability_lifecycle_callback.h"
#include "bool_wrapper.h"
#include "camera_device.h"
#include "camera_log.h"
#include "int_wrapper.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "string_wrapper.h"

#include "napi_base_context.h"

namespace OHOS {
namespace CameraStandard {
namespace {
constexpr char CAMERA_PICKER_ABILITY_ACTION_PHOTO[] = "ohos.want.action.imageCapture";
constexpr char CAMERA_PICKER_ABILITY_ACTION_VIDEO[] = "ohos.want.action.videoCapture";
const std::map<std::string, PickerMediaType> PICKER_MEDIA_TYPE_MAP = {
    { "photo", PickerMediaType::PHOTO },
    { "video", PickerMediaType::VIDEO },
};
constexpr char CAMERA_PICKER_NAPI_CLASS_NAME[] = "CameraPicker";
const char* const PICKER_MEDIA_TYPE[] = { "PHOTO", "VIDEO" };
const std::vector<std::string> PICKER_MEDIA_TYPE_VALUE = { "photo", "video" };
const char* const PICKER_PROFILE[] = { "cameraPosition", "saveUri", "videoDuration" };
const char* const PICKER_RESULT[] = { "resultCode", "resultUri", "mediaType" };
} // namespace

using namespace std;
thread_local napi_ref CameraPickerNapi::sConstructor_ = nullptr;
thread_local napi_ref CameraPickerNapi::mediaTypeRef_ = nullptr;
thread_local uint32_t CameraPickerNapi::cameraPickerTaskId = CAMERA_PICKER_TASKID;

CameraPickerNapi::CameraPickerNapi() : env_(nullptr), wrapper_(nullptr)
{
    CAMERA_SYNC_TRACE;
}

CameraPickerNapi::~CameraPickerNapi()
{
    MEDIA_DEBUG_LOG("~CameraPickerNapi is called");
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

static std::shared_ptr<AbilityRuntime::AbilityContext> GetAbilityContext(napi_env env, napi_value value)
{
    MEDIA_DEBUG_LOG("GetAbilityContext is called");
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, value, stageMode);
    if (status != napi_ok || !stageMode) {
        MEDIA_ERR_LOG("GetAbilityContext It is not stage Mode");
        return nullptr;
    }
    auto context = AbilityRuntime::GetStageModeContext(env, value);
    if (context == nullptr) {
        MEDIA_ERR_LOG("GetAbilityContext get context failed context");
        return nullptr;
    }
    auto abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        MEDIA_ERR_LOG("GetAbilityContext AbilityRuntime convert context failed");
        return nullptr;
    }
    MEDIA_DEBUG_LOG("CameraPickerNapi GetAbilityContext success");
    return abilityContext;
}

static bool GetMediaTypes(napi_env env, napi_value napiMediaTypesArray, std::vector<PickerMediaType>& mediaTypes)
{
    MEDIA_DEBUG_LOG("GetMediaTypes is called");
    uint32_t typeLen;
    if (napi_get_array_length(env, napiMediaTypesArray, &typeLen) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_array_length failed");
        return false;
    }
    for (uint32_t i = 0; i < typeLen; i++) {
        napi_value element;
        if (napi_get_element(env, napiMediaTypesArray, i, &element) != napi_ok) {
            MEDIA_ERR_LOG("napi_get_element failed");
            return false;
        }
        std::string typeString;
        size_t stringSize = 0;
        if (napi_get_value_string_utf8(env, element, nullptr, 0, &stringSize) != napi_ok) {
            MEDIA_ERR_LOG("napi_get_value_string_utf8 failed");
            return false;
        }
        typeString.reserve(stringSize + 1);
        typeString.resize(stringSize);
        if (napi_get_value_string_utf8(env, element, typeString.data(), (stringSize + 1), &stringSize) != napi_ok) {
            MEDIA_ERR_LOG("napi_get_value_string_utf8 failed");
            return false;
        }
        auto it = PICKER_MEDIA_TYPE_MAP.find(typeString.c_str());
        if (it != PICKER_MEDIA_TYPE_MAP.end()) {
            mediaTypes.emplace_back(it->second);
        }
    }
    MEDIA_DEBUG_LOG("GetMediaTypes end valid size is %{public}zu", mediaTypes.size());
    return true;
}

static bool GetPickerProfile(napi_env env, napi_value napiPickerProfile, PickerProfile& pickerProfile)
{
    MEDIA_DEBUG_LOG("GetPickerProfile is called");
    napi_value value = nullptr;

    // get cameraPosition
    if (napi_get_named_property(env, napiPickerProfile, "cameraPosition", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    int32_t cameraPosition = 0;
    if (napi_get_value_int32(env, value, &cameraPosition) != napi_ok) {
        MEDIA_WARNING_LOG("napi_get_value_int32 failed");
    }
    // get videoDuration
    if (napi_get_named_property(env, napiPickerProfile, "videoDuration", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    int32_t videoDuration = 0;
    if (napi_get_value_int32(env, value, &videoDuration) != napi_ok) {
        MEDIA_WARNING_LOG("napi_get_value_int32 failed");
    }
    // get saveUri
    char saveUri[PATH_MAX];
    size_t length = 0;
    if (napi_get_named_property(env, napiPickerProfile, "saveUri", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    if (napi_get_value_string_utf8(env, value, saveUri, PATH_MAX, &length) != napi_ok) {
        MEDIA_WARNING_LOG("get saveUri fail!");
    }
    pickerProfile.cameraPosition = static_cast<CameraPosition>(cameraPosition);
    pickerProfile.videoDuration = videoDuration;
    pickerProfile.saveUri = std::string(saveUri);
    MEDIA_INFO_LOG("GetPickerProfile cameraPosition: %{public}d, duration: %{public}d", cameraPosition, videoDuration);
    MEDIA_INFO_LOG("GetPickerProfile saveUri: %{public}s", saveUri);
    return true;
}

static void SetPickerWantParams(AAFwk::Want& want, std::shared_ptr<AbilityRuntime::AbilityContext>& abilityContext,
    const vector<PickerMediaType>& mediaTypes, PickerProfile& pickerProfile)
{
    MEDIA_DEBUG_LOG("SetPickerWantParams enter");
    AAFwk::WantParams wantParam;
    bool isPhotoType = false;
    bool isVideoType = false;
    for (auto type : mediaTypes) {
        MEDIA_INFO_LOG("SetPickerWantParams current type is:%{public}d", type);
        switch (type) {
            case PickerMediaType::PHOTO:
                isPhotoType = true;
                break;
            case PickerMediaType::VIDEO:
                isVideoType = true;
                break;
        }
    }

    want.SetUri(pickerProfile.saveUri);
    want.SetFlags(AAFwk::Want::FLAG_AUTH_READ_URI_PERMISSION | AAFwk::Want::FLAG_AUTH_WRITE_URI_PERMISSION);
    wantParam.SetParam("ability.want.params.uiExtensionTargetType", AAFwk::String::Box("cameraPicker"));
    wantParam.SetParam("callBundleName", AAFwk::String::Box(abilityContext->GetAbilityInfo()->bundleName.c_str()));
    wantParam.SetParam("cameraPosition", AAFwk::Integer::Box(pickerProfile.cameraPosition));
    wantParam.SetParam("videoDuration", AAFwk::Integer::Box(pickerProfile.videoDuration));
    wantParam.SetParam("saveUri", AAFwk::String::Box(pickerProfile.saveUri.c_str()));
    if (isPhotoType && isVideoType) {
        wantParam.SetParam("supportMultiMode", AAFwk::Boolean::Box(true));
    }
    want.SetParams(wantParam);
    if (isPhotoType) {
        want.SetAction(CAMERA_PICKER_ABILITY_ACTION_PHOTO);
    } else if (isVideoType) {
        want.SetAction(CAMERA_PICKER_ABILITY_ACTION_VIDEO);
    } else {
        MEDIA_ERR_LOG("SetPickerWantParams set action fail!");
    }
    MEDIA_DEBUG_LOG("SetPickerWantParams end");
}

static void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    MEDIA_INFO_LOG("CommonCompleteCallback is called");
    napi_value callbackObj = nullptr;
    napi_value resultCode = nullptr;
    napi_value resultUri = nullptr;
    napi_value resultMediaType = nullptr;
    auto context = static_cast<CameraPickerAsyncContext*>(data);
    if (context == nullptr) {
        MEDIA_ERR_LOG("Async context is null");
        return;
    }

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();

    if (!context->status) {
        CameraNapiUtils::CreateNapiErrorObject(env, context->errorCode, context->errorMsg.c_str(), jsContext);
    } else {
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
        if (!context->bRetBool) {
            napi_create_object(env, &callbackObj);
            napi_create_int32(env, context->uiExtCallback->GetResultCode(), &resultCode);
            napi_set_named_property(env, callbackObj, "resultCode", resultCode);
            napi_create_string_utf8(env, context->uiExtCallback->GetResultUri().c_str(), NAPI_AUTO_LENGTH, &resultUri);
            napi_set_named_property(env, callbackObj, "resultUri", resultUri);
            napi_create_string_utf8(
                env, context->uiExtCallback->GetResultMediaType().c_str(), NAPI_AUTO_LENGTH, &resultMediaType);
            napi_set_named_property(env, callbackObj, "mediaType", resultMediaType);
            jsContext->data = callbackObj;
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    }

    if (!context->funcName.empty() && context->taskId > 0) {
        // Finish async trace
        CAMERA_FINISH_ASYNC_TRACE(context->funcName, context->taskId);
        jsContext->funcName = context->funcName;
    }

    if (context->work != nullptr) {
        CameraNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

static std::shared_ptr<UIExtensionCallback> StartCameraAbility(
    napi_env env, std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext, AAFwk::Want& want)
{
    auto uiExtCallback = std::make_shared<UIExtensionCallback>(abilityContext);
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        std::bind(&UIExtensionCallback::OnRelease, uiExtCallback, std::placeholders::_1),
        std::bind(&UIExtensionCallback::OnResult, uiExtCallback, std::placeholders::_1, std::placeholders::_2),
        std::bind(&UIExtensionCallback::OnReceive, uiExtCallback, std::placeholders::_1),
        std::bind(&UIExtensionCallback::OnError, uiExtCallback, std::placeholders::_1, std::placeholders::_2,
            std::placeholders::_3),
        std::bind(&UIExtensionCallback::OnRemoteReady, uiExtCallback, std::placeholders::_1),
        std::bind(&UIExtensionCallback::OnDestroy, uiExtCallback)
    };
    Ace::ModalUIExtensionConfig config;
    auto uiContent = abilityContext->GetUIContent();
    if (uiContent == nullptr) {
        MEDIA_ERR_LOG("StartCameraAbility fail uiContent is null");
        return nullptr;
    }
    int32_t sessionId = uiContent->CreateModalUIExtension(want, extensionCallbacks, config);
    MEDIA_DEBUG_LOG("StartCameraAbility CreateModalUIExtension session id is %{public}d", sessionId);
    if (sessionId == 0) {
        MEDIA_ERR_LOG("StartCameraAbility CreateModalUIExtension fail");
        return nullptr;
    }
    uiExtCallback->SetSessionId(sessionId);
    return uiExtCallback;
}

static napi_status StartAsyncWork(napi_env env, CameraPickerAsyncContext* pickerAsyncCtx)
{
    napi_value resource = nullptr;
    CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "Pick");
    MEDIA_INFO_LOG("CameraPicker StartAsyncWork");
    return napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void* data) {
            MEDIA_INFO_LOG("CameraPicker wait result begin");
            auto context = static_cast<CameraPickerAsyncContext*>(data);
            context->status = false;
            // Start async trace

            CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
            context->bRetBool = false;

            context->uiExtCallback->WaitResultLock();
            MEDIA_INFO_LOG("CameraPicker wait result end");
            context->status = true;
        },
        CommonCompleteCallback, static_cast<void*>(pickerAsyncCtx), &pickerAsyncCtx->work);
}

napi_value CameraPickerNapi::Pick(napi_env env, napi_callback_info cbInfo)
{
    MEDIA_INFO_LOG("CameraPicker::Pick is called");
    CAMERA_SYNC_TRACE;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE];
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_cb_info failed");
        return result;
    }

    if (argc < ARGS_THREE) {
        MEDIA_ERR_LOG("the parameter of number should be at least three");
        return result;
    }

    std::unique_ptr<CameraPickerAsyncContext> asyncCtx = std::make_unique<CameraPickerAsyncContext>();
    asyncCtx->funcName = "CameraPickerNapi::Pick";
    asyncCtx->taskId = CameraNapiUtils::IncreamentAndGet(cameraPickerTaskId);
    asyncCtx->abilityContext = GetAbilityContext(env, argv[ARGS_ZERO]);
    if (asyncCtx->abilityContext == nullptr) {
        MEDIA_ERR_LOG("GetAbilityContext failed");
        return result;
    }

    std::vector<PickerMediaType> mediaTypes;
    if (!GetMediaTypes(env, argv[ARGS_ONE], mediaTypes)) {
        MEDIA_ERR_LOG("GetMediaTypes failed");
        return result;
    }

    if (!GetPickerProfile(env, argv[ARGS_TWO], asyncCtx->pickerProfile)) {
        MEDIA_ERR_LOG("GetPhotoProfiles failed");
        return result;
    }
    SetPickerWantParams(asyncCtx->want, asyncCtx->abilityContext, mediaTypes, asyncCtx->pickerProfile);
    asyncCtx->uiExtCallback = StartCameraAbility(env, asyncCtx->abilityContext, asyncCtx->want);
    if (asyncCtx->uiExtCallback == nullptr) {
        MEDIA_ERR_LOG("StartCameraAbility failed");
        return result;
    }
    CAMERA_NAPI_CREATE_PROMISE(env, asyncCtx->callbackRef, asyncCtx->deferred, result);
    if (StartAsyncWork(env, asyncCtx.get()) != napi_ok) {
        MEDIA_ERR_LOG("Failed to create napi_create_async_work for Pick");
        napi_get_undefined(env, &result);
    } else {
        napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated);
        asyncCtx.release();
    }
    return result;
}

napi_value CameraPickerNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_INFO_LOG("CameraPickerNapi::Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor camera_picker_props[] = {};

    napi_property_descriptor camera_picker_static_props[] = {
        DECLARE_NAPI_STATIC_FUNCTION("pick", Pick),
        DECLARE_NAPI_PROPERTY("PickerMediaType", CreatePickerMediaType(env)),
        DECLARE_NAPI_PROPERTY("PickerProfile", CreatePickerProfile(env)),
        DECLARE_NAPI_PROPERTY("PickerResult", CreatePickerResult(env)),
    };

    status = napi_define_class(env, CAMERA_PICKER_NAPI_CLASS_NAME, NAPI_AUTO_LENGTH, CameraPickerNapiConstructor,
        nullptr, sizeof(camera_picker_props) / sizeof(camera_picker_props[PARAM0]), camera_picker_props, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, CAMERA_PICKER_NAPI_CLASS_NAME, ctorObj);
            if (status == napi_ok &&
                napi_define_properties(env, exports,
                    sizeof(camera_picker_static_props) / sizeof(camera_picker_static_props[PARAM0]),
                    camera_picker_static_props) == napi_ok) {
                return exports;
            }
        }
    }
    MEDIA_ERR_LOG("Init call Failed!");
    return nullptr;
}

napi_value CameraPickerNapi::CreatePickerProfile(napi_env env)
{
    MEDIA_DEBUG_LOG("CreatePickerProfile is called");
    napi_value result = nullptr;
    napi_status status;

    status = CameraNapiUtils::CreateObjectWithPropName(
        env, &result, sizeof(PICKER_PROFILE) / sizeof(PICKER_PROFILE[0]), const_cast<const char**>(PICKER_PROFILE));
    if (status != napi_ok) {
        MEDIA_DEBUG_LOG("CreatePickerProfile call end!");
        napi_get_undefined(env, &result);
    }
    return result;
}

napi_value CameraPickerNapi::CreatePickerMediaType(napi_env env)
{
    MEDIA_DEBUG_LOG("CreatePickerMediaType is called");
    napi_value result = nullptr;
    napi_status status;
    if (mediaTypeRef_ != nullptr) {
        status = napi_get_reference_value(env, mediaTypeRef_, &result);
        if (status == napi_ok) {
            return result;
        }
    }
    status = CameraNapiUtils::CreateObjectWithPropNameAndValues(env, &result,
        sizeof(PICKER_MEDIA_TYPE) / sizeof(PICKER_MEDIA_TYPE[0]), const_cast<const char**>(PICKER_MEDIA_TYPE),
        PICKER_MEDIA_TYPE_VALUE);
    if (status != napi_ok) {
        MEDIA_DEBUG_LOG("CreatePickerMediaType call end!");
        napi_get_undefined(env, &result);
    } else {
        napi_create_reference(env, result, 1, &mediaTypeRef_);
    }
    return result;
}

napi_value CameraPickerNapi::CreatePickerResult(napi_env env)
{
    MEDIA_DEBUG_LOG("CreatePickerResult is called");
    napi_value result = nullptr;
    napi_status status;

    status = CameraNapiUtils::CreateObjectWithPropName(
        env, &result, sizeof(PICKER_RESULT) / sizeof(PICKER_RESULT[0]), const_cast<const char**>(PICKER_RESULT));
    if (status != napi_ok) {
        MEDIA_ERR_LOG("CreatePickerResult call Failed!");
        napi_get_undefined(env, &result);
    }
    return result;
}

// Constructor callback
napi_value CameraPickerNapi::CameraPickerNapiConstructor(napi_env env, napi_callback_info info)
{
    MEDIA_DEBUG_LOG("CameraPickerNapiConstructor is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    CAMERA_NAPI_GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<CameraPickerNapi> obj = std::make_unique<CameraPickerNapi>();
        obj->env_ = env;
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            CameraPickerNapi::CameraPickerNapiDestructor, nullptr, nullptr);
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            MEDIA_ERR_LOG("Failure wrapping js to native napi");
        }
    }
    MEDIA_ERR_LOG("CameraPickerNapiConstructor call Failed!");
    return result;
}

void CameraPickerNapi::CameraPickerNapiDestructor(napi_env env, void* nativeObject, void* finalize_hint)
{
    MEDIA_DEBUG_LOG("CameraPickerNapiDestructor is called");
    CameraPickerNapi* camera = reinterpret_cast<CameraPickerNapi*>(nativeObject);
    if (camera != nullptr) {
        delete camera;
    }
}

UIExtensionCallback::UIExtensionCallback(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext)
{
    abilityContext_ = abilityContext;
}

void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    sessionId_ = sessionId;
}

bool UIExtensionCallback::SetErrorCode(int32_t code)
{
    {
        std::unique_lock<std::mutex> lock(cbMutex_);
        if (isCallbackReturned_) {
            MEDIA_ERR_LOG("alreadyCallback");
            return false;
        }
        isCallbackReturned_ = true;
    }
    resultCode_ = code;
    NotifyResultLock();
    return true;
}
void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnRelease(), releaseCode = %{public}d", releaseCode);
    if (SetErrorCode(releaseCode)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    const AAFwk::WantParams& wantParams = result.GetParams();
    std::string uri = wantParams.GetStringParam("resourceUri");
    std::string resourceMode = wantParams.GetStringParam("mode");
    MEDIA_INFO_LOG("OnResult is called,resultCode = %{public}d, uri = %{public}s ,CaptureMode:%{public}s", resultCode,
        uri.c_str(), resourceMode.c_str());
    resultUri_ = uri;
    resultMode_ = resourceMode;
    if (SetErrorCode(resultCode)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnReceive()");
}

void UIExtensionCallback::OnError(int32_t errorCode, const std::string& name, const std::string& message)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnError(), errorCode = %{public}d, name = %{public}s, message = %{public}s",
        errorCode, name.c_str(), message.c_str());
    if (SetErrorCode(errorCode)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnRemoteReady()");
}

void UIExtensionCallback::OnDestroy()
{
    MEDIA_INFO_LOG("UIExtensionComponent OnDestroy()");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::SendMessageBack()
{
    MEDIA_INFO_LOG("start SendMessageBack");
    auto abilityContext = abilityContext_.lock();
    if (abilityContext == nullptr) {
        MEDIA_ERR_LOG("reqContext is nullptr");
        return;
    }
    if (abilityContext != nullptr) {
        auto uiContent = abilityContext->GetUIContent();
        if (uiContent != nullptr) {
            MEDIA_INFO_LOG("CloseModalUIExtension");
            uiContent->CloseModalUIExtension(sessionId_);
        }
    }
}
} // namespace CameraStandard
} // namespace OHOS