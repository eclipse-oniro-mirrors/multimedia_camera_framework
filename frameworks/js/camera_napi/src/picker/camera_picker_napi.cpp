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
#include "camera_napi_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace {

constexpr char CAMERA_PICKER_BUNDLE_HAP_NAME[] = "com.huawei.hmos.camera";
constexpr char CAMERA_PICKER_BUNDLE_ABILITY_NAME[] = "com.huawei.hmos.camera.ExtensionPickerAbility";
constexpr char CAMERA_PICKER_ABILITY_ACTION_PHOTO[] = "ohos.want.action.imageCapture";
constexpr char CAMERA_PICKER_ABILITY_ACTION_VIDEO[] = "ohos.want.action.videoCapture";
} // namespace
using namespace std;

thread_local napi_ref CameraPickerNapi::sConstructor_ = nullptr;
thread_local napi_ref CameraPickerNapi::pickerPhotoProfile_ = nullptr;
thread_local napi_ref CameraPickerNapi::pickerVideoProfile_ = nullptr;
thread_local napi_ref CameraPickerNapi::pickerResult_ = nullptr;
thread_local uint32_t CameraPickerNapi::cameraPickerTaskId = CAMERA_PICKER_TASKID;
std::condition_variable cvFinish_;
std::string CameraPickerNapi::resultUri_ = "";
int32_t CameraPickerNapi::resultCode = -1;
std::mutex CameraPickerNapi::mutex_;
PhotoProfileForPicker CameraPickerNapi::photoProfile_ = {};
VideoProfileForPicker CameraPickerNapi::videoProfile_ = {};

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

static bool GetAbilityContext(const napi_env& env, const napi_value& value,
    std::shared_ptr<AbilityRuntime::AbilityContext>& abilityContext, Ace::UIContent** uiContent)
{
    MEDIA_ERR_LOG("CreateModalUIExtension is called");
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, value, stageMode);
    if (status != napi_ok || !stageMode) {
        MEDIA_ERR_LOG("It is not stage Mode");
        return false;
    }
    auto context = AbilityRuntime::GetStageModeContext(env, value);
    if (context == nullptr) {
        MEDIA_ERR_LOG("get context falled");
        return false;
    }
    abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        MEDIA_ERR_LOG("get stage mode ability context falled");
        return false;
    }
    *uiContent = abilityContext->GetUIContent();
    if (*uiContent == nullptr) {
        MEDIA_ERR_LOG("uiContent is nullptr");
        return false;
    }
    MEDIA_ERR_LOG("CameraPickerNapi GetAbilityContext SUCC");
    return true;
}

bool GetPhotoProfiles(const napi_env& env, const napi_value photoProfiles, PhotoProfileForPicker& photoProfile)
{
    MEDIA_ERR_LOG("CameraPicker::GetPhotoProfiles is called");
    napi_value value = nullptr;
    // get cameraPosition
    if (napi_get_named_property(env, photoProfiles, "cameraPosition", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    int32_t cameraPosition = 0;
    if (napi_get_value_int32(env, value, &cameraPosition) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_value_int32 failed");
        return false;
    }
    // get saveUri
    char saveUri[PATH_MAX];
    size_t length = 0;
    if (napi_get_named_property(env, photoProfiles, "saveUri", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    if (napi_get_value_string_utf8(env, value, saveUri, PATH_MAX, &length) != napi_ok) {
        MEDIA_ERR_LOG("get saveUri fail!");
        return false;
    }
    photoProfile.cameraPosition = static_cast<CameraPosition>(cameraPosition);
    photoProfile.saveUri = std::string(saveUri);
    CameraPickerNapi::photoProfile_ = photoProfile;
    MEDIA_ERR_LOG("GetPhotoProfiles cameraPosition: %{public}d,saveUri: %{public}s ", cameraPosition, saveUri);
    return true;
}

bool GetVideoProfiles(const napi_env& env, const napi_value videoProfiles, VideoProfileForPicker& videoProfile)
{
    MEDIA_ERR_LOG("GetVideoProfiles is called");
    napi_value value = nullptr;
    // get cameraPosition
    if (napi_get_named_property(env, videoProfiles, "cameraPosition", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    int32_t cameraPosition = 0;
    if (napi_get_value_int32(env, value, &cameraPosition) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_value_int32 failed");
        return false;
    }
    // get videoDuration
    if (napi_get_named_property(env, videoProfiles, "videoDuration", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    int32_t videoDuration = 0;
    if (napi_get_value_int32(env, value, &videoDuration) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_value_int32 failed");
        return false;
    }
    // get saveUri
    char saveUri[PATH_MAX];
    size_t length = 0;
    if (napi_get_named_property(env, videoProfiles, "saveUri", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    if (napi_get_value_string_utf8(env, value, saveUri, PATH_MAX, &length) != napi_ok) {
        MEDIA_ERR_LOG("get saveUri fail!");
        return false;
    }
    videoProfile.cameraPosition = static_cast<CameraPosition>(cameraPosition);
    videoProfile.videoDuration = videoDuration;
    videoProfile.saveUri = std::string(saveUri);
    CameraPickerNapi::videoProfile_ = videoProfile;
    MEDIA_ERR_LOG("GetVideoProfiles cameraPosition: %{public}d,videoDuration: %{public}d", cameraPosition, videoDuration);
    MEDIA_ERR_LOG("GetVideoProfiles saveUri: %{public}s", saveUri);
    return true;
}

void SetPhotoWantParams(AAFwk::Want& want, std::shared_ptr<AbilityRuntime::AbilityContext>& abilityContext)
{
    AAFwk::WantParams wantParam;

    want.SetElementName(CAMERA_PICKER_BUNDLE_HAP_NAME, CAMERA_PICKER_BUNDLE_ABILITY_NAME);
    wantParam.SetParam("ability.want.params.uiExtensionType", AAFwk::String::Box("sys/commonUI"));
    wantParam.SetParam("callFlag", AAFwk::String::Box("local"));
    wantParam.SetParam("abilityName", AAFwk::String::Box("MainAbility"));
    wantParam.SetParam("callBundleName", AAFwk::String::Box(abilityContext->GetAbilityInfo()->bundleName.c_str()));
    wantParam.SetParam("cameraPosition", AAFwk::Integer::Box(CameraPickerNapi::photoProfile_.cameraPosition));
    wantParam.SetParam("saveUri", AAFwk::String::Box(CameraPickerNapi::photoProfile_.saveUri.c_str()));
    want.SetParams(wantParam);
    want.SetAction(CAMERA_PICKER_ABILITY_ACTION_PHOTO);
}

void SetVideoWantParams(AAFwk::Want& want, std::shared_ptr<AbilityRuntime::AbilityContext>& abilityContext)
{
    AAFwk::WantParams wantParam;

    want.SetElementName(CAMERA_PICKER_BUNDLE_HAP_NAME, CAMERA_PICKER_BUNDLE_ABILITY_NAME);
    wantParam.SetParam("ability.want.params.uiExtensionType", AAFwk::String::Box("sys/commonUI"));
    wantParam.SetParam("callFlag", AAFwk::String::Box("local"));
    wantParam.SetParam("abilityName", AAFwk::String::Box("MainAbility"));
    wantParam.SetParam("callBundleName", AAFwk::String::Box(abilityContext->GetAbilityInfo()->bundleName.c_str()));
    wantParam.SetParam("cameraPosition", AAFwk::Integer::Box(CameraPickerNapi::videoProfile_.cameraPosition));
    wantParam.SetParam("videoDuration", AAFwk::Integer::Box(CameraPickerNapi::videoProfile_.videoDuration));
    wantParam.SetParam("saveUri", AAFwk::String::Box(CameraPickerNapi::photoProfile_.saveUri.c_str()));
    want.SetParams(wantParam);
    want.SetAction(CAMERA_PICKER_ABILITY_ACTION_VIDEO);
}

static void CommonCompleteCallback(napi_env env, napi_status status, void* data)
{
    MEDIA_ERR_LOG("CommonCompleteCallback is called");
    napi_value callbackObj = nullptr;
    napi_value resultCode = nullptr;
    napi_value resultUri = nullptr;
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
            napi_create_int32(env, CameraPickerNapi::resultCode, &resultCode);
            napi_set_named_property(env, callbackObj, "resultCode", resultCode);
            napi_create_string_utf8(env, CameraPickerNapi::resultUri_.c_str(), NAPI_AUTO_LENGTH, &resultUri);
            napi_set_named_property(env, callbackObj, "resultUri", resultUri);
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

napi_value CameraPickerNapi::TakePhoto(napi_env env, napi_callback_info cbInfo)
{
    MEDIA_ERR_LOG("CameraPicker::takePhoto is called");
    CAMERA_SYNC_TRACE;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO];
    napi_value thisVar = nullptr;
    napi_status status;

    std::unique_ptr<CameraPickerAsyncContext> asyncCtx = std::make_unique<CameraPickerAsyncContext>();
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_cb_info failed");
        return result;
    }

    if (argc < ARGS_TWO) {
        MEDIA_ERR_LOG("the paramter of number should be at least two");
        return result;
    }
    if (!GetAbilityContext(env, argv[0], asyncCtx->abilityContext, &asyncCtx->uiContent)) {
        MEDIA_ERR_LOG("GetAbilityContext failed");
        return result;
    }

    if (!GetPhotoProfiles(env, argv[1], asyncCtx->photoProfile)) {
        MEDIA_ERR_LOG("GetPhotoProfiles failed");
        return result;
    }

    SetPhotoWantParams(asyncCtx->want, asyncCtx->abilityContext);

    CAMERA_NAPI_GET_JS_ARGS(env, cbInfo, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 2 parameter maximum");
    napi_get_undefined(env, &result);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncCtx->objectInfo));

    if (status == napi_ok && asyncCtx->objectInfo != nullptr) {
        CAMERA_NAPI_CREATE_PROMISE(env, asyncCtx->callbackRef, asyncCtx->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "TakePhoto");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<CameraPickerAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CameraPickerNapi::TakePhoto";
                context->taskId = CameraNapiUtils::IncreamentAndGet(cameraPickerTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;

                    auto asyncContext = std::make_shared<UIExtensionRequestContext>(env);
                    asyncContext->context = context->abilityContext;
                    asyncContext->requestWant = context->want;
                    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
                    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
                        std::bind(&UIExtensionCallback::OnRelease, uiExtCallback, std::placeholders::_1),
                        std::bind(&UIExtensionCallback::OnResult, uiExtCallback, std::placeholders::_1, std::placeholders::_2),
                        std::bind(&UIExtensionCallback::OnReceive, uiExtCallback, std::placeholders::_1),
                        std::bind(&UIExtensionCallback::OnError, uiExtCallback, std::placeholders::_1,
                            std::placeholders::_2, std::placeholders::_3),
                        std::bind(&UIExtensionCallback::OnRemoteReady, uiExtCallback, std::placeholders::_1),
                        std::bind(&UIExtensionCallback::OnDestroy, uiExtCallback)
                    };
                    Ace::ModalUIExtensionConfig config;
                    if (napi_ok == context->uiContent->CreateModalUIExtension(context->want, extensionCallbacks, config)) {
                        MEDIA_ERR_LOG("Create modal ui extension is failed.");
                        return ;
                    }
                    std::unique_lock<std::mutex> lock(CameraPickerNapi::mutex_);
                    cvFinish_.wait(lock);
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncCtx.get()), &asyncCtx->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for TakePhoto");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated);
            asyncCtx.release();
        }
    } else {
        MEDIA_ERR_LOG("TakePhoto call Failed!");
    }
    return result;
}

napi_value CameraPickerNapi::RecordVideo(napi_env env, napi_callback_info cbInfo)
{
    MEDIA_ERR_LOG("CameraPicker::RecordVideo is called");
    CAMERA_SYNC_TRACE;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO];
    napi_value thisVar = nullptr;
    napi_status status;

    std::unique_ptr<CameraPickerAsyncContext> asyncCtx = std::make_unique<CameraPickerAsyncContext>();
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_cb_info failed");
        return result;
    }

    if (argc < ARGS_TWO) {
        MEDIA_ERR_LOG("the paramter of number should be at least two");
        return result;
    }
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    Ace::UIContent* uiContent;
    if (!GetAbilityContext(env, argv[0], asyncCtx->abilityContext, &asyncCtx->uiContent)) {
        MEDIA_ERR_LOG("GetAbilityContext failed");
        return result;
    }

    if (!GetVideoProfiles(env, argv[1], asyncCtx->videoProfile)) {
        MEDIA_ERR_LOG("GetVideoProfiles failed");
        return result;
    }

    SetVideoWantParams(asyncCtx->want, asyncCtx->abilityContext);

    CAMERA_NAPI_GET_JS_ARGS(env, cbInfo, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 2 parameter maximum");
    napi_get_undefined(env, &result);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncCtx->objectInfo));

    if (status == napi_ok && asyncCtx->objectInfo != nullptr) {
        CAMERA_NAPI_CREATE_PROMISE(env, asyncCtx->callbackRef, asyncCtx->deferred, result);
        CAMERA_NAPI_CREATE_RESOURCE_NAME(env, resource, "RecordVideo");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<CameraPickerAsyncContext*>(data);
                context->status = false;
                // Start async trace
                context->funcName = "CameraPickerNapi::RecordVideo";
                context->taskId = CameraNapiUtils::IncreamentAndGet(cameraPickerTaskId);
                CAMERA_START_ASYNC_TRACE(context->funcName, context->taskId);
                if (context->objectInfo != nullptr) {
                    context->bRetBool = false;
                    context->status = true;

                    auto asyncContext = std::make_shared<UIExtensionRequestContext>(env);
                    asyncContext->context = context->abilityContext;
                    asyncContext->requestWant = context->want;
                    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
                    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
                        std::bind(&UIExtensionCallback::OnRelease, uiExtCallback, std::placeholders::_1),
                        std::bind(&UIExtensionCallback::OnResult, uiExtCallback, std::placeholders::_1, std::placeholders::_2),
                        std::bind(&UIExtensionCallback::OnReceive, uiExtCallback, std::placeholders::_1),
                        std::bind(&UIExtensionCallback::OnError, uiExtCallback, std::placeholders::_1,
                            std::placeholders::_2, std::placeholders::_3),
                        std::bind(&UIExtensionCallback::OnRemoteReady, uiExtCallback, std::placeholders::_1),
                        std::bind(&UIExtensionCallback::OnDestroy, uiExtCallback)
                    };
                    Ace::ModalUIExtensionConfig config;
                    if (napi_ok == context->uiContent->CreateModalUIExtension(context->want, extensionCallbacks, config)) {
                        MEDIA_ERR_LOG("Create modal ui extension is failed.");
                        return ;
                    }
                    std::unique_lock<std::mutex> lock(CameraPickerNapi::mutex_);
                    cvFinish_.wait(lock);
                }
            },
            CommonCompleteCallback, static_cast<void*>(asyncCtx.get()), &asyncCtx->work);
        if (status != napi_ok) {
            MEDIA_ERR_LOG("Failed to create napi_create_async_work for RecordVideo");
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated);
            asyncCtx.release();
        }
    } else {
        MEDIA_ERR_LOG("RecordVideo call Failed!");
    }
    return result;
}

napi_status CameraPickerNapi::AddNamedProperty(napi_env env, napi_value object,
                                         const std::string name, int32_t enumValue)
{
    napi_status status;
    napi_value enumNapiValue;
    status = napi_create_int32(env, enumValue, &enumNapiValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, object, name.c_str(), enumNapiValue);
    }
    return status;
}

napi_value CameraPickerNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor camera_picker_props[] = {};

    napi_property_descriptor camera_picker_static_props[] = {
        DECLARE_NAPI_STATIC_FUNCTION("takePhoto", TakePhoto),
        DECLARE_NAPI_STATIC_FUNCTION("recordVideo", RecordVideo),
        DECLARE_NAPI_PROPERTY("PhotoProfileForPicker", CreatePickerPhotoProfile(env)),
        DECLARE_NAPI_PROPERTY("VideoProfileForPicker", CreatePickerVideoProfile(env)),
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

napi_value CameraPickerNapi::CreatePickerPhotoProfile(napi_env env)
{
    MEDIA_DEBUG_LOG("CreatePickerPhotoProfile is called");
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < pickerPhotoProfile.size(); i++) {
            propName = pickerPhotoProfile[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for pickerPhotoProfile!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &pickerPhotoProfile_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreatePickerPhotoProfile call Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraPickerNapi::CreatePickerVideoProfile(napi_env env)
{
    MEDIA_DEBUG_LOG("CreatePickerVideoProfile is called");
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < pickerVideoProfile.size(); i++) {
            propName = pickerVideoProfile[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for videoProfile!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &pickerVideoProfile_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreatePickerVideoProfile call Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraPickerNapi::CreatePickerResult(napi_env env)
{
    MEDIA_DEBUG_LOG("CreatePickerResult is called");
    napi_value result = nullptr;
    napi_status status;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        std::string propName;
        for (unsigned int i = 0; i < pickerResult.size(); i++) {
            propName = pickerResult[i];
            status = AddNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                MEDIA_ERR_LOG("Failed to add named prop for pickerResult!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        status = napi_create_reference(env, result, 1, &pickerResult_);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_ERR_LOG("CreatePickerResult call Failed!");
    napi_get_undefined(env, &result);

    return result;
}

napi_value CameraPickerNapi::CreateCameraPickerInstance(napi_env env, napi_callback_info info)
{
    MEDIA_ERR_LOG("CreateCameraPickerInstance is called");
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;

    CAMERA_NAPI_GET_JS_ARGS(env, info, argc, argv, thisVar);

    napi_get_undefined(env, &result);
    result = CameraPickerNapi::CreateCameraPicker(env);
    return result;
}

napi_value CameraPickerNapi::CreateCameraPicker(napi_env env)
{
    MEDIA_INFO_LOG("CreateCameraPicker is called");
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;

    status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        status = napi_new_instance(env, ctor, 0, nullptr, &result);
        if (status == napi_ok) {
            return result;
        } else {
            MEDIA_ERR_LOG("New instance could not be obtained");
        }
    }
    napi_get_undefined(env, &result);
    MEDIA_ERR_LOG("CreateCameraPicker call Failed!");
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

/* UIExtensionCallback */
CommonAsyncContext::CommonAsyncContext(napi_env napiEnv)
{
    env = napiEnv;
}

CommonAsyncContext::~CommonAsyncContext()
{
    if (callbackRef) {
        MEDIA_ERR_LOG("~CommonAsyncContext delete callbackRef");
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
    if (work) {
        MEDIA_ERR_LOG("~CommonAsyncContext delete work");
        napi_delete_async_work(env, work);
        work = nullptr;
    }
}

UIExtensionCallback::UIExtensionCallback(std::shared_ptr<UIExtensionRequestContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

bool UIExtensionCallback::SetErrorCode(int32_t code)
{
    if (this->reqContext_ == nullptr) {
        MEDIA_ERR_LOG("OnError reqContext is nullptr");
        return false;
    }
    if (this->alreadyCallback_) {
        MEDIA_ERR_LOG("alreadyCallback");
        return false;
    }
    this->alreadyCallback_ = true;
    this->reqContext_->errCode = code;
    return true;
}
void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    MEDIA_ERR_LOG("UIExtensionComponent OnRelease(), releaseCode = %{public}d", releaseCode);
    if (SetErrorCode(releaseCode)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    std::unique_lock<std::mutex> lock(CameraPickerNapi::mutex_);
    const AAFwk::WantParams &wantParams = result.GetParams();
    std::string uri = wantParams.GetStringParam("resourceUri");
    MEDIA_ERR_LOG("OnResult is called,resultCode = %{public}d, uri =  %{public}s", resultCode, uri.c_str());

    CameraPickerNapi::resultUri_ = uri;
    CameraPickerNapi::resultCode = resultCode;
    this->resultCode_ = resultCode;
    this->resultWant_ = result;
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
    cvFinish_.notify_one();
}

void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    MEDIA_ERR_LOG("UIExtensionComponent OnReceive()");
}

void UIExtensionCallback::OnError(int32_t errorCode, const std::string& name, const std::string& message)
{
    MEDIA_ERR_LOG("UIExtensionComponent OnError(), errorCode = %{public}d, name = %{public}s, message = %{public}s",
        errorCode, name.c_str(), message.c_str());
    if (SetErrorCode(errorCode)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy)
{
    MEDIA_ERR_LOG("UIExtensionComponent OnRemoteReady()");
}

void UIExtensionCallback::OnDestroy()
{
    MEDIA_ERR_LOG("UIExtensionComponent OnDestroy()");
    if (SetErrorCode(0)) {
        SendMessageBack();
    }
}

void UIExtensionCallback::SendMessageBack()
{
    MEDIA_ERR_LOG("start SendMessageBack");
    if (this->reqContext_ == nullptr) {
        MEDIA_ERR_LOG("reqContext is nullptr");
        return;
    }

    auto abilityContext = this->reqContext_->context;
    if (abilityContext != nullptr) {
        auto uiContent = abilityContext->GetUIContent();
        if (uiContent != nullptr) {
            MEDIA_ERR_LOG("CloseModalUIExtension");
            uiContent->CloseModalUIExtension(this->sessionId_);
        }
    }
}
} // namespace CameraStandard
} // namespace OHOS