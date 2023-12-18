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
namespace {

constexpr char CAMERA_PICKER_BUNDLE_HAP_NAME[] = "com.huawei.hmos.camera";
constexpr char CAMERA_PICKER_BUNDLE_ABILITY_NAME[] = "com.huawei.hmos.camera.ExtensionPickerAbility";
constexpr char CAMERA_PICKER_ABILITY_ACTION_PHOTO[] = "ohos.want.action.imageCapture";
constexpr char CAMERA_PICKER_ABILITY_ACTION_VIDEO[] = "ohos.want.action.videoCapture";
} // namespace
using namespace std;

thread_local napi_ref CameraPickerNapi::sConstructor_ = nullptr;
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
    MEDIA_DEBUG_LOG("CameraPickerNapi GetAbilityContext SUCC");
    return true;
}

bool GetPhotoProfiles(const napi_env& env, const napi_value photoProfiles, PhotoProfileForPicker& photoProfile)
{
    MEDIA_ERR_LOG("CameraPicker::GetPhotoProfiles is called");
    napi_value value = nullptr;
    if (napi_get_named_property(env, photoProfiles, "cameraPosition", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    int32_t cameraPosition = 0;
    if (napi_get_value_int32(env, value, &cameraPosition) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_value_int32 failed");
        return false;
    }

    photoProfile.cameraPosition = static_cast<CameraPosition>(cameraPosition);
    MEDIA_ERR_LOG("CameraPicker::GetPhotoProfiles cameraPosition = %{public}d ", cameraPosition);
    return true;
}

bool GetVideoProfiles(const napi_env& env, const napi_value videoProfiles, VideoProfileForPicker& videoProfile)
{
    MEDIA_ERR_LOG("CameraPicker::GetVideoProfiles is called");
    napi_value value = nullptr;
    if (napi_get_named_property(env, videoProfiles, "cameraPosition", &value) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_named_property failed");
        return false;
    }
    int32_t cameraPosition = 0;
    if (napi_get_value_int32(env, value, &cameraPosition) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_value_int32 failed");
        return false;
    }
    videoProfile.cameraPosition = static_cast<CameraPosition>(cameraPosition);
    MEDIA_ERR_LOG("CameraPicker::GetVideoProfiles cameraPosition = %{public}d ", cameraPosition);
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
    want.SetParams(wantParam);
    want.SetAction(CAMERA_PICKER_ABILITY_ACTION_VIDEO);
}

napi_value CameraPickerNapi::TakePhoto(napi_env env, napi_callback_info cbInfo)
{
    MEDIA_ERR_LOG("CameraPicker::takePhoto is called");
    CAMERA_SYNC_TRACE;
    napi_value result;
    napi_create_int32(env, napi_invalid_arg, &result);

    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO];
    napi_value thisVar = nullptr;

    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_cb_info failed");
        return result;
    }

    if (argc < ARGS_TWO) {
        MEDIA_ERR_LOG("the paramter of number should be at least one");
        return result;
    }
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    Ace::UIContent* uiContent;
    if (!GetAbilityContext(env, argv[0], abilityContext, &uiContent)) {
        MEDIA_ERR_LOG("GetAbilityContext failed");
        return result;
    }

    if (!GetPhotoProfiles(env, argv[1], photoProfile_)) {
        MEDIA_ERR_LOG("GetPhotoProfiles failed");
        return result;
    }
    CameraPickerNapi* nativeObject = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&nativeObject));
    if ((status != napi_ok) || (nativeObject == nullptr)) {
        MEDIA_ERR_LOG("napi_unwarp native request failed");
        return result;
    }

    AAFwk::Want want;
    SetPhotoWantParams(want, abilityContext);

    Ace::ModalUIExtensionCallbacks callback;
    Ace::ModalUIExtensionConfig config;
    if (napi_ok == uiContent->CreateModalUIExtension(want, callback, config)) {
        MEDIA_ERR_LOG("Create modal ui extension is failed.");
        return result;
    }

    napi_create_int32(env, napi_ok, &result);
    return result;
}

napi_value CameraPickerNapi::RecordVideo(napi_env env, napi_callback_info cbInfo)
{
    MEDIA_ERR_LOG("CameraPicker::RecordVideo is called");
    CAMERA_SYNC_TRACE;
    napi_value result;
    napi_create_int32(env, napi_invalid_arg, &result);

    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO];
    napi_value thisVar = nullptr;

    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        MEDIA_ERR_LOG("napi_get_cb_info failed");
        return result;
    }

    if (argc < ARGS_TWO) {
        MEDIA_ERR_LOG("the paramter of number should be at least one");
        return result;
    }
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext;
    Ace::UIContent* uiContent;
    if (!GetAbilityContext(env, argv[0], abilityContext, &uiContent)) {
        MEDIA_ERR_LOG("GetAbilityContext failed");
        return result;
    }

    if (!GetVideoProfiles(env, argv[1], videoProfile_)) {
        MEDIA_ERR_LOG("GetVideoProfiles failed");
        return result;
    }
    CameraPickerNapi* nativeObject = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&nativeObject));
    if ((status != napi_ok) || (nativeObject == nullptr)) {
        MEDIA_ERR_LOG("napi_unwarp native request failed");
        return result;
    }

    AAFwk::Want want;
    SetVideoWantParams(want, abilityContext);

    Ace::ModalUIExtensionCallbacks callback;
    Ace::ModalUIExtensionConfig config;
    if (napi_ok == uiContent->CreateModalUIExtension(want, callback, config)) {
        MEDIA_ERR_LOG("Create modal ui extension is failed.");
        return result;
    }

    napi_create_int32(env, napi_ok, &result);
    return result;
}

napi_value CameraPickerNapi::Init(napi_env env, napi_value exports)
{
    MEDIA_DEBUG_LOG("Init is called");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor camera_picker_props[] = {
        DECLARE_NAPI_FUNCTION("takePhoto", TakePhoto),
        DECLARE_NAPI_FUNCTION("recordVideo", RecordVideo),
    };

    napi_property_descriptor camera_picker_static_props[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getCameraPicker", CreateCameraPickerInstance),
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

} // namespace CameraStandard
} // namespace OHOS