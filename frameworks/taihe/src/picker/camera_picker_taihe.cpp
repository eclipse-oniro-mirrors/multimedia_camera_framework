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

#include <cstring>
#include "ani_base_context.h"
#include "bool_wrapper.h"
#include "ohos.multimedia.cameraPicker.proj.hpp"
#include "ohos.multimedia.cameraPicker.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "int_wrapper.h"
#include "camera_picker_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "parameters.h"
#include "string_wrapper.h"
#include "camera_worker_queue_keeper_taihe.h"

using namespace taihe;
using namespace ohos::multimedia::cameraPicker;
using namespace OHOS;

namespace Ani {
namespace Camera {
constexpr char CAMERA_PICKER_BUNDLE_HAP_NAME[] = "com.huawei.hmos.camera";
constexpr char CAMERA_PICKER_BUNDLE_ABILITY_NAME[] = "PickerAbility";
constexpr char CAMERA_PICKER_ABILITY_ACTION_PHOTO[] = "ohos.want.action.imageCapture";
constexpr char CAMERA_PICKER_ABILITY_ACTION_VIDEO[] = "ohos.want.action.videoCapture";
constexpr char CAMERA_PICKER_BUNDLE_ABILITY_NAME_FOR_UIEXTENSION[] = "com.huawei.hmos.camera.ExtensionPickerAbility";
const size_t MAX_MEDIA_TYPES_SIZE = 100;

enum PickerAbilityType { UIABILITY, UIEXTENSION };
static PickerAbilityType g_pickerAbilityType = UIABILITY;

static std::shared_ptr<PickerContextProxy> GetAbilityContext(ani_env* env, uintptr_t value)
{
    MEDIA_DEBUG_LOG("GetAbilityContext is called");
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, reinterpret_cast<ani_object>(value));
    CHECK_RETURN_RET_ELOG(context == nullptr, nullptr, "GetAbilityContext get context failed context");
    auto contextProxy = std::make_shared<PickerContextProxy>(context);
    CHECK_RETURN_RET_ELOG(contextProxy == nullptr || contextProxy->GetType() == PickerContextType::UNKNOWN, nullptr,
        "GetAbilityContext AbilityRuntime convert context failed");
    if (contextProxy->GetType() == PickerContextType::UI_EXTENSION) {
        MEDIA_INFO_LOG("GetAbilityContext type is UI_EXTENSION");
    } else if (contextProxy->GetType() == PickerContextType::ABILITY) {
        MEDIA_INFO_LOG("GetAbilityContext type is ABILITY");
    } else {
        // Do nothing.
    }
    MEDIA_DEBUG_LOG("CameraPickerNapi GetAbilityContext success");
    return contextProxy;
}

static void SetPickerWantParams(AAFwk::Want& want, std::shared_ptr<PickerContextProxy>& pickerContextProxy,
    array_view<PickerMediaType>& mediaTypes, PickerProfile const& pickerProfile)
{
    MEDIA_DEBUG_LOG("SetPickerWantParams enter");
    AAFwk::WantParams wantParam;
    bool isPhotoType = false;
    bool isVideoType = false;
    CHECK_RETURN_ELOG(mediaTypes.size() > MAX_MEDIA_TYPES_SIZE, "mediaTypes size exceeds maximum allowed size");
    for (size_t i = 0; i < mediaTypes.size(); i++) {
        if (strcmp(mediaTypes[i].get_value(), "photo") == 0) {
            isPhotoType = true;
        } else if (strcmp(mediaTypes[i].get_value(), "video") == 0) {
            isVideoType = true;
        } else {
            // Do nothing.
        }
    }

    if (g_pickerAbilityType == UIABILITY) {
        want.SetElementName(CAMERA_PICKER_BUNDLE_HAP_NAME, CAMERA_PICKER_BUNDLE_ABILITY_NAME);
    } else {
        want.SetElementName(CAMERA_PICKER_BUNDLE_HAP_NAME, CAMERA_PICKER_BUNDLE_ABILITY_NAME_FOR_UIEXTENSION);
    }
    want.SetFlags(AAFwk::Want::FLAG_AUTH_READ_URI_PERMISSION | AAFwk::Want::FLAG_AUTH_WRITE_URI_PERMISSION);
    if (pickerProfile.saveUri.has_value()) {
        std::string uriValue = std::string(pickerProfile.saveUri.value());
        want.SetUri(uriValue);
        wantParam.SetParam("saveUri", AAFwk::String::Box(uriValue.c_str()));
    }
    if (g_pickerAbilityType == UIABILITY) {
        wantParam.SetParam("ability.want.params.uiExtensionTargetType", AAFwk::String::Box("cameraPicker"));
    } else {
        wantParam.SetParam("ability.want.params.uiExtensionType", AAFwk::String::Box("sys/commonUI"));
    }
    wantParam.SetParam("callBundleName", AAFwk::String::Box(pickerContextProxy->GetBundleName().c_str()));
    wantParam.SetParam("cameraPosition", AAFwk::Integer::Box(
        static_cast<OHOS::CameraStandard::CameraPosition>(pickerProfile.cameraPosition.get_value())));
    if (pickerProfile.videoDuration.has_value()) {
        wantParam.SetParam("videoDuration", AAFwk::Integer::Box(pickerProfile.videoDuration.value()));
    }

    CHECK_EXECUTE(isPhotoType && isVideoType, wantParam.SetParam("supportMultiMode", AAFwk::Boolean::Box(true)));
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

static std::shared_ptr<UIExtensionCallback> StartCameraAbility(
    std::shared_ptr<PickerContextProxy> pickerContextProxy, AAFwk::Want& want)
{
    auto uiExtCallback = std::make_shared<UIExtensionCallback>(pickerContextProxy);
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](int32_t resultCode, const OHOS::AAFwk::Want& result) {
            uiExtCallback->OnResult(resultCode, result); },
        [uiExtCallback](const OHOS::AAFwk::WantParams& request) { uiExtCallback->OnReceive(request); },
        [uiExtCallback](int32_t errorCode, const std::string& name, const std::string& message) {
            uiExtCallback->OnError(errorCode, name, message); },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy); },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); }
    };
    AbilityRuntime::RuntimeTask task = [extensionCallbacks](
                                           const int32_t code, const AAFwk::Want& returnWant, bool isInner) {
        if (code == 0) {
            extensionCallbacks.onResult(0, returnWant);
        } else {
            extensionCallbacks.onError(code, "", "");
        }
        MEDIA_INFO_LOG("picker StartCameraAbility get result %{public}d %{public}d", code, isInner);
    };

    auto ret = pickerContextProxy->StartAbilityForResult(want, 1, std::move(task));
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("picker StartCameraAbility picker StartCameraAbility is %{public}d", ret);
        return nullptr;
    }
    return uiExtCallback;
}

static std::shared_ptr<UIExtensionCallback> StartCameraAbilityForUIExtension(
    std::shared_ptr<PickerContextProxy> pickerContextProxy, AAFwk::Want& want)
{
    auto uiExtCallback = std::make_shared<UIExtensionCallback>(pickerContextProxy);
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](int32_t resultCode, const OHOS::AAFwk::Want& result) {
            uiExtCallback->OnResult(resultCode, result); },
        [uiExtCallback](const OHOS::AAFwk::WantParams& request) { uiExtCallback->OnReceive(request); },
        [uiExtCallback](int32_t errorCode, const std::string& name, const std::string& message) {
            uiExtCallback->OnError(errorCode, name, message); },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy); },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); }
    };

    Ace::ModalUIExtensionConfig config;
    auto uiContent = pickerContextProxy->GetUIContent();
    if (uiContent == nullptr) {
        MEDIA_ERR_LOG("StartCameraAbilityForUIExtension fail uiContent is null");
        return nullptr;
    }
    int32_t sessionId = uiContent->CreateModalUIExtension(want, extensionCallbacks, config);
    MEDIA_DEBUG_LOG("StartCameraAbilityForUIExtension CreateModalUIExtension session id is %{public}d", sessionId);
    if (sessionId == 0) {
        MEDIA_ERR_LOG("StartCameraAbilityForUIExtension CreateModalUIExtension fail");
        return nullptr;
    }
    uiExtCallback->SetSessionId(sessionId);
    return uiExtCallback;
}

int64_t CameraPickerJsAsyncContextImpl::GetSpecificImplPtr()
{
    return reinterpret_cast<uintptr_t>(this);
}

UIExtensionCallback::UIExtensionCallback(std::shared_ptr<PickerContextProxy> contextProxy) : contextProxy_(contextProxy)
{}

bool UIExtensionCallback::FinishPicker(int32_t code)
{
    {
        std::unique_lock<std::mutex> lock(cbMutex_);
        CHECK_RETURN_RET_ELOG(isCallbackReturned_, false, "alreadyCallback");
        isCallbackReturned_ = true;
    }
    resultCode_ = code;
    CloseWindow();
    NotifyResultLock();
    return true;
}

void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnRelease(), releaseCode = %{public}d", releaseCode);
    FinishPicker(releaseCode);
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
    FinishPicker(resultCode);
}

void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams& request)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnReceive()");
    if (g_pickerAbilityType == UIABILITY) {
        return;
    }

    int32_t code = request.GetIntParam("code", 0);
    MEDIA_INFO_LOG("UIExtensionCallback::OnReceive get code %{public}d", code);
    if (code == 1) { // 1 is page appear.
        if (contextProxy_ == nullptr || sessionId_ == 0) {
            MEDIA_ERR_LOG("UIExtensionCallback::OnReceive contextProxy_ or sessionId_ illegal");
            return;
        }
        auto uiContent = contextProxy_->GetUIContent();
        if (uiContent == nullptr) {
            MEDIA_ERR_LOG("UIExtensionCallback::OnReceive uiContent is null");
            return;
        }
        Ace::ModalUIExtensionAllowedUpdateConfig updateConfig;
        updateConfig.prohibitedRemoveByNavigation = false;
        uiContent->UpdateModalUIExtensionConfig(sessionId_, updateConfig);
        MEDIA_INFO_LOG("UIExtensionComponent OnReceive() UpdateModalUIExtensionConfig done");
    }
}

void UIExtensionCallback::OnError(int32_t errorCode, const std::string& name, const std::string& message)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnError(), errorCode = %{public}d, name = %{public}s, message = %{public}s",
        errorCode, name.c_str(), message.c_str());
    FinishPicker(errorCode);
}

void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnRemoteReady()");
}

void UIExtensionCallback::OnDestroy()
{
    MEDIA_INFO_LOG("UIExtensionComponent OnDestroy()");
    FinishPicker(0);
}

void UIExtensionCallback::CloseWindow()
{
    MEDIA_INFO_LOG("start CloseWindow");
    CHECK_RETURN_ELOG(contextProxy_ == nullptr, "contextProxy_ is nullptr");
    if (sessionId_ == 0) {
        MEDIA_WARNING_LOG("sessionId_ is 0");
        return;
    }
    auto uiContent = contextProxy_->GetUIContent();
    if (uiContent != nullptr) {
        MEDIA_INFO_LOG("CloseModalUIExtension");
        uiContent->CloseModalUIExtension(sessionId_);
    }
}

static void InitPickerAbilityType(std::unique_ptr<CameraPickerAsyncContext>& asyncCtx)
{
    static bool inited = false;
    if (inited) {
        return;
    }
    std::string deviceType = system::GetParameter("const.product.devicetype", "");
    MEDIA_INFO_LOG("CameraPickerNapi::Pick GetParameter deviceType is:%{public}s", deviceType.c_str());
    if (deviceType.empty()) {
        deviceType = system::GetParameter("const.build.characteristics", "");
        MEDIA_INFO_LOG("CameraPickerNapi::Pick GetParameter characteristics is:%{public}s", deviceType.c_str());
    }
    if (deviceType == "tv") {
        MEDIA_INFO_LOG("CameraPickerNapi::Pick get device type is tv");
        g_pickerAbilityType = UIEXTENSION;
    }
    inited = true;
}

CameraPickerJsAsyncContext PickStart(
    uintptr_t context, array_view<PickerMediaType> mediaTypes, PickerProfile const& pickerProfile)
{
    MEDIA_INFO_LOG("CameraPicker PickStart");
    CameraPickerJsAsyncContext res =
        make_holder<CameraPickerJsAsyncContextImpl, CameraPickerJsAsyncContext>(nullptr);
    std::unique_ptr<CameraPickerAsyncContext> asyncCtx = std::make_unique<CameraPickerAsyncContext>();
    asyncCtx->contextProxy = GetAbilityContext(get_env(), context);
    CHECK_RETURN_RET_ELOG(asyncCtx->contextProxy == nullptr, res, "GetAbilityContext failed");
    InitPickerAbilityType(asyncCtx);
    SetPickerWantParams(asyncCtx->want, asyncCtx->contextProxy, mediaTypes, pickerProfile);
    asyncCtx->uiExtCallback = g_pickerAbilityType == UIABILITY
                                  ? StartCameraAbility(asyncCtx->contextProxy, asyncCtx->want)
                                  : StartCameraAbilityForUIExtension(asyncCtx->contextProxy, asyncCtx->want);
    CHECK_RETURN_RET_ELOG(asyncCtx->uiExtCallback == nullptr, res, "StartCameraAbility failed");
    MEDIA_INFO_LOG("CameraPicker PickStart end");
    return make_holder<CameraPickerJsAsyncContextImpl, CameraPickerJsAsyncContext>(std::move(asyncCtx));
}

void PickAsync(ohos::multimedia::cameraPicker::weak::CameraPickerJsAsyncContext asyncContext)
{
    MEDIA_INFO_LOG("CameraPicker PickAsync");
    auto ctxImpl = reinterpret_cast<CameraPickerJsAsyncContextImpl *>(asyncContext->GetSpecificImplPtr());
    CHECK_RETURN(ctxImpl == nullptr);
    auto ctx = ctxImpl->GetCameraPickerAsyncContext();
    CHECK_RETURN(ctx == nullptr);
    ctx->bRetBool = false;
    ctx->uiExtCallback->WaitResultLock();
    MEDIA_INFO_LOG("CameraPicker PickAsync end");
}

PickerResult GetPickerResult(ohos::multimedia::cameraPicker::weak::CameraPickerJsAsyncContext asyncContext)
{
    MEDIA_INFO_LOG("CameraPicker GetPickerResult");
    PickerResult res = {.resultCode = -1, .resultUri = "", .mediaType = PickerMediaType::key_t::PHOTO};
    auto ctxImpl = reinterpret_cast<CameraPickerJsAsyncContextImpl *>(asyncContext->GetSpecificImplPtr());
    CHECK_RETURN_RET_ELOG(ctxImpl == nullptr, res, "ctxImpl is nullptr");
    auto ctx = ctxImpl->GetCameraPickerAsyncContext();
    CHECK_RETURN_RET_ELOG(ctx == nullptr, res, "ctx is nullptr");
    if (!ctx->bRetBool) {
        res.resultCode = ctx->uiExtCallback->GetResultCode();
        res.resultUri = ctx->uiExtCallback->GetResultUri();
        if (strcmp(ctx->uiExtCallback->GetResultMediaType().c_str(), "photo") == 0) {
            res.mediaType = PickerMediaType::key_t::PHOTO;
        } else {
            res.mediaType = PickerMediaType::key_t::VIDEO;
        }
    }
    return res;
}
} // namespace Camera
} // namespace Ani

TH_EXPORT_CPP_API_PickStart(Ani::Camera::PickStart);
TH_EXPORT_CPP_API_PickAsync(Ani::Camera::PickAsync);
TH_EXPORT_CPP_API_GetPickerResult(Ani::Camera::GetPickerResult);
