/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "camera_picker_impl.h"
#include "bool_wrapper.h"
#include "cj_lambda.h"
#include "int_wrapper.h"
#include "string_wrapper.h"

using namespace std;

namespace OHOS::CameraStandard {
constexpr char CAMERA_PICKER_ABILITY_ACTION_PHOTO[] = "ohos.want.action.imageCapture";
constexpr char CAMERA_PICKER_ABILITY_ACTION_VIDEO[] = "ohos.want.action.videoCapture";

thread_local uint32_t cameraPickerTaskId = 0x08000000;

std::function<void(int32_t, std::string, std::string)> onResultCallBack = nullptr;

struct AsyncContext {
    bool status;
    int32_t taskId;
    int32_t errorCode;
    std::string errorMsg;
    std::string funcName;
    bool isInvalidArgument;
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

static string PickerMediaTypeToString(int32_t type)
{
    if (type == 0) {
        return "photo";
    }
    return "video";
}

static int32_t StringToPickerMediaType(std::string type)
{
    if (type == "photo") {
        return 0;
    }
    return 1;
}

static vector<string> CArrI32ToVector(const CArrI32 &cArr)
{
    vector<string> ret;
    for (int64_t i = 0; i < cArr.size; i++) {
        ret.emplace_back(PickerMediaTypeToString(cArr.head[i]));
    }
    return ret;
}

char *MallocCString(const std::string &origin)
{
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

UIExtensionCallback::UIExtensionCallback(std::shared_ptr<PickerContextProxy> contextProxy) : contextProxy_(contextProxy)
{
}

bool UIExtensionCallback::FinishPicker(int32_t code)
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
    CloseWindow();
    NotifyResultLock();
    return true;
}

void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnRelease(), releaseCode = %{public}d", releaseCode);
    FinishPicker(releaseCode);
}

void UIExtensionCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result)
{
    const AAFwk::WantParams &wantParams = result.GetParams();
    std::string uri = wantParams.GetStringParam("resourceUri");
    std::string resourceMode = wantParams.GetStringParam("mode");
    MEDIA_INFO_LOG("OnResult is called,resultCode = %{public}d, uri = %{public}s ,CaptureMode:%{public}s", resultCode,
                   uri.c_str(), resourceMode.c_str());
    resultUri_ = uri;
    resultMode_ = resourceMode;
    FinishPicker(resultCode);
    if (onResultCallBack != nullptr) {
        onResultCallBack(resultCode, uri, resourceMode);
    }
}

void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnReceive()");
}

void UIExtensionCallback::OnError(int32_t errorCode, const std::string &name, const std::string &message)
{
    MEDIA_INFO_LOG("UIExtensionComponent OnError(), errorCode = %{public}d, name = %{public}s, message = %{public}s",
                   errorCode, name.c_str(), message.c_str());
    FinishPicker(errorCode);
}

void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy)
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
    if (contextProxy_ == nullptr) {
        MEDIA_ERR_LOG("contextProxy_ is nullptr");
        return;
    }
    auto uiContent = contextProxy_->GetUIContent();
    if (uiContent != nullptr && sessionId_ != 0) {
        MEDIA_INFO_LOG("CloseModalUIExtension");
        uiContent->CloseModalUIExtension(sessionId_);
    }
}

static void SetPickerWantParams(AAFwk::Want &want, std::shared_ptr<PickerContextProxy> &pickerContextProxy,
                                const vector<string> &mediaTypes, PickerProfile &pickerProfile)
{
    MEDIA_DEBUG_LOG("SetPickerWantParams enter");
    AAFwk::WantParams wantParam;
    bool isPhotoType = false;
    bool isVideoType = false;
    for (auto type : mediaTypes) {
        MEDIA_INFO_LOG("SetPickerWantParams current type is:%{public}s", type.c_str());
        if (type.compare(std::string("photo")) == 0) {
            isPhotoType = true;
        } else if (type.compare(std::string("video")) == 0) {
            isVideoType = true;
        }
    }

    want.SetUri(pickerProfile.saveUri);
    want.SetFlags(AAFwk::Want::FLAG_AUTH_READ_URI_PERMISSION | AAFwk::Want::FLAG_AUTH_WRITE_URI_PERMISSION);
    wantParam.SetParam("ability.want.params.uiExtensionTargetType", AAFwk::String::Box("cameraPicker"));
    wantParam.SetParam("callBundleName", AAFwk::String::Box(pickerContextProxy->GetBundleName().c_str()));
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

static std::shared_ptr<UIExtensionCallback> StartCameraAbility(std::shared_ptr<PickerContextProxy> pickerContextProxy,
                                                               AAFwk::Want &want)
{
    auto uiExtCallback = std::make_shared<UIExtensionCallback>(pickerContextProxy);
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](int32_t resultCode, const OHOS::AAFwk::Want &result) {
            uiExtCallback->OnResult(resultCode, result);
        },
        [uiExtCallback](const OHOS::AAFwk::WantParams &request) { uiExtCallback->OnReceive(request); },
        [uiExtCallback](int32_t errorCode, const std::string &name, const std::string &message) {
            uiExtCallback->OnError(errorCode, name, message);
        },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); }};
    AbilityRuntime::RuntimeTask task = [extensionCallbacks](const int32_t code, const AAFwk::Want &returnWant,
                                                            bool isInner) {
        if (code == 0) {
            extensionCallbacks.onResult(0, returnWant);
        } else {
            extensionCallbacks.onError(code, "", "");
        }
        MEDIA_INFO_LOG("picker StartCameraAbility get result %{public}d %{public}d", code, isInner);
    };

    auto ret = pickerContextProxy->StartAbilityForResult(want, 1, std::move(task));
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("picker StartCameraAbility is %{public}d", ret);
        return nullptr;
    }
    return uiExtCallback;
}

static int32_t IncrementAndGet(uint32_t &num)
{
    int32_t temp = num & 0x00ffffff;
    if (temp >= 0xffff) {
        num = num & 0xff000000;
    }
    num++;
    return num;
}

void Pick(OHOS::AbilityRuntime::Context *context, CArrI32 pickerMediaTypes, CJPickerProfile pickerProfile,
          int64_t callbackId)
{
    auto cFunc = reinterpret_cast<void (*)(CJPickerResult result)>(callbackId);
    onResultCallBack = [lambda = CJLambda::Create(cFunc)](int32_t resultCode, std::string uri,
                                                          std::string type) -> void {
        auto resultUri = MallocCString(uri);
        auto mediaType = StringToPickerMediaType(type);
        lambda(CJPickerResult{resultCode, resultUri, mediaType});
        free(resultUri);
    };

    MEDIA_INFO_LOG("CameraPicker::Pick is called");
    std::unique_ptr<CameraPickerAsyncContext> asyncCtx = std::make_unique<CameraPickerAsyncContext>();
    auto contextSharedPtr = context->shared_from_this();
    auto abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(contextSharedPtr);
    asyncCtx->funcName = "CameraPicker::Pick";
    asyncCtx->taskId = IncrementAndGet(cameraPickerTaskId);
    asyncCtx->contextProxy = make_shared<PickerContextProxy>(abilityContext);
    if (asyncCtx->contextProxy == nullptr) {
        MEDIA_ERR_LOG("GetAbilityContext failed");
        return;
    }
    auto mediaTypes = CArrI32ToVector(pickerMediaTypes);
    asyncCtx->pickerProfile.cameraPosition = static_cast<CameraPosition>(pickerProfile.cameraPosition);
    asyncCtx->pickerProfile.videoDuration = pickerProfile.videoDuration;
    asyncCtx->pickerProfile.saveUri = std::string(pickerProfile.saveUri);
    MEDIA_INFO_LOG("GetPickerProfile cameraPosition: %{public}d, duration: %{public}d",
                   asyncCtx->pickerProfile.cameraPosition, asyncCtx->pickerProfile.videoDuration);
    MEDIA_INFO_LOG("GetPickerProfile saveUri: %{public}s", asyncCtx->pickerProfile.saveUri.c_str());
    SetPickerWantParams(asyncCtx->want, asyncCtx->contextProxy, mediaTypes, asyncCtx->pickerProfile);
    asyncCtx->uiExtCallback = StartCameraAbility(asyncCtx->contextProxy, asyncCtx->want);
    if (asyncCtx->uiExtCallback == nullptr) {
        MEDIA_ERR_LOG("StartCameraAbility failed");
        return;
    }
    return;
}
} // namespace OHOS::CameraStandard