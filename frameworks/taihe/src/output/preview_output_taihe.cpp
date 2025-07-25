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

#include "preview_output_taihe.h"

#include "camera_manager.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_security_utils_taihe.h"
#include "camera_template_utils_taihe.h"
#include "image_receiver.h"

namespace Ani {
namespace Camera {
uint32_t PreviewOutputImpl::previewOutputTaskId_ = CAMERA_PREVIEW_OUTPUT_TASKID;

PreviewOutputCallbackAni::PreviewOutputCallbackAni(ani_env* env): ListenerBase(env)
{
    MEDIA_DEBUG_LOG("PreviewOutputCallbackAni is called.");
}

void PreviewOutputCallbackAni::OnFrameStartedCallback() const
{
    MEDIA_DEBUG_LOG("OnFrameStartedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr, this]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("frameStart", 0, "Callback is OK", undefined));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameStart", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PreviewOutputCallbackAni::OnFrameEndedCallback(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnFrameEndedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr, this]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("frameEnd", 0, "Callback is OK", undefined));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameEnd", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PreviewOutputCallbackAni::OnErrorCallback(const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called, errorCode: %{public}d", errorCode);
    auto sharePtr = shared_from_this();
    auto task = [errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback("error", errorCode));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PreviewOutputCallbackAni::OnSketchStatusDataChangedCallback(
    const OHOS::CameraStandard::SketchStatusData& sketchStatusData) const
{
    MEDIA_DEBUG_LOG("OnSketchStatusDataChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sketchStatusData, sharePtr]() {
        SketchStatusData aniSketchStatusData = CameraUtilsTaihe::ToTaiheSketchStatusData(sketchStatusData);
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback<SketchStatusData const&>(
            "sketchStatusChanged", 0, "Callback is OK", aniSketchStatusData));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnSketchStatusChanged", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void PreviewOutputCallbackAni::OnFrameStarted() const
{
    MEDIA_DEBUG_LOG("OnFrameStarted is called");
    OnFrameStartedCallback();
}
void PreviewOutputCallbackAni::OnFrameEnded(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnFrameEnded is called, frameCount: %{public}d", frameCount);
    OnFrameEndedCallback(frameCount);
}

void PreviewOutputCallbackAni::OnError(const int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    OnErrorCallback(errorCode);
}

void PreviewOutputCallbackAni::OnSketchStatusDataChanged(
    const OHOS::CameraStandard::SketchStatusData& sketchStatusData) const
{
    MEDIA_DEBUG_LOG("OnSketchStatusDataChanged is called");
    OnSketchStatusDataChangedCallback(sketchStatusData);
}

PreviewOutputImpl::PreviewOutputImpl(OHOS::sptr<OHOS::CameraStandard::CaptureOutput> output) : CameraOutputImpl(output)
{
    previewOutput_ = static_cast<OHOS::CameraStandard::PreviewOutput*>(output.GetRefPtr());
}

void PreviewOutputImpl::EnableSketch(bool enabled)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableSketch is called!");
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr, "EnableSketch failed, videoOutput_ is nullptr");
    int32_t retCode = previewOutput_->EnableSketch(enabled);
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "PreviewOutputImpl::EnableSketch fail! %{public}d", retCode);
}

double PreviewOutputImpl::GetSketchRatio()
{
    double ratio = -1.0;
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), ratio,
        "SystemApi GetSketchRatio is called!");
    MEDIA_INFO_LOG("PreviewOutputImpl::GetSketchRatio is called");
    CHECK_ERROR_RETURN_RET_LOG(previewOutput_ == nullptr, ratio, "GetSketchRatio failed, previewOutput_ is nullptr");
    ratio = static_cast<double>(previewOutput_->GetSketchRatio());
    return ratio;
}

void PreviewOutputImpl::AddDeferredSurface(string_view surfaceId)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi AddDeferredSurface is called!");
    std::string nativeStr(surfaceId);
    uint64_t iSurfaceId;
    std::istringstream iss(nativeStr);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (!surface) {
        surface = OHOS::Media::ImageReceiver::getSurfaceById(nativeStr);
    }
    if (surface == nullptr) {
        MEDIA_ERR_LOG("PreviewOutputImpl::AddDeferredSurface failed to get surface");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "invalid argument surface get fail");
        return;
    }
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr, "EnablAddDeferredSurfaceeSketch failed, videoOutput_ is nullptr");
    auto previewProfile = previewOutput_->GetPreviewProfile();
    CHECK_EXECUTE(previewProfile != nullptr, surface->SetUserData(
        OHOS::CameraStandard::CameraManager::surfaceFormat, std::to_string(previewProfile->GetCameraFormat())));
    previewOutput_->AddDeferredSurface(surface);
}

bool PreviewOutputImpl::IsSketchSupported()
{
    CHECK_ERROR_RETURN_RET_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsSketchSupported is called!");
    MEDIA_INFO_LOG("PreviewOutputImpl::IsSketchSupported is called");
    CHECK_ERROR_RETURN_RET_LOG(previewOutput_ == nullptr, false, "IsSketchSupported failed, previewOutput_ is nullptr");
    bool isSupported = previewOutput_->IsSketchSupported();
    return isSupported;
}

array<FrameRateRange> PreviewOutputImpl::GetSupportedFrameRates()
{
    CHECK_ERROR_RETURN_RET_LOG(previewOutput_ == nullptr, array<FrameRateRange>(nullptr, 0),
        "GetSupportedFrameRates failed, previewOutput_ is nullptr");
    std::vector<std::vector<int32_t>> supportedFrameRatesRange = previewOutput_->GetSupportedFrameRates();
    return CameraUtilsTaihe::ToTaiheArrayFrameRateRange(supportedFrameRatesRange);
}

FrameRateRange PreviewOutputImpl::GetActiveFrameRate()
{
    FrameRateRange res {
        .min = -1,
        .max = -1,
    };
    CHECK_ERROR_RETURN_RET_LOG(previewOutput_ == nullptr, res, "GetActiveFrameRate failed, previewOutput_ is nullptr");
    std::vector<int32_t> frameRateRange = previewOutput_->GetFrameRateRange();
    res.min = frameRateRange[0];
    res.max = frameRateRange[1];
    return res;
}

Profile PreviewOutputImpl::GetActiveProfile()
{
    Profile res {
        .size = {
            .height = -1,
            .width = -1,
        },
        .format = CameraFormat::key_t::CAMERA_FORMAT_YUV_420_SP,
    };
    CHECK_ERROR_RETURN_RET_LOG(previewOutput_ == nullptr, res, "GetActiveProfile failed, previewOutput_ is nullptr");
    auto profile = previewOutput_->GetPhotoProfile();
    CHECK_ERROR_RETURN_RET_LOG(profile == nullptr, res, "GetActiveProfile failed, profile is nullptr");
    CameraFormat cameraFormat = CameraUtilsTaihe::ToTaiheCameraFormat(profile->GetCameraFormat());
    res.size.height = profile->GetSize().height;
    res.size.width = profile->GetSize().width;
    res.format = cameraFormat;
    return res;
}

void PreviewOutputImpl::SetFrameRate(int32_t minFps, int32_t maxFps)
{
    if (previewOutput_ == nullptr) {
        MEDIA_ERR_LOG("PreviewOutputImpl::SetFrameRate get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = previewOutput_->SetFrameRate(minFps, maxFps);
    CHECK_ERROR_PRINT_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "PreviewOutputImpl::SetFrameRate fail %{public}d", retCode);
}

ImageRotation PreviewOutputImpl::GetPreviewRotation(int32_t displayRotation)
{
    CHECK_ERROR_RETURN_RET_LOG(previewOutput_ == nullptr, ImageRotation(static_cast<ImageRotation::key_t>(-1)),
        "GetPreviewRotation failed, previewOutput_ is nullptr");
    int32_t retCode = previewOutput_->GetPreviewRotation(displayRotation);
    if (retCode == OHOS::CameraStandard::SERVICE_FATL_ERROR) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR,
            "GetPreviewRotation Camera service fatal error.");
        return ImageRotation(static_cast<ImageRotation::key_t>(-1));
    }
    if (retCode == OHOS::CameraStandard::INVALID_ARGUMENT) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "GetPreviewRotation Camera invalid argument.");
        return ImageRotation(static_cast<ImageRotation::key_t>(-1));
    }
    int32_t taiheRetCode = CameraUtilsTaihe::ToTaiheImageRotation(retCode);
    return ImageRotation(static_cast<ImageRotation::key_t>(taiheRetCode));
}

void PreviewOutputImpl::SetPreviewRotation(ImageRotation previewRotation, optional_view<bool> isDisplayLocked)
{
    int32_t imageRotation = previewRotation.get_value();
    bool displayLocked = false;
    if (previewOutput_ == nullptr || imageRotation < 0 ||
        imageRotation > OHOS::CameraStandard::CaptureOutput::ROTATION_270 ||
        (imageRotation % OHOS::CameraStandard::CaptureOutput::ROTATION_90 != 0)) {
        MEDIA_ERR_LOG("PreviewOutputImpl::SetPreviewRotation get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    if (isDisplayLocked.has_value()) {
        displayLocked = isDisplayLocked.value();
    }
    int32_t retCode = previewOutput_->SetPreviewRotation(imageRotation, displayLocked);
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "PreviewOutputImpl::SetPreviewRotation! %{public}d", retCode);
}

sptr<Surface> GetSurfaceFromSurfaceId(std::string& surfaceId)
{
    MEDIA_DEBUG_LOG("GetSurfaceFromSurfaceId enter");
    char *ptr;
    uint64_t iSurfaceId = std::strtoull(surfaceId.c_str(), &ptr, 10);
    MEDIA_INFO_LOG("GetSurfaceFromSurfaceId surfaceId %{public}" PRIu64, iSurfaceId);

    return SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
}

void PreviewOutputImpl::AttachSketchSurface(string_view surfaceId)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr, "failed to AttachSketchSurface, previewOutput_ is nullptr");
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi AttachSketchSurface is called!");
    std::string nativeStr(surfaceId);
    sptr<Surface> surface = GetSurfaceFromSurfaceId(nativeStr);
    if (surface == nullptr) {
        MEDIA_ERR_LOG("PreviewOutputImpl::AttachSketchSurface get surface is null");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "input surface convert fail");
        return;
    }
    int32_t retCode = previewOutput_->AttachSketchSurface(surface);
    CHECK_ERROR_RETURN_LOG(!CameraUtilsTaihe::CheckError(retCode),
        "PreviewOutputImpl::AttachSketchSurface! %{public}d", retCode);
}

void PreviewOutputImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<PreviewOutputTaiheAsyncContext> asyncContext = std::make_unique<PreviewOutputTaiheAsyncContext>(
        "PreviewOutputImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(previewOutputTaskId_));
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr, "previewOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("PreviewOutputImpl::ReleaseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "previewOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->previewOutput_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

const PreviewOutputImpl::EmitterFunctions& PreviewOutputImpl::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { "error", {
            &PreviewOutputImpl::RegisterErrorCallbackListener,
            &PreviewOutputImpl::UnregisterCommonCallbackListener } },
        { "frameStart", {
            &PreviewOutputImpl::RegisterFrameStartCallbackListener,
            &PreviewOutputImpl::UnregisterCommonCallbackListener } },
        { "frameEnd", {
            &PreviewOutputImpl::RegisterFrameEndCallbackListener,
            &PreviewOutputImpl::UnregisterCommonCallbackListener } },
        { "sketchStatusChanged", {
            &PreviewOutputImpl::RegisterSketchStatusChangedCallbackListener,
            &PreviewOutputImpl::UnregisterSketchStatusChangedCallbackListener } }
        };
    return funMap;
}

void PreviewOutputImpl::RegisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to RegisterErrorCallbackListener, previewOutput is nullptr");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputImpl::RegisterErrorCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
}

void PreviewOutputImpl::RegisterFrameStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to RegisterFrameStartCallbackListener, previewOutput is nullptr");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputImpl::RegisterFrameStartCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
}

void PreviewOutputImpl::RegisterFrameEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to RegisterFrameEndCallbackListener, previewOutput is nullptr");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputImpl::RegisterFrameEndCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
}

void PreviewOutputImpl::UnregisterCommonCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to UnregisterCommonCallbackListener, previewOutput is nullptr");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::UnregisterCallbackListener(eventName, env, callback);
    CHECK_ERROR_RETURN_LOG(listener == nullptr,
        "PreviewOutputImpl::UnregisterCommonCallbackListener %{public}s listener is null",
        eventName.c_str());
    if (listener->IsEmpty(eventName)) {
        previewOutput_->RemoveCallback(listener);
    }
}

void PreviewOutputImpl::RegisterSketchStatusChangedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to RegisterSketchStatusChangedCallbackListener, previewOutput is nullptr");
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi On sketchStatusChanged is called!");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::RegisterCallbackListener(eventName, env, callback, isOnce);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputImpl::RegisterSketchStatusChangedCallbackListener listener is null");
    previewOutput_->SetCallback(listener);
    previewOutput_->OnNativeRegisterCallback(eventName);
}

void PreviewOutputImpl::UnregisterSketchStatusChangedCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(previewOutput_ == nullptr,
        "failed to UnregisterSketchStatusChangedCallbackListener, previewOutput is nullptr");
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi Off sketchStatusChanged is called!");
    ani_env *env = get_env();
    auto listener =
        CameraAniEventListener<PreviewOutputCallbackAni>::UnregisterCallbackListener(eventName, env, callback);
    CHECK_ERROR_RETURN_LOG(
        listener == nullptr, "PreviewOutputImpl::UnregisterSketchStatusChangedCallbackListener listener is null");
    previewOutput_->OnNativeUnregisterCallback(eventName);
    if (listener->IsEmpty(eventName)) {
        previewOutput_->RemoveCallback(listener);
    }
}

void PreviewOutputImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OnError");
    ListenerTemplate<PreviewOutputImpl>::On(this, callback, "error");
}

void PreviewOutputImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OffError");
    ListenerTemplate<PreviewOutputImpl>::Off(this, callback, "error");
}

void PreviewOutputImpl::OnFrameStart(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OnFrameStart");
    ListenerTemplate<PreviewOutputImpl>::On(this, callback, "frameStart");
}

void PreviewOutputImpl::OffFrameStart(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OffFrameStart");
    ListenerTemplate<PreviewOutputImpl>::Off(this, callback, "frameStart");
}

void PreviewOutputImpl::OnFrameEnd(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OnFrameEnd");
    ListenerTemplate<PreviewOutputImpl>::On(this, callback, "frameEnd");
}

void PreviewOutputImpl::OffFrameEnd(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OffFrameEnd");
    ListenerTemplate<PreviewOutputImpl>::Off(this, callback, "frameEnd");
}

void PreviewOutputImpl::OnSketchStatusChanged(callback_view<void(uintptr_t, SketchStatusData const&)> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OnSketchStatusChanged");
    ListenerTemplate<PreviewOutputImpl>::On(this, callback, "sketchStatusChanged");
}

void PreviewOutputImpl::OffSketchStatusChanged(
    optional_view<callback<void(uintptr_t, SketchStatusData const&)>> callback)
{
    MEDIA_ERR_LOG("PreviewOutputImpl::OffSketchStatusChanged");
    ListenerTemplate<PreviewOutputImpl>::Off(this, callback, "sketchStatusChanged");
}
} // namespace Camera
} // namespace Ani