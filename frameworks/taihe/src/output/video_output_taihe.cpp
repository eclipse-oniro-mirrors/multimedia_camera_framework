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
#include "video_output_taihe.h"
#include "camera_security_utils_taihe.h"
#include "camera_template_utils_taihe.h"

using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace OHOS;

namespace Ani {
namespace Camera {
uint32_t VideoOutputImpl::videoOutputTaskId_ = CAMERA_VIDEO_OUTPUT_TASKID;
VideoOutputImpl::VideoOutputImpl(sptr<OHOS::CameraStandard::CaptureOutput> output) : CameraOutputImpl(output)
{
    videoOutput_ = static_cast<OHOS::CameraStandard::VideoOutput*>(output.GetRefPtr());
}

void VideoOutputImpl::StartSync()
{
    MEDIA_DEBUG_LOG("StartSync is called");
    std::unique_ptr<VideoOutputTaiheAsyncContext> asyncContext = std::make_unique<VideoOutputTaiheAsyncContext>(
        "VideoOutputImpl::StartSync", CameraUtilsTaihe::IncrementAndGet(videoOutputTaskId_));
    CHECK_RETURN_ELOG(videoOutput_ == nullptr, "videoOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("VideoOutputImpl::StartSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "videoOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->videoOutput_->Start();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void VideoOutputImpl::StopSync()
{
    MEDIA_DEBUG_LOG("StopSync is called");
    std::unique_ptr<VideoOutputTaiheAsyncContext> asyncContext = std::make_unique<VideoOutputTaiheAsyncContext>(
        "VideoOutputImpl::StopSync", CameraUtilsTaihe::IncrementAndGet(videoOutputTaskId_));
    CHECK_RETURN_ELOG(videoOutput_ == nullptr, "videoOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("VideoOutputImpl::StopSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "videoOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->videoOutput_->Stop();
        MEDIA_INFO_LOG("VideoOutputImpl::StopSync asyncContext->errorCode : %{public}d", asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void VideoOutputImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<VideoOutputTaiheAsyncContext> asyncContext = std::make_unique<VideoOutputTaiheAsyncContext>(
        "VideoOutputImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(videoOutputTaskId_));
    CHECK_RETURN_ELOG(videoOutput_ == nullptr, "videoOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("VideoOutputImpl::ReleaseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "videoOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->videoOutput_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

bool VideoOutputImpl::IsMirrorSupported()
{
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::IsMirrorSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }
    return videoOutput_->IsMirrorSupported();
}

void VideoOutputImpl::EnableMirror(bool enabled)
{
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::EnableMirror get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = videoOutput_->enableMirror(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "VideoOutputImpl::EnableAutoHighQualityPhoto fail %{public}d", retCode);
}

bool VideoOutputImpl::IsAutoVideoFrameRateSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsAutoVideoFrameRateSupported is called!");
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::EnableAutoVideoFrameRate get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }
    return videoOutput_->IsAutoVideoFrameRateSupported();
}

void VideoOutputImpl::EnableAutoVideoFrameRate(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableAutoVideoFrameRate is called!");
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::EnableAutoVideoFrameRate get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = videoOutput_->EnableAutoVideoFrameRate(enabled);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "VideoOutputImpl::EnableAutoVideoFrameRate fail %{public}d", retCode);
}

bool VideoOutputImpl::IsAutoDeferredVideoEnhancementSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsAutoDeferredVideoEnhancementSupported is called!");
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::IsAutoDeferredVideoEnhancementSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }
    int32_t res = videoOutput_->IsAutoDeferredVideoEnhancementSupported();
    if (res > 1) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "inner fail");
        return false;
    }
    return res == 1;
}

bool VideoOutputImpl::IsAutoDeferredVideoEnhancementEnabled()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsAutoDeferredVideoEnhancementEnabled is called!");
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::IsAutoDeferredVideoEnhancementEnabled get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }
    int32_t res = videoOutput_->IsAutoDeferredVideoEnhancementEnabled();
    if (res > 1) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "inner fail");
        return false;
    }
    return res == 1;
}

array<FrameRateRange> VideoOutputImpl::GetSupportedFrameRates()
{
    CHECK_RETURN_RET_ELOG(videoOutput_ == nullptr, array<FrameRateRange>(nullptr, 0),
        "GetSupportedFrameRates failed, videoOutput_ is nullptr");
    std::vector<std::vector<int32_t>> supportedFrameRatesRange = videoOutput_->GetSupportedFrameRates();
    return CameraUtilsTaihe::ToTaiheArrayFrameRateRange(supportedFrameRatesRange);
}

FrameRateRange VideoOutputImpl::GetActiveFrameRate()
{
    FrameRateRange res {
        .min = -1,
        .max = -1,
    };
    CHECK_RETURN_RET_ELOG(videoOutput_ == nullptr, res, "GetActiveFrameRate failed, videoOutput_ is nullptr");
    std::vector<int32_t> frameRateRange = videoOutput_->GetFrameRateRange();
    res.min = frameRateRange[0];
    res.max = frameRateRange[1];
    return res;
}

VideoProfile VideoOutputImpl::GetActiveProfile()
{
    VideoProfile res {
        .base = {
            .size = {
                .height = 0,
                .width = 0,
            },
            .format = CameraFormat::key_t::CAMERA_FORMAT_YUV_420_SP,
        },
        .frameRateRange = {
            .min = -1,
            .max = -1,
        },
    };
    CHECK_RETURN_RET_ELOG(videoOutput_ == nullptr, res, "GetActiveProfile failed, videoOutput_ is nullptr");
    auto profile = videoOutput_->GetVideoProfile();
    CHECK_RETURN_RET_ELOG(profile == nullptr, res, "GetActiveProfile failed, profile is nullptr");
    CameraFormat cameraFormat = CameraFormat::from_value(static_cast<int32_t>(profile->GetCameraFormat()));
    res.base.size.height = static_cast<int32_t>(profile->GetSize().height);
    res.base.size.width = static_cast<int32_t>(profile->GetSize().width);
    res.base.format = cameraFormat;
    auto frameRates = profile->GetFrameRates();
    res.frameRateRange.min = frameRates[0] >= frameRates[1] ? frameRates[1] : frameRates[0];
    res.frameRateRange.max = frameRates[0] >= frameRates[1] ? frameRates[0] : frameRates[1];
    return res;
}

void VideoOutputImpl::SetFrameRate(int32_t minFps, int32_t maxFps)
{
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::SetFrameRate get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = videoOutput_->SetFrameRate(minFps, maxFps);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "VideoOutputImpl::SetFrameRate fail %{public}d", retCode);
}

void VideoOutputImpl::SetRotation(ImageRotation rotation)
{
    CHECK_PRINT_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetRotation is called!");
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::SetRotation get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return;
    }
    int32_t retCode = videoOutput_->SetRotation(rotation.get_value());
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode),
        "VideoOutputImpl::SetRotation fail %{public}d", retCode);
}

bool VideoOutputImpl::IsRotationSupported()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), false,
        "SystemApi IsRotationSupported is called!");
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::IsRotationSupported get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return false;
    }
    bool isSupported = false;
    int32_t retCode = videoOutput_->IsRotationSupported(isSupported);
    CHECK_RETURN_RET_ELOG(!CameraUtilsTaihe::CheckError(retCode), false,
        "VideoOutputImpl::IsRotationSupported fail %{public}d", retCode);
    return isSupported;
}

array<ImageRotation> VideoOutputImpl::GetSupportedRotations()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        array<ImageRotation>(nullptr, 0), "SystemApi GetSupportedRotations is called!");
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("VideoOutputImpl::GetSupportedRotations get native object fail");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "get native object fail");
        return array<ImageRotation>(nullptr, 0);
    }
    std::vector<int32_t> supportedRotations;
    int32_t retCode = videoOutput_->GetSupportedRotations(supportedRotations);
    CHECK_RETURN_RET(!CameraUtilsTaihe::CheckError(retCode), array<ImageRotation>(nullptr, 0));
    return CameraUtilsTaihe::ToTaiheArrayEnum<ImageRotation, int32_t>(supportedRotations);
}

ImageRotation VideoOutputImpl::GetVideoRotation()
{
    CHECK_RETURN_RET_ELOG(videoOutput_ == nullptr, ImageRotation(static_cast<ImageRotation::key_t>(-1)),
        "GetVideoRotation failed, videoOutput_ is nullptr");
    int32_t retCode = videoOutput_->GetVideoRotation();
    if (retCode == OHOS::CameraStandard::SERVICE_FATL_ERROR) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR,
            "GetVideoRotation Camera service fatal error.");
        return ImageRotation(static_cast<ImageRotation::key_t>(-1));
    }
    int32_t taiheRetCode = CameraUtilsTaihe::ToTaiheImageRotation(retCode);
    return ImageRotation(static_cast<ImageRotation::key_t>(taiheRetCode));
}

ImageRotation VideoOutputImpl::GetVideoRotation(int32_t deviceDegree)
{
    CHECK_RETURN_RET_ELOG(videoOutput_ == nullptr, ImageRotation(static_cast<ImageRotation::key_t>(-1)),
        "GetVideoRotation failed, videoOutput_ is nullptr");
    int32_t retCode = videoOutput_->GetVideoRotation(deviceDegree);
    if (retCode == OHOS::CameraStandard::SERVICE_FATL_ERROR) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR,
            "GetVideoRotation Camera service fatal error.");
        return ImageRotation(static_cast<ImageRotation::key_t>(-1));
    }
    if (retCode == OHOS::CameraStandard::INVALID_ARGUMENT) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT,
            "GetVideoRotation Camera invalid argument.");
        return ImageRotation(static_cast<ImageRotation::key_t>(-1));
    }
    int32_t taiheRetCode = CameraUtilsTaihe::ToTaiheImageRotation(retCode);
    return ImageRotation(static_cast<ImageRotation::key_t>(taiheRetCode));
}

void VideoOutputImpl::AttachMetaSurface(string_view surfaceId, VideoMetaType type)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi AttachMetaSurface is called!");
    CHECK_RETURN_ELOG(videoOutput_ == nullptr, "AttachMetaSurface failed, videoOutput_ is nullptr");
    uint64_t iSurfaceId;
    std::istringstream iss((std::string(surfaceId)));
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    CHECK_RETURN_ELOG(surface == nullptr, "failed to get surface from SurfaceUtils");
    videoOutput_->AttachMetaSurface(surface, static_cast<OHOS::CameraStandard::VideoMetaType>(type.get_value()));
}

array<VideoMetaType> VideoOutputImpl::GetSupportedVideoMetaTypes()
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), array<VideoMetaType>(nullptr, 0),
        "SystemApi GetSupportedVideoMetaTypes is called!");
    CHECK_RETURN_RET_ELOG(videoOutput_ == nullptr, array<VideoMetaType>(nullptr, 0),
        "GetSupportedVideoMetaTypes failed, videoOutput_ is nullptr");
    std::vector<OHOS::CameraStandard::VideoMetaType> videoMetaTypes = videoOutput_->GetSupportedVideoMetaTypes();
    return CameraUtilsTaihe::ToTaiheArrayEnum<VideoMetaType, OHOS::CameraStandard::VideoMetaType>(videoMetaTypes);
}

void VideoCallbackListener::OnError(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    OnErrorCallback(errorCode);
}

void VideoCallbackListener::OnErrorCallback(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called, errorCode: %{public}d", errorCode);
    auto sharePtr = shared_from_this();
    auto task = [errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback("error", errorCode));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoCallbackListener::OnFrameStarted() const
{
    MEDIA_DEBUG_LOG("OnFrameStarted is called");
    OnFrameStartedCallback();
}

void VideoCallbackListener::OnFrameStartedCallback() const
{
    MEDIA_DEBUG_LOG("OnFrameStartedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("frameStart", 0, "Callback is OK", undefined));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameStart", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoCallbackListener::OnFrameEnded(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnFrameEnded is called, frameCount: %{public}d", frameCount);
    OnFrameEndedCallback(frameCount);
}

void VideoCallbackListener::OnFrameEndedCallback(const int32_t frameCount) const
{
    MEDIA_DEBUG_LOG("OnFrameEndedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [sharePtr]() {
        uintptr_t undefined = CameraUtilsTaihe::GetUndefined(get_env());
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("frameEnd", 0, "Callback is OK", undefined));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFrameEnd", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoCallbackListener::OnDeferredVideoEnhancementInfo(
    const OHOS::CameraStandard::CaptureEndedInfoExt captureEndedInfo) const
{
    MEDIA_DEBUG_LOG("OnDeferredVideoEnhancementInfo is called");
    DeferredVideoEnhancementInfo info{
        captureEndedInfo.isDeferredVideoEnhancementAvailable,
        taihe::optional<::taihe::string>::make(captureEndedInfo.videoId)
    };
    MEDIA_INFO_LOG("OnDeferredVideoEnhancementInfo isDeferredVideo:%{public}d videoId:%{public}s ",
        captureEndedInfo.isDeferredVideoEnhancementAvailable, captureEndedInfo.videoId.c_str());

    auto sharePtr = shared_from_this();
    auto task = [info, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("deferredVideoEnhancementInfo", 0, "Callback is OK", info));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnDeferredVideoEnhancementInfo", 0,
        OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void VideoOutputImpl::RegisterVideoOutputErrorCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(videoOutput_ == nullptr, "videoOutput_ is null!");
    if (videoCallback_ == nullptr) {
        ani_env *env = get_env();
        videoCallback_ = std::make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoOutputImpl::UnregisterVideoOutputErrorCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(videoCallback_ == nullptr, "videoCallback is null");
    videoCallback_->RemoveCallbackRef(eventName, callback);
}

void VideoOutputImpl::RegisterDeferredVideoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi on deferredVideoEnhancementInfo is called!");
    CHECK_RETURN_ELOG(videoOutput_ == nullptr, "videoOutput_ is null!");
    if (videoCallback_ == nullptr) {
        ani_env *env = get_env();
        videoCallback_ = std::make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoOutputImpl::UnregisterDeferredVideoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi off deferredVideoEnhancementInfo is called!");
    CHECK_RETURN_ELOG(videoCallback_ == nullptr, "videoCallback is null");
    videoCallback_->RemoveCallbackRef(eventName, callback);
}

void VideoOutputImpl::RegisterFrameStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(videoOutput_ == nullptr, "videoOutput_ is null!");
    if (videoCallback_ == nullptr) {
        ani_env *env = get_env();
        videoCallback_ = std::make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoOutputImpl::UnregisterFrameStartCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(videoCallback_ == nullptr, "videoCallback is null");
    videoCallback_->RemoveCallbackRef(eventName, callback);
}

void VideoOutputImpl::RegisterFrameEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(videoOutput_ == nullptr, "videoOutput_ is null!");
    if (videoCallback_ == nullptr) {
        ani_env *env = get_env();
        videoCallback_ = std::make_shared<VideoCallbackListener>(env);
        videoOutput_->SetCallback(videoCallback_);
    }
    videoCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void VideoOutputImpl::UnregisterFrameEndCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(videoCallback_ == nullptr, "videoCallback is null");
    videoCallback_->RemoveCallbackRef(eventName, callback);
}

const VideoOutputImpl::EmitterFunctions VideoOutputImpl::fun_map_ = {
    { "error", {
        &VideoOutputImpl::RegisterVideoOutputErrorCallbackListener,
        &VideoOutputImpl::UnregisterVideoOutputErrorCallbackListener } },
    { "frameStart", {
        &VideoOutputImpl::RegisterFrameStartCallbackListener,
        &VideoOutputImpl::UnregisterFrameStartCallbackListener } },
    { "frameEnd", {
        &VideoOutputImpl::RegisterFrameEndCallbackListener,
        &VideoOutputImpl::UnregisterFrameEndCallbackListener } },
    { "deferredVideoEnhancementInfo", {
        &VideoOutputImpl::RegisterDeferredVideoCallbackListener,
        &VideoOutputImpl::UnregisterDeferredVideoCallbackListener } }
};

const VideoOutputImpl::EmitterFunctions& VideoOutputImpl::GetEmitterFunctions()
{
    return fun_map_;
}

void VideoOutputImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    ListenerTemplate<VideoOutputImpl>::On(this, callback, "error");
}

void VideoOutputImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    ListenerTemplate<VideoOutputImpl>::Off(this, callback, "error");
}

void VideoOutputImpl::OnDeferredVideoEnhancementInfo(
    callback_view<void(uintptr_t, DeferredVideoEnhancementInfo const&)> callback)
{
    ListenerTemplate<VideoOutputImpl>::On(this, callback, "deferredVideoEnhancementInfo");
}

void VideoOutputImpl::OffDeferredVideoEnhancementInfo(
    optional_view<callback<void(uintptr_t, DeferredVideoEnhancementInfo const&)>> callback)
{
    ListenerTemplate<VideoOutputImpl>::Off(this, callback, "deferredVideoEnhancementInfo");
}

void VideoOutputImpl::OnFrameStart(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    ListenerTemplate<VideoOutputImpl>::On(this, callback, "frameStart");
}

void VideoOutputImpl::OffFrameStart(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    ListenerTemplate<VideoOutputImpl>::Off(this, callback, "frameStart");
}

void VideoOutputImpl::OnFrameEnd(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    ListenerTemplate<VideoOutputImpl>::On(this, callback, "frameEnd");
}

void VideoOutputImpl::OffFrameEnd(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    ListenerTemplate<VideoOutputImpl>::Off(this, callback, "frameEnd");
}

void VideoOutputImpl::EnableAutoDeferredVideoEnhancement(bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi EnableAutoDeferredVideoEnhancement is called!");
    CHECK_RETURN_ELOG(videoOutput_ == nullptr, "EnableAutoDeferredVideoEnhancement failed, videoOutput_ is nullptr");
    int32_t res = videoOutput_->EnableAutoDeferredVideoEnhancement(enabled);
    CHECK_EXECUTE(res > 0, CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "inner fail"));
}
} // namespace Camera
} // namespace Ani
