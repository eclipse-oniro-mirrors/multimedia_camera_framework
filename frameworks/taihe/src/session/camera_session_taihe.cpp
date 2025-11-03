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

#include "camera_const_ability_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_template_utils_taihe.h"
#include "session/camera_session_taihe.h"
#include "camera_log.h"
#include "camera_error_code.h"
#include "camera_input_taihe.h"
#include "camera_output_taihe.h"
#include "camera_input.h"
#include "camera_security_utils_taihe.h"
#include "event_handler.h"

namespace Ani {
namespace Camera {
using namespace taihe;
using namespace ohos::multimedia::camera;
uint32_t SessionImpl::cameraSessionTaskId_ = CAMERA_SESSION_TASKID;

void SessionImpl::BeginConfig()
{
    MEDIA_DEBUG_LOG("BeginConfig is called");
    if (captureSession_ == nullptr) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR,
            "failed to BeginConfig, captureSession is nullptr");
        return;
    }
    captureSession_->BeginConfig();
}

void SessionImpl::CommitConfigSync()
{
    MEDIA_DEBUG_LOG("CommitConfigSync is called");
    std::unique_ptr<SessionTaiheAsyncContext> asyncContext = std::make_unique<SessionTaiheAsyncContext>(
        "SessionImpl::CommitConfigSync", CameraUtilsTaihe::IncrementAndGet(cameraSessionTaskId_));
    CHECK_RETURN_ELOG(captureSession_ == nullptr, "captureSession_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("SessionImpl::CommitConfigSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "captureSession_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->captureSession_->CommitConfig();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void SessionImpl::StartSync()
{
    MEDIA_DEBUG_LOG("StartSync is called");
    std::unique_ptr<SessionTaiheAsyncContext> asyncContext = std::make_unique<SessionTaiheAsyncContext>(
        "SessionImpl::StartSync", CameraUtilsTaihe::IncrementAndGet(cameraSessionTaskId_));
    CHECK_RETURN_ELOG(captureSession_ == nullptr, "captureSession_ is nullptr");
    asyncContext->queueTask = CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("SessionImpl::Start");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "captureSession_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->captureSession_->Start();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void SessionImpl::StopSync()
{
    MEDIA_DEBUG_LOG("StopSync is called");
    std::unique_ptr<SessionTaiheAsyncContext> asyncContext = std::make_unique<SessionTaiheAsyncContext>(
        "SessionImpl::StopSync", CameraUtilsTaihe::IncrementAndGet(cameraSessionTaskId_));
    CHECK_RETURN_ELOG(captureSession_ == nullptr, "captureSession_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("SessionImpl::StopSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "captureSession_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->captureSession_->Stop();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void SessionImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<SessionTaiheAsyncContext> asyncContext = std::make_unique<SessionTaiheAsyncContext>(
        "SessionImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(cameraSessionTaskId_));
    CHECK_RETURN_ELOG(captureSession_ == nullptr, "captureSession_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("SessionImpl::ReleaseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "captureSession_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->captureSession_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void SessionImpl::AddInput(weak::CameraInput cameraInput)
{
    MEDIA_DEBUG_LOG("AddInput is called");
    CHECK_RETURN_ELOG(captureSession_ == nullptr, "AddInput captureSession_ is null");
    Ani::Camera::CameraInputImpl* inputImpl =
        reinterpret_cast<Ani::Camera::CameraInputImpl *>(cameraInput->GetSpecificImplPtr());
    CHECK_RETURN_ELOG(inputImpl == nullptr, "AddInput inputImpl is null");
    sptr<OHOS::CameraStandard::CaptureInput> captureInput = inputImpl->GetCameraInput();
    int32_t ret = captureSession_->AddInput(captureInput);
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(ret));
}

bool SessionImpl::CanAddInput(weak::CameraInput cameraInput)
{
    MEDIA_DEBUG_LOG("CanAddInput is called");
    CHECK_RETURN_RET_ELOG(captureSession_ == nullptr, false, "CanAddInput captureSession_ is null");
    Ani::Camera::CameraInputImpl* inputImpl =
        reinterpret_cast<Ani::Camera::CameraInputImpl *>(cameraInput->GetSpecificImplPtr());
    CHECK_RETURN_RET_ELOG(inputImpl == nullptr, false, "CanAddInput inputImpl is null");
    sptr<OHOS::CameraStandard::CaptureInput> captureInput = inputImpl->GetCameraInput();
    bool isSupported = captureSession_->CanAddInput(captureInput);
    return isSupported;
}

bool SessionImpl::CanAddOutput(weak::CameraOutput cameraOutput)
{
    MEDIA_DEBUG_LOG("CanAddOutput is called");
    CHECK_RETURN_RET_ELOG(captureSession_ == nullptr, false, "CanAddOutput captureSession_ is null");
    Ani::Camera::CameraOutputImpl* outputImpl =
        reinterpret_cast<Ani::Camera::CameraOutputImpl *>(cameraOutput->GetSpecificImplPtr());
    CHECK_RETURN_RET_ELOG(outputImpl == nullptr, false, "CanAddOutput CameraOutputImpl is null");
    sptr<OHOS::CameraStandard::CaptureOutput> captureOutput = outputImpl->GetCameraOutput();
    CHECK_RETURN_RET_ELOG(captureOutput == nullptr, false, "CanAddOutput captureOutput is null");
    bool isSupported = captureSession_->CanAddOutput(captureOutput);
    return isSupported;
}

void SessionImpl::RemoveInput(weak::CameraInput cameraInput)
{
    CHECK_RETURN_ELOG(captureSession_ == nullptr, "RemoveInput captureSession_ is null");
    Ani::Camera::CameraInputImpl* inputImpl =
        reinterpret_cast<Ani::Camera::CameraInputImpl *>(cameraInput->GetSpecificImplPtr());
    CHECK_RETURN_ELOG(inputImpl == nullptr, "RemoveInput inputImpl is null");
    sptr<OHOS::CameraStandard::CaptureInput> captureInput = inputImpl->GetCameraInput();
    int32_t ret = captureSession_->RemoveInput(captureInput);
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(ret));
}

void SessionImpl::AddOutput(weak::CameraOutput cameraOutput)
{
    MEDIA_DEBUG_LOG("AddOutput is called");
    CHECK_RETURN_ELOG(captureSession_ == nullptr, "AddOutput captureSession_ is null");
    Ani::Camera::CameraOutputImpl* outputImpl =
        reinterpret_cast<Ani::Camera::CameraOutputImpl *>(cameraOutput->GetSpecificImplPtr());
        CHECK_RETURN_ELOG(outputImpl == nullptr, "AddOutput CameraOutputImpl is null");
    sptr<OHOS::CameraStandard::CaptureOutput> captureOutput = outputImpl->GetCameraOutput();
    CHECK_RETURN_ELOG(captureOutput == nullptr, "AddOutput captureOutput is null");
    int32_t ret = captureSession_->AddOutput(captureOutput);
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(ret));
}

void SessionImpl::RemoveOutput(weak::CameraOutput cameraOutput)
{
    CHECK_RETURN_ELOG(captureSession_ == nullptr, "AddOutput captureSession_ is null");
    Ani::Camera::CameraOutputImpl* outputImpl =
        reinterpret_cast<Ani::Camera::CameraOutputImpl *>(cameraOutput->GetSpecificImplPtr());
    CHECK_RETURN_ELOG(outputImpl == nullptr, "AddOutput CameraOutputImpl is null");
    sptr<OHOS::CameraStandard::CaptureOutput> captureOutput = outputImpl->GetCameraOutput();
    CHECK_RETURN_ELOG(captureOutput == nullptr, "AddOutput captureOutput is null");
    int32_t ret = captureSession_->RemoveOutput(captureOutput);
    CHECK_RETURN(!CameraUtilsTaihe::CheckError(ret));
}

void SessionImpl::SetUsage(UsageType usage, bool enabled)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi SetUsage is called!");
    CHECK_RETURN_ELOG(captureSessionForSys_ == nullptr, "SetUsage captureSessionForSys_ is null");
    captureSessionForSys_->LockForControl();
    captureSessionForSys_->SetUsage(static_cast<OHOS::CameraStandard::UsageType>(usage.get_value()), enabled);
    captureSessionForSys_->UnlockForControl();
}

array<CameraOutputCapability> SessionImpl::GetCameraOutputCapabilities(CameraDevice const& camera)
{
    CHECK_RETURN_RET_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(), {},
        "SystemApi GetCameraOutputCapabilities is called!");
    std::string nativeStr(camera.cameraId);
    sptr<OHOS::CameraStandard::CameraDevice> cameraInfo =
        OHOS::CameraStandard::CameraManager::GetInstance()->GetCameraDeviceFromId(nativeStr);
    if (cameraInfo == nullptr) {
        MEDIA_ERR_LOG("cameraInfo is null");
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::SERVICE_FATL_ERROR, "cameraInfo is null.");
        return {};
    }
    CHECK_RETURN_RET_ELOG(captureSession_ == nullptr, {}, "GetCameraOutputCapabilities captureSession_ is null");
    std::vector<sptr<OHOS::CameraStandard::CameraOutputCapability>> caplist =
        captureSession_->GetCameraOutputCapabilities(cameraInfo);
    std::vector<CameraOutputCapability> vec;
    for (size_t i = 0; i < caplist.size(); i++) {
        if (caplist[i] == nullptr) {
            continue;
        }
        caplist[i]->RemoveDuplicatesProfiles();
        vec.push_back(CameraUtilsTaihe::ToTaiheCameraOutputCapability(caplist[i]));
    }
    return array<CameraOutputCapability>(vec);
}

void SessionImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "error");
}

void SessionImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "error");
}
void SessionImpl::RegisterSessionErrorCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (sessionCallback_ == nullptr) {
        ani_env *env = get_env();
        sessionCallback_ = std::make_shared<SessionCallbackListener>(env);
        captureSession_->SetCallback(sessionCallback_);
    }
    sessionCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void SessionImpl::UnregisterSessionErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(sessionCallback_ == nullptr, "sessionCallback is null");
    sessionCallback_->RemoveCallbackRef(eventName, callback);
}

void SessionCallbackListener::OnError(int32_t errorCode)
{
    MEDIA_DEBUG_LOG("OnError is called, errorCode: %{public}d", errorCode);
    OnErrorCallback(errorCode);
}

void SessionCallbackListener::OnErrorCallback(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called, errorCode: %{public}d", errorCode);
    auto sharePtr = shared_from_this();
    auto task = [errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback("error", errorCode));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void SessionImpl::OnFocusStateChange(callback_view<void(uintptr_t, FocusState)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "focusStateChange");
}

void SessionImpl::OffFocusStateChange(optional_view<callback<void(uintptr_t, FocusState)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "focusStateChange");
}
void SessionImpl::RegisterFocusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (focusCallback_ == nullptr) {
        ani_env *env = get_env();
        focusCallback_ = std::make_shared<FocusCallbackListener>(env);
        captureSession_->SetFocusCallback(focusCallback_);
    }
    focusCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void SessionImpl::UnregisterFocusCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(focusCallback_ == nullptr, "focusCallback is null");
    focusCallback_->RemoveCallbackRef(eventName, callback);
}

void SessionImpl::RegisterPressureStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::UnregisterPressureStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

void SessionImpl::OnSystemPressureLevelChange(callback_view<void(uintptr_t, SystemPressureLevel)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "systemPressureLevelChange");
}

void SessionImpl::OffSystemPressureLevelChange(optional_view<callback<void(uintptr_t, SystemPressureLevel)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "systemPressureLevelChange");
}

void PressureCallbackListener::OnPressureStatusChanged(
    OHOS::CameraStandard::PressureStatus systemPressureLevel)
{
    MEDIA_DEBUG_LOG("OnPressureStatusChanged is called, systemPressureLevel: %{public}d", systemPressureLevel);
    OnSystemPressureLevelCallback(systemPressureLevel);
}

void PressureCallbackListener::OnSystemPressureLevelCallback(
    OHOS::CameraStandard::PressureStatus systemPressureLevel) const
{
    MEDIA_INFO_LOG("OnSystemPressureLevelCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [systemPressureLevel, sharePtr]() {
        auto aniSystemPressureLevel = CameraUtilsTaihe::ToTaiheSystemPressureLevel(systemPressureLevel);
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback(
            "systemPressureLevelChange", 0, "Callback is OK", aniSystemPressureLevel));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnSystemPressureLevelChange",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void FocusCallbackListener::OnFocusState(OHOS::CameraStandard::FocusCallback::FocusState state)
{
    MEDIA_DEBUG_LOG("OnFocusState is called, state: %{public}d", state);
    OnFocusStateCallback(state);
}

void FocusCallbackListener::OnFocusStateCallback(OHOS::CameraStandard::FocusCallback::FocusState state) const
{
    MEDIA_DEBUG_LOG("OnFocusStateCallback is called, state: %{public}d", state);
    auto sharePtr = shared_from_this();
    auto task = [state, sharePtr]() {
        ohos::multimedia::camera::FocusState taiheState = CameraUtilsTaihe::ToTaiheFocusState(state);
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("focusStateChange", 0, "Callback is OK", taiheState));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFocusStateChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void SessionImpl::OnExposureInfoChange(callback_view<void(uintptr_t, ExposureInfo const&)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "exposureInfoChange");
}

void SessionImpl::OffExposureInfoChange(optional_view<callback<void(uintptr_t, ExposureInfo const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "exposureInfoChange");
}

void SessionImpl::RegisterExposureInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::UnregisterExposureInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::OnIsoInfoChange(callback_view<void(uintptr_t, IsoInfo const&)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "isoInfoChange");
}

void SessionImpl::OffIsoInfoChange(optional_view<callback<void(uintptr_t, IsoInfo const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "isoInfoChange");
}

void SessionImpl::RegisterIsoInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::UnregisterIsoInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

void SessionImpl::OnSmoothZoomInfoAvailable(callback_view<void(uintptr_t, SmoothZoomInfo const&)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "smoothZoomInfoAvailable");
}

void SessionImpl::OffSmoothZoomInfoAvailable(optional_view<callback<void(uintptr_t, SmoothZoomInfo const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "smoothZoomInfoAvailable");
}

void SessionImpl::RegisterSmoothZoomCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (smoothZoomCallback_ == nullptr) {
        ani_env *env = get_env();
        smoothZoomCallback_ = std::make_shared<SmoothZoomCallbackListener>(env);
        captureSession_->SetSmoothZoomCallback(smoothZoomCallback_);
    }
    smoothZoomCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void SessionImpl::UnregisterSmoothZoomCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(smoothZoomCallback_ == nullptr, "smoothZoomCallback is null");
    smoothZoomCallback_->RemoveCallbackRef(eventName, callback);
}

void SmoothZoomCallbackListener::OnSmoothZoom(int32_t duration)
{
    MEDIA_DEBUG_LOG("OnSmoothZoom is called, duration: %{public}d", duration);
    OnSmoothZoomCallback(duration);
}

void SmoothZoomCallbackListener::OnSmoothZoomCallback(int32_t duration) const
{
    MEDIA_DEBUG_LOG("OnSmoothZoomCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [duration, sharePtr]() {
        SmoothZoomInfo smoothZoomInfo{ duration };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<SmoothZoomInfo const&>(
                "smoothZoomInfoAvailable", 0, "Callback is OK", smoothZoomInfo));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnSmoothZoomInfoAvailable", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void SessionImpl::OnApertureInfoChange(callback_view<void(uintptr_t, ApertureInfo const&)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "apertureInfoChange");
}

void SessionImpl::OffApertureInfoChange(optional_view<callback<void(uintptr_t, ApertureInfo const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "apertureInfoChange");
}

void SessionImpl::RegisterApertureInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::UnregisterApertureInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

void SessionImpl::OnLuminationInfoChange(callback_view<void(uintptr_t, LuminationInfo const&)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "luminationInfoChange");
}

void SessionImpl::OffLuminationInfoChange(optional_view<callback<void(uintptr_t, LuminationInfo const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "luminationInfoChange");
}

void SessionImpl::RegisterLuminationInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::UnregisterLuminationInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

void SessionImpl::OnTryAEInfoChange(callback_view<void(uintptr_t, TryAEInfo const&)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "tryAEInfoChange");
}

void SessionImpl::OffTryAEInfoChange(optional_view<callback<void(uintptr_t, TryAEInfo const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "tryAEInfoChange");
}

void SessionImpl::RegisterTryAEInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::UnregisterTryAEInfoCallbackListener(const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unregistered in current session!");
}

void SessionImpl::OnSlowMotionStatus(callback_view<void(uintptr_t, SlowMotionStatus)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "slowMotionStatus");
}

void SessionImpl::OffSlowMotionStatus(optional_view<callback<void(uintptr_t, SlowMotionStatus)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "slowMotionStatus");
}

void SessionImpl::RegisterSlowMotionStateCb(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::UnregisterSlowMotionStateCb(const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be unRegistered in current session!");
}


void SessionImpl::RegisterLcdFlashStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi on lcdFlashStatus is called!");
    if (lcdFlashStatusCallback_ == nullptr) {
        ani_env *env = get_env();
        lcdFlashStatusCallback_ = std::make_shared<LcdFlashStatusCallbackListener>(env);
        captureSessionForSys_->SetLcdFlashStatusCallback(lcdFlashStatusCallback_);
    }
    lcdFlashStatusCallback_->SaveCallbackReference(eventName, callback, isOnce);
    captureSessionForSys_->LockForControl();
    captureSessionForSys_->EnableLcdFlashDetection(true);
    captureSessionForSys_->UnlockForControl();
}

void SessionImpl::UnregisterLcdFlashStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi off lcdFlashStatus is called!");
    CHECK_RETURN_ELOG(lcdFlashStatusCallback_ == nullptr, "LcdFlashStatusCallback is null");
    lcdFlashStatusCallback_->RemoveCallbackRef(eventName, callback);
}

void LcdFlashStatusCallbackListener::OnLcdFlashStatusChanged(
    OHOS::CameraStandard::LcdFlashStatusInfo lcdFlashStatusInfo)
{
    MEDIA_DEBUG_LOG("LcdFlashStatusCallback is called");
    OnLcdFlashStatusCallback(lcdFlashStatusInfo);
}

void LcdFlashStatusCallbackListener::OnLcdFlashStatusCallback(
    OHOS::CameraStandard::LcdFlashStatusInfo lcdFlashStatusInfo) const
{
    MEDIA_DEBUG_LOG("LcdFlashStatusCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [lcdFlashStatusInfo, sharePtr]() {
        LcdFlashStatus status = {
            .isLcdFlashNeeded = lcdFlashStatusInfo.isLcdFlashNeeded,
            .lcdCompensation = lcdFlashStatusInfo.lcdCompensation };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<LcdFlashStatus const&>("lcdFlashStatus", 0, "Callback is OK", status));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnLcdFlashStatus", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void SessionImpl::OnLcdFlashStatus(callback_view<void(uintptr_t, LcdFlashStatus const&)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "lcdFlashStatus");
}

void SessionImpl::OffLcdFlashStatus(optional_view<callback<void(uintptr_t, LcdFlashStatus const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "lcdFlashStatus");
}

void SessionImpl::OnAutoDeviceSwitchStatusChange(callback_view<void(uintptr_t, AutoDeviceSwitchStatus const&)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "autoDeviceSwitchStatusChange");
}
void SessionImpl::OffAutoDeviceSwitchStatusChange(optional_view<callback<void(
    uintptr_t, AutoDeviceSwitchStatus const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "autoDeviceSwitchStatusChange");
}

void SessionImpl::RegisterAutoDeviceSwitchCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(captureSession_ == nullptr, "cameraSession is null!");
    if (autoDeviceSwitchCallback_ == nullptr) {
        ani_env *env = get_env();
        autoDeviceSwitchCallback_ = std::make_shared<AutoDeviceSwitchCallbackListener>(env);
        captureSession_->SetAutoDeviceSwitchCallback(autoDeviceSwitchCallback_);
    }
    autoDeviceSwitchCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void SessionImpl::UnregisterAutoDeviceSwitchCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(autoDeviceSwitchCallback_ == nullptr, "autoDeviceSwitchCallback is nullptr.");
    autoDeviceSwitchCallback_->RemoveCallbackRef(eventName, callback);
}

void AutoDeviceSwitchCallbackListener::OnAutoDeviceSwitchStatusChange(
    bool isDeviceSwitched, bool isDeviceCapabilityChanged) const
{
    MEDIA_INFO_LOG("isDeviceSwitched: %{public}d, isDeviceCapabilityChanged: %{public}d",
        isDeviceSwitched, isDeviceCapabilityChanged);
    OnAutoDeviceSwitchCallback(isDeviceSwitched, isDeviceCapabilityChanged);
}

void AutoDeviceSwitchCallbackListener::OnAutoDeviceSwitchCallback(
    bool isDeviceSwitched, bool isDeviceCapabilityChanged) const
{
    MEDIA_DEBUG_LOG("OnAutoDeviceSwitchCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [isDeviceSwitched, isDeviceCapabilityChanged, sharePtr]() {
        AutoDeviceSwitchStatus autoDeviceSwitchStatus{
            isDeviceSwitched,
            isDeviceCapabilityChanged
        };
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback<AutoDeviceSwitchStatus const&>(
            "autoDeviceSwitchStatusChange", 0, "Callback is OK", autoDeviceSwitchStatus));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnAutoDeviceSwitchStatusChange",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void SessionImpl::OnFeatureDetection(SceneFeatureType featureType,
    callback_view<void(uintptr_t, SceneFeatureDetectionResult const&)> callback)
{
    featureType_ = featureType;
    ListenerTemplate<SessionImpl>::On(this, callback, "featureDetection");
}

void SessionImpl::OffFeatureDetection(SceneFeatureType featureType_,
    optional_view<callback<void(uintptr_t, SceneFeatureDetectionResult const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "featureDetection");
}

void SessionImpl::RegisterFeatureDetectionStatusListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi on featureDetection is called!");
    if (featureType_ < OHOS::CameraStandard::SceneFeature::FEATURE_ENUM_MIN ||
        featureType_ >= OHOS::CameraStandard::SceneFeature::FEATURE_ENUM_MAX) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "scene feature invalid");
        MEDIA_ERR_LOG("CameraSessionTaihe::RegisterFeatureDetectionStatusListener scene feature invalid");
        return;
    }

    if (featureDetectionCallback_ == nullptr) {
        ani_env *env = get_env();
        featureDetectionCallback_ = std::make_shared<FeatureDetectionStatusCallbackListener>(env);
        captureSessionForSys_->SetFeatureDetectionStatusCallback(featureDetectionCallback_);
    }

    if (featureType_ == OHOS::CameraStandard::SceneFeature::FEATURE_LOW_LIGHT_BOOST) {
        captureSessionForSys_->LockForControl();
        captureSessionForSys_->EnableLowLightDetection(true);
        captureSessionForSys_->UnlockForControl();
    }
    if (featureType_ == OHOS::CameraStandard::SceneFeature::FEATURE_TRIPOD_DETECTION) {
        captureSessionForSys_->LockForControl();
        captureSessionForSys_->EnableTripodDetection(true);
        captureSessionForSys_->UnlockForControl();
    }
    featureDetectionCallback_->SaveCallbackReference(eventName + std::to_string(featureType_), callback, isOnce);
}

void SessionImpl::UnregisterFeatureDetectionStatusListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi off featureDetection is called!");
    CHECK_RETURN_ELOG(featureDetectionCallback_ == nullptr, "featureDetectionCallback_ is null");
    if (featureType_ < OHOS::CameraStandard::SceneFeature::FEATURE_ENUM_MIN ||
        featureType_ >=OHOS::CameraStandard::SceneFeature::FEATURE_ENUM_MAX) {
        CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::INVALID_ARGUMENT, "scene feature invalid");
        MEDIA_ERR_LOG("CameraSessionTaihe::UnregisterFeatureDetectionStatusListener scene feature invalid");
        return;
    }

    featureDetectionCallback_->RemoveCallbackRef(eventName + std::to_string(featureType_), callback);

    if (featureType_ == OHOS::CameraStandard::SceneFeature::FEATURE_LOW_LIGHT_BOOST &&
        !featureDetectionCallback_->IsFeatureSubscribed(OHOS::CameraStandard::SceneFeature::FEATURE_LOW_LIGHT_BOOST)) {
        captureSessionForSys_->LockForControl();
        captureSessionForSys_->EnableLowLightDetection(false);
        captureSessionForSys_->UnlockForControl();
    }
    if (featureType_ == OHOS::CameraStandard::SceneFeature::FEATURE_TRIPOD_DETECTION &&
        !featureDetectionCallback_->IsFeatureSubscribed(OHOS::CameraStandard::SceneFeature::FEATURE_TRIPOD_DETECTION)) {
        captureSessionForSys_->LockForControl();
        captureSessionForSys_->EnableTripodDetection(false);
        captureSessionForSys_->UnlockForControl();
    }
}

void FeatureDetectionStatusCallbackListener::OnFeatureDetectionStatusChanged(
    OHOS::CameraStandard::SceneFeature feature, FeatureDetectionStatusCallbackListener::FeatureDetectionStatus status)
{
    MEDIA_DEBUG_LOG(
        "OnFeatureDetectionStatusChanged is called,feature:%{public}d, status: %{public}d", feature, status);
    OnFeatureDetectionStatusChangedCallback(feature, status);
}

void FeatureDetectionStatusCallbackListener::OnFeatureDetectionStatusChangedCallback(
    OHOS::CameraStandard::SceneFeature feature,
    FeatureDetectionStatusCallbackListener::FeatureDetectionStatus status) const
{
    MEDIA_DEBUG_LOG("OnFeatureDetectionStatusChangedCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [feature, status, sharePtr]() {
        std::string eventName = "featureDetection" + std::to_string(static_cast<int32_t>(feature));
        std::string eventNameOld = "featureDetectionStatus" + std::to_string(static_cast<int32_t>(feature));
        auto featureType = CameraUtilsTaihe::ToTaiheSceneFeatureType(feature);
        SceneFeatureDetectionResult sceneFeatureDetectionResult = {
            featureType,
            status
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(eventName, 0, "Callback is OK", sceneFeatureDetectionResult));
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback(eventNameOld, 0, "Callback is OK", sceneFeatureDetectionResult));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnFeatureDetection", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

bool FeatureDetectionStatusCallbackListener::IsFeatureSubscribed(OHOS::CameraStandard::SceneFeature feature)
{
    std::string eventName = "featureDetection" + std::to_string(static_cast<int32_t>(feature));
    std::string eventNameOld = "featureDetectionStatus" + std::to_string(static_cast<int32_t>(feature));

    return !IsEmpty(eventName) || !IsEmpty(eventNameOld);
}

void SessionImpl::OnMacroStatusChanged(callback_view<void(uintptr_t, bool)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "macroStatusChanged");
}

void SessionImpl::OffMacroStatusChanged(optional_view<callback<void(uintptr_t, bool)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "macroStatusChanged");
}

void SessionImpl::RegisterMacroStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (macroStatusCallback_ == nullptr) {
        ani_env *env = get_env();
        macroStatusCallback_ = std::make_shared<MacroStatusCallbackListener>(env);
        captureSession_->SetMacroStatusCallback(macroStatusCallback_);
    }
    macroStatusCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void SessionImpl::UnregisterMacroStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(macroStatusCallback_ == nullptr, "macroStatusCallback is null");
    macroStatusCallback_->RemoveCallbackRef(eventName, callback);
}

void MacroStatusCallbackListener::OnMacroStatusChanged(MacroStatus status)
{
    MEDIA_DEBUG_LOG("OnMacroStatusChanged is called, status: %{public}d", status);
    OnMacroStatusCallback(status);
}

void MacroStatusCallbackListener::OnMacroStatusCallback(MacroStatus status) const
{
    MEDIA_DEBUG_LOG("OnMacroStatusCallback is called, status: %{public}d", status);
    auto sharePtr = shared_from_this();
    auto task = [status, sharePtr]() {
        auto boolStatus = CameraUtilsTaihe::ToTaiheMacroStatus(status);
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("macroStatusChanged", 0, "Callback is OK", boolStatus));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnMacroStatusChanged", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void SessionImpl::OnLightStatusChange(callback_view<void(uintptr_t, LightStatus)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "lightStatusChange");
}

void SessionImpl::OffLightStatusChange(
    optional_view<callback<void(uintptr_t, LightStatus)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "lightStatusChange");
}

void SessionImpl::RegisterLightStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi on lightStatusChange is called");
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::UnregisterLightStatusCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi off macroStatusChanged is called!");
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::OnFocusTrackingInfoAvailable(
    callback_view<void(FocusTrackingInfo const&)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "focusTrackingInfoAvailable");
}

void SessionImpl::OffFocusTrackingInfoAvailable(
    optional_view<callback<void(FocusTrackingInfo const&)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "focusTrackingInfoAvailable");
}

void SessionImpl::RegisterFocusTrackingInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi on focusTrackingInfoAvailable is called");
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::UnregisterFocusTrackingInfoCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi off focusTrackingInfoAvailable is called");
    CameraUtilsTaihe::ThrowError(OHOS::CameraStandard::CameraErrorCode::OPERATION_NOT_ALLOWED,
        "this type callback can not be registered in current session!");
}

void SessionImpl::OnEffectSuggestionChange(
    callback_view<void(uintptr_t, EffectSuggestionType)> callback)
{
    ListenerTemplate<SessionImpl>::On(this, callback, "effectSuggestionChange");
}

void SessionImpl::OffEffectSuggestionChange(
    optional_view<callback<void(uintptr_t, EffectSuggestionType)>> callback)
{
    ListenerTemplate<SessionImpl>::Off(this, callback, "effectSuggestionChange");
}

void SessionImpl::RegisterEffectSuggestionCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi on effectSuggestionChange is called!");
    if (effectSuggestionCallback_ == nullptr) {
        ani_env *env = get_env();
        auto effectSuggestionCallback = std::make_shared<EffectSuggestionCallbackListener>(env);
        effectSuggestionCallback_ = effectSuggestionCallback;
        captureSessionForSys_->SetEffectSuggestionCallback(effectSuggestionCallback);
    }
    effectSuggestionCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void SessionImpl::UnregisterEffectSuggestionCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi off effectSuggestionChange is called!");
    CHECK_RETURN_ELOG(effectSuggestionCallback_ == nullptr, "macroStatusCallback is null");
    effectSuggestionCallback_->RemoveCallbackRef(eventName, callback);
}

void EffectSuggestionCallbackListener::OnEffectSuggestionChange(
    OHOS::CameraStandard::EffectSuggestionType effectSuggestionType)
{
    MEDIA_DEBUG_LOG("OnEffectSuggestionChange is called, effectSuggestionType: %{public}d", effectSuggestionType);
    OnEffectSuggestionCallback(effectSuggestionType);
}

void EffectSuggestionCallbackListener::OnEffectSuggestionCallback(
    OHOS::CameraStandard::EffectSuggestionType effectSuggestionType) const
{
    MEDIA_DEBUG_LOG("OnEffectSuggestionCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [effectSuggestionType, sharePtr]() {
        auto aniEffectSuggestionType = CameraUtilsTaihe::ToTaiheEffectSuggestionType(effectSuggestionType);
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteAsyncCallback(
            "effectSuggestionChange", 0, "Callback is OK", aniEffectSuggestionType));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnEffectSuggestionChange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

const SessionImpl::EmitterFunctions SessionImpl::fun_map_ = {
    { "focusStateChange", {
        &SessionImpl::RegisterFocusCallbackListener,
        &SessionImpl::UnregisterFocusCallbackListener } },
    { "macroStatusChanged", {
        &SessionImpl::RegisterMacroStatusCallbackListener,
        &SessionImpl::UnregisterMacroStatusCallbackListener } },
    { "featureDetection", {
        &SessionImpl::RegisterFeatureDetectionStatusListener,
        &SessionImpl::UnregisterFeatureDetectionStatusListener } },
    { "error", {
        &SessionImpl::RegisterSessionErrorCallbackListener,
        &SessionImpl::UnregisterSessionErrorCallbackListener } },
    { "smoothZoomInfoAvailable", {
        &SessionImpl::RegisterSmoothZoomCallbackListener,
        &SessionImpl::UnregisterSmoothZoomCallbackListener } },
    { "slowMotionStatus", {
        &SessionImpl::RegisterSlowMotionStateCb,
        &SessionImpl::UnregisterSlowMotionStateCb } },
    { "exposureInfoChange", {
        &SessionImpl::RegisterExposureInfoCallbackListener,
        &SessionImpl::UnregisterExposureInfoCallbackListener} },
    { "isoInfoChange", {
        &SessionImpl::RegisterIsoInfoCallbackListener,
        &SessionImpl::UnregisterIsoInfoCallbackListener } },
    { "apertureInfoChange", {
        &SessionImpl::RegisterApertureInfoCallbackListener,
        &SessionImpl::UnregisterApertureInfoCallbackListener } },
    { "luminationInfoChange", {
        &SessionImpl::RegisterLuminationInfoCallbackListener,
        &SessionImpl::UnregisterLuminationInfoCallbackListener } },
    { "effectSuggestionChange", {
        &SessionImpl::RegisterEffectSuggestionCallbackListener,
        &SessionImpl::UnregisterEffectSuggestionCallbackListener } },
    { "tryAEInfoChange", {
        &SessionImpl::RegisterTryAEInfoCallbackListener,
        &SessionImpl::UnregisterTryAEInfoCallbackListener } },
    { "lcdFlashStatus", {
        &SessionImpl::RegisterLcdFlashStatusCallbackListener,
        &SessionImpl::UnregisterLcdFlashStatusCallbackListener } },
    { "autoDeviceSwitchStatusChange", {
        &SessionImpl::RegisterAutoDeviceSwitchCallbackListener,
        &SessionImpl::UnregisterAutoDeviceSwitchCallbackListener } },
    { "focusTrackingInfoAvailable", {
        &SessionImpl::RegisterFocusTrackingInfoCallbackListener,
        &SessionImpl::UnregisterFocusTrackingInfoCallbackListener } },
    { "lightStatusChange", {
        &SessionImpl::RegisterLightStatusCallbackListener,
        &SessionImpl::UnregisterLightStatusCallbackListener } },
    { "systemPressureLevelChange", {
        &SessionImpl::RegisterPressureStatusCallbackListener,
        &SessionImpl::UnregisterPressureStatusCallbackListener } },
};
const SessionImpl::EmitterFunctions& SessionImpl::GetEmitterFunctions()
{
    return fun_map_;
}
} // namespace Ani
} // namespace Camera