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

#include "camera_input_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_security_utils_taihe.h"
#include "camera_template_utils_taihe.h"

using namespace taihe;
using namespace ohos::multimedia::camera;

namespace Ani {
namespace Camera {

uint32_t CameraInputImpl::cameraInputTaskId_ = CAMERA_INPUT_TASKID;

void ErrorCallbackListenerAni::OnError(const int32_t errorType, const int32_t errorMsg) const
{
    MEDIA_DEBUG_LOG("OnError is called, errorType: %{public}d, errorMsg: %{public}d", errorType, errorMsg);
    OnErrorCallback(errorType, errorMsg);
}

void ErrorCallbackListenerAni::OnErrorCallback(const int32_t errorType, const int32_t errorMsg) const
{
    MEDIA_DEBUG_LOG("OnErrorCallback is called, errorType: %{public}d", errorType);
    auto sharePtr = shared_from_this();
    auto task = [errorType, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback("error", errorType));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void OcclusionDetectCallbackListenerAni::OnCameraOcclusionDetected(const uint8_t isCameraOcclusion,
                                                                   const uint8_t isCameraLensDirty) const
{
    MEDIA_DEBUG_LOG("OnCameraOcclusionDetected is called, isCameraOcclusion: %{public}d, isCameraLensDirty: %{public}d",
        isCameraOcclusion, isCameraLensDirty);
    OnCameraOcclusionDetectedCallback(isCameraOcclusion, isCameraLensDirty);
}

void OcclusionDetectCallbackListenerAni::OnCameraOcclusionDetectedCallback(const uint8_t isCameraOcclusion,
                                                                           const uint8_t isCameraLensDirty) const
{
    MEDIA_DEBUG_LOG("OnCameraOcclusionDetectedCallback is called, isCameraOcclusion: %{public}d, "
        "isCameraLensDirty: %{public}d", isCameraOcclusion, isCameraLensDirty);
    auto sharePtr = shared_from_this();
    auto task = [isCameraOcclusion, isCameraLensDirty, sharePtr]() {
        CameraOcclusionDetectionResult res = {
            .isCameraOccluded = isCameraOcclusion == 1 ? true : false,
            .isCameraLensDirty = isCameraLensDirty == 1 ? true : false,
        };
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback<CameraOcclusionDetectionResult const&>(
                "cameraOcclusionDetect", 0, "Callback is OK", res));
    };
    CHECK_ERROR_RETURN_LOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnCameraOcclusionDetection",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

CameraInputImpl::CameraInputImpl(sptr<OHOS::CameraStandard::CameraInput> input)
{
    cameraInput_ = static_cast<OHOS::CameraStandard::CameraInput*>(input.GetRefPtr());
}

void CameraInputImpl::OpenSync()
{
    MEDIA_DEBUG_LOG("OpenSync is called");
    std::unique_ptr<CameraInputAsyncContext> asyncContext = std::make_unique<CameraInputAsyncContext>(
        "CameraInputImpl::OpenSync", CameraUtilsTaihe::IncrementAndGet(cameraInputTaskId_));
    CHECK_ERROR_RETURN_LOG(cameraInput_ == nullptr, "cameraInput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("CameraInputImpl::OpenSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "cameraInput_ is nullptr");
        asyncContext->isEnableSecCam = CameraUtilsTaihe::GetEnableSecureCamera();
        MEDIA_DEBUG_LOG("CameraInputImpl::Open asyncContext->isEnableSecCam %{public}d", asyncContext->isEnableSecCam);

        asyncContext->errorCode = asyncContext->objectInfo->GetCameraInput()->Open();

        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
        CameraUtilsTaihe::IsEnableSecureCamera(false);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

array<uint64_t> CameraInputImpl::OpenByIsSecureEnabledSync(bool isSecureEnabled)
{
    MEDIA_DEBUG_LOG("OpenByIsSecureEnabledSync is called");
    std::unique_ptr<CameraInputAsyncContext> asyncContext = std::make_unique<CameraInputAsyncContext>(
        "CameraInputImpl::OpenByIsSecureEnabledSync", CameraUtilsTaihe::IncrementAndGet(cameraInputTaskId_));
    CameraUtilsTaihe::IsEnableSecureCamera(isSecureEnabled);
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask(
            "CameraInputImpl::OpenByIsSecureEnabledSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "cameraInput_ is nullptr");
        asyncContext->isEnableSecCam = CameraUtilsTaihe::GetEnableSecureCamera();
        MEDIA_DEBUG_LOG("CameraInputImpl::Open asyncContext->isEnableSecCam %{public}d", asyncContext->isEnableSecCam);
        if (asyncContext->isEnableSecCam) {
            asyncContext->errorCode =
                asyncContext->objectInfo->GetCameraInput()->Open(true, &asyncContext->secureCameraSeqId);
            MEDIA_INFO_LOG("CameraInputImpl::Open, SeqId = %{public}" PRIu64 "", asyncContext->secureCameraSeqId);
        } else {
            asyncContext->errorCode = asyncContext->objectInfo->GetCameraInput()->Open();
        }
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
        CameraUtilsTaihe::IsEnableSecureCamera(false);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    array<uint64_t> secureCameraSeqId{asyncContext->secureCameraSeqId};
    return secureCameraSeqId;
}

void CameraInputImpl::OpenByCameraConcurrentTypeSync(ohos::multimedia::camera::CameraConcurrentType type)
{
    MEDIA_DEBUG_LOG("OpenByCameraConcurrentTypeSync is called");
    std::unique_ptr<CameraInputAsyncContext> asyncContext = std::make_unique<CameraInputAsyncContext>(
        "CameraInputImpl::OpenByCameraConcurrentTypeSync", CameraUtilsTaihe::IncrementAndGet(cameraInputTaskId_));
    CHECK_ERROR_RETURN_LOG(cameraInput_ == nullptr, "cameraInput_ is nullptr");
    asyncContext->cameraConcurrentType = type;
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask(
            "CameraInputImpl::OpenByCameraConcurrentTypeSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "cameraInput_ is nullptr");
        asyncContext->isEnableSecCam = CameraUtilsTaihe::GetEnableSecureCamera();
        MEDIA_DEBUG_LOG("CameraInputImpl::Open asyncContext->isEnableSecCam %{public}d", asyncContext->isEnableSecCam);
        asyncContext->errorCode = asyncContext->objectInfo->GetCameraInput()->Open(asyncContext->cameraConcurrentType);
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
        CameraUtilsTaihe::IsEnableSecureCamera(false);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void CameraInputImpl::CloseSync()
{
    MEDIA_DEBUG_LOG("CloseSync is called");
    std::unique_ptr<CameraInputAsyncContext> asyncContext = std::make_unique<CameraInputAsyncContext>(
        "CameraInputImpl::CloseSync", CameraUtilsTaihe::IncrementAndGet(cameraInputTaskId_));
    CHECK_ERROR_RETURN_LOG(cameraInput_ == nullptr, "cameraInput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("CameraInputImpl::CloseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "cameraInput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->cameraInput_->Close();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
        CameraUtilsTaihe::IsEnableSecureCamera(false);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void CameraInputImpl::ControlAuxiliarySync(AuxiliaryType auxiliaryType, AuxiliaryStatus auxiliaryStatus)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi ControlAuxiliary is called!");
    CHECK_ERROR_RETURN_LOG(cameraInput_ == nullptr, "SystemApi ControlAuxiliary is called!");
    cameraInput_->ControlAuxiliary(static_cast<const OHOS::CameraStandard::AuxiliaryType>(auxiliaryType.get_value()),
        static_cast<const OHOS::CameraStandard::AuxiliaryStatus>(auxiliaryStatus.get_value()));
}

void CameraInputImpl::CloseDelayedSync(int32_t time)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi closeDelayed is called!");
    std::unique_ptr<CameraInputAsyncContext> asyncContext = std::make_unique<CameraInputAsyncContext>(
        "CameraInputImpl::closeDelayed", CameraUtilsTaihe::IncrementAndGet(cameraInputTaskId_));
    asyncContext->delayTime = time;
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("CameraInputImpl::closeDelayed");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_ERROR_RETURN_LOG(asyncContext->objectInfo == nullptr, "closeDelayed async info is nullptr");
        auto cameraInput = asyncContext->objectInfo->GetCameraInput();
        CHECK_ERROR_RETURN_LOG(cameraInput == nullptr, "closeDelayed GetCameraInput info is nullptr");
        asyncContext->errorCode = cameraInput->closeDelayed(asyncContext->delayTime);
        asyncContext->status = asyncContext->errorCode == OHOS::CameraStandard::CameraErrorCode::SUCCESS;
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    if (! (asyncContext->status)) {
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
        return;
    }
}

OHOS::sptr<OHOS::CameraStandard::CameraInput> CameraInputImpl::GetCameraInput()
{
    return cameraInput_;
}

const CameraInputImpl::EmitterFunctions& CameraInputImpl::GetEmitterFunctions()
{
    static const EmitterFunctions funMap = {
        { "error", {
            &CameraInputImpl::RegisterErrorCallbackListener,
            &CameraInputImpl::UnregisterErrorCallbackListener } },
        { "cameraOcclusionDetection", {
            &CameraInputImpl::RegisterOcclusionDetectCallbackListener,
            &CameraInputImpl::UnregisterOcclusionDetectCallbackListener } }
        };
    return funMap;
}

void CameraInputImpl::RegisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(cameraInput_ == nullptr,
        "failed to RegisterErrorCallbackListener, cameraInput is nullptr");
    if (errorCallback_ == nullptr) {
        ani_env *env = get_env();
        errorCallback_ = std::make_shared<ErrorCallbackListenerAni>(env);
        cameraInput_->SetErrorCallback(errorCallback_);
    }
    errorCallback_->SaveCallbackReference(eventName, callback, isOnce);
    MEDIA_INFO_LOG("CameraInputImpl::RegisterErrorCallbackListener success");
}

void CameraInputImpl::UnregisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(errorCallback_ == nullptr, "errorCallback is null");
    errorCallback_->RemoveCallbackRef(eventName, callback);
    MEDIA_INFO_LOG("CameraInputImpl::UnregisterErrorCallbackListener success");
}

void CameraInputImpl::RegisterOcclusionDetectCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    CHECK_ERROR_RETURN_LOG(cameraInput_ == nullptr,
        "failed to RegisterOcclusionDetectCallbackListener, cameraInput is nullptr");
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi On cameraOcclusionDetection is called!");
    if (occlusionDetectCallback_ == nullptr) {
        ani_env *env = get_env();
        occlusionDetectCallback_ = std::make_shared<OcclusionDetectCallbackListenerAni>(env);
        cameraInput_->SetOcclusionDetectCallback(occlusionDetectCallback_);
    }
    occlusionDetectCallback_->SaveCallbackReference(eventName, callback, isOnce);
    MEDIA_INFO_LOG("CameraInputImpl::RegisterOcclusionDetectCallbackListener success");
}

void CameraInputImpl::UnregisterOcclusionDetectCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_ERROR_RETURN_LOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi Off cameraOcclusionDetection is called!");
    CHECK_ERROR_RETURN_LOG(occlusionDetectCallback_ == nullptr, "occlusionDetectCallback is null");
    occlusionDetectCallback_->RemoveCallbackRef(eventName, callback);
    MEDIA_INFO_LOG("CameraInputImpl::UnregisterOcclusionDetectCallbackListener success");
}

void CameraInputImpl::OnError(CameraDevice const& parm, callback_view<void(uintptr_t)> callback)
{
    MEDIA_DEBUG_LOG("CameraInputImpl::OnError CameraDevice id: %{public}s", parm.cameraId.c_str());
    ListenerTemplate<CameraInputImpl>::On(this, callback, "error");
}

void CameraInputImpl::OffError(CameraDevice const& parm, optional_view<callback<void(uintptr_t)>> callback)
{
    MEDIA_DEBUG_LOG("CameraInputImpl::OffError CameraDevice id: %{public}s", parm.cameraId.c_str());
    ListenerTemplate<CameraInputImpl>::Off(this, callback, "error");
}

void CameraInputImpl::OnCameraOcclusionDetection(
    callback_view<void(uintptr_t, CameraOcclusionDetectionResult const&)> callback)
{
    MEDIA_DEBUG_LOG("CameraInputImpl::OnCameraOcclusionDetection");
    ListenerTemplate<CameraInputImpl>::On(this, callback, "cameraOcclusionDetection");
}

void CameraInputImpl::OffCameraOcclusionDetection(
    optional_view<callback<void(uintptr_t, CameraOcclusionDetectionResult const&)>> callback)
{
    MEDIA_DEBUG_LOG("CameraInputImpl::OffCameraOcclusionDetection");
    ListenerTemplate<CameraInputImpl>::Off(this, callback, "cameraOcclusionDetection");
}
} // namespace Ani
} // namespace Camera