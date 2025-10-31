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
#include "metadata_output_taihe.h"
#include "camera_utils_taihe.h"
#include "camera_log.h"
#include "camera_template_utils_taihe.h"
#include "camera_const_ability_taihe.h"
#include "camera_security_utils_taihe.h"
#include "metadata_output.h"

using namespace taihe;
using namespace ohos::multimedia::camera;
using namespace OHOS;

namespace Ani {
namespace Camera {

uint32_t MetadataOutputImpl::metadataOutputTaskId_ = CAMERA_METADATA_OUTPUT_TASKID;

MetadataOutputImpl::MetadataOutputImpl(sptr<OHOS::CameraStandard::MetadataOutput> output) : CameraOutputImpl(output)
{
    metadataOutput_ = static_cast<OHOS::CameraStandard::MetadataOutput*>(output.GetRefPtr());
}

void MetadataOutputImpl::StartSync()
{
    MEDIA_DEBUG_LOG("StartSync is called");
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>(
        "MetadataOutputImpl::StartSync", CameraUtilsTaihe::IncrementAndGet(metadataOutputTaskId_));
    CHECK_RETURN_ELOG(metadataOutput_ == nullptr, "metadataOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MetadataOutputImpl::StartSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "metadataOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->metadataOutput_->Start();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void MetadataOutputImpl::StopSync()
{
    MEDIA_DEBUG_LOG("StopSync is called");
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>(
        "MetadataOutputImpl::StopSync", CameraUtilsTaihe::IncrementAndGet(metadataOutputTaskId_));
    CHECK_RETURN_ELOG(metadataOutput_ == nullptr, "metadataOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MetadataOutputImpl::StopSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "metadataOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->metadataOutput_->Stop();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

void MetadataOutputImpl::ReleaseSync()
{
    MEDIA_DEBUG_LOG("ReleaseSync is called");
    std::unique_ptr<MetadataOutputAsyncContext> asyncContext = std::make_unique<MetadataOutputAsyncContext>(
        "MetadataOutputImpl::ReleaseSync", CameraUtilsTaihe::IncrementAndGet(metadataOutputTaskId_));
    CHECK_RETURN_ELOG(metadataOutput_ == nullptr, "metadataOutput_ is nullptr");
    asyncContext->queueTask =
        CameraTaiheWorkerQueueKeeper::GetInstance()->AcquireWorkerQueueTask("MetadataOutputImpl::ReleaseSync");
    asyncContext->objectInfo = this;
    CAMERA_START_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
    CameraTaiheWorkerQueueKeeper::GetInstance()->ConsumeWorkerQueueTask(asyncContext->queueTask, [&asyncContext]() {
        CHECK_RETURN_ELOG(asyncContext->objectInfo == nullptr, "metadataOutput_ is nullptr");
        asyncContext->errorCode = asyncContext->objectInfo->metadataOutput_->Release();
        CameraUtilsTaihe::CheckError(asyncContext->errorCode);
    });
    CAMERA_FINISH_ASYNC_TRACE(asyncContext->funcName, asyncContext->taskId);
}

const MetadataOutputImpl::EmitterFunctions MetadataOutputImpl::fun_map_ = {
    { "metadataObjectsAvailable", {
        &MetadataOutputImpl::RegisterMetadataObjectsAvailableCallbackListener,
        &MetadataOutputImpl::UnregisterMetadataObjectsAvailableCallbackListener} },
    { "error", {
        &MetadataOutputImpl::RegisterErrorCallbackListener,
        &MetadataOutputImpl::UnregisterErrorCallbackListener } },
};

const MetadataOutputImpl::EmitterFunctions& MetadataOutputImpl::GetEmitterFunctions()
{
    return fun_map_;
}

void MetadataOutputImpl::RegisterErrorCallbackListener(const std::string& eventName,
                                                       std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (metadataOutputCallback_ == nullptr) {
        ani_env *env = get_env();
        metadataOutputCallback_ = std::make_shared<MetadataOutputCallbackListener>(env);
        metadataOutput_->SetCallback(metadataOutputCallback_);
    }
    metadataOutputCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void MetadataOutputImpl::UnregisterErrorCallbackListener(const std::string& eventName,
    std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(metadataOutputCallback_ == nullptr, "ErrorCallback is null");
    metadataOutputCallback_->RemoveCallbackRef(eventName, callback);
}

void MetadataOutputCallbackListener::OnError(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnMetadataOutputError is called, errorCode: %{public}d", errorCode);
    OnMetadataOutputErrorCallback(errorCode);
}

void MetadataOutputCallbackListener::OnMetadataOutputErrorCallback(int32_t errorCode) const
{
    MEDIA_DEBUG_LOG("OnMetadataOutputErrorCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [errorCode, sharePtr]() {
        CHECK_EXECUTE(sharePtr != nullptr, sharePtr->ExecuteErrorCallback("error", errorCode));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void MetadataOutputImpl::OnError(callback_view<void(uintptr_t)> callback)
{
    ListenerTemplate<MetadataOutputImpl>::On(this, callback, "error");
}

void MetadataOutputImpl::OffError(optional_view<callback<void(uintptr_t)>> callback)
{
    ListenerTemplate<MetadataOutputImpl>::Off(this, callback, "error");
}

void MetadataOutputImpl::RegisterMetadataObjectsAvailableCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback, bool isOnce)
{
    if (metadataObjectsAvailableCallback_ == nullptr) {
        ani_env *env = get_env();
        metadataObjectsAvailableCallback_ = std::make_shared<MetadataObjectsAvailableCallbackListener>(env);
        metadataOutput_->SetCallback(metadataObjectsAvailableCallback_);
    }
    metadataObjectsAvailableCallback_->SaveCallbackReference(eventName, callback, isOnce);
}

void MetadataOutputImpl::UnregisterMetadataObjectsAvailableCallbackListener(
    const std::string& eventName, std::shared_ptr<uintptr_t> callback)
{
    CHECK_RETURN_ELOG(metadataObjectsAvailableCallback_ == nullptr, "metadataOutputCallback is null");
    metadataObjectsAvailableCallback_->RemoveCallbackRef(eventName, callback);
}

void MetadataObjectsAvailableCallbackListener::OnMetadataObjectsAvailable(
    const std::vector<sptr<OHOS::CameraStandard::MetadataObject>> metadataObjList) const
{
    MEDIA_DEBUG_LOG("OnMetadataObjectsAvailable is called");
    OnMetadataObjectsAvailableCallback(metadataObjList);
}

void MetadataObjectsAvailableCallbackListener::OnMetadataObjectsAvailableCallback(
    const std::vector<sptr<OHOS::CameraStandard::MetadataObject>> metadataObjList) const
{
    MEDIA_DEBUG_LOG("OnMetadataObjectsAvailableCallback is called");
    auto sharePtr = shared_from_this();
    auto task = [metadataObjList, sharePtr]() {
        taihe::array<MetadataObject> metadataObject =
        CameraUtilsTaihe::ToTaiheMetadataObjectsAvailableData(metadataObjList);
        CHECK_EXECUTE(sharePtr != nullptr,
            sharePtr->ExecuteAsyncCallback("metadataObjectsAvailable", 0, "Callback is OK", metadataObject));
    };
    CHECK_RETURN_ELOG(mainHandler_ == nullptr, "callback failed, mainHandler_ is nullptr!");
    mainHandler_->PostTask(task, "OnMetadataObjectsAvailable",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
}

void MetadataOutputImpl::OnMetadataObjectsAvailable(callback_view<void(uintptr_t, array_view<MetadataObject>)> callback)
{
    ListenerTemplate<MetadataOutputImpl>::On(this, callback, "metadataObjectsAvailable");
}

void MetadataOutputImpl::OffMetadataObjectsAvailable(
    optional_view<callback<void(uintptr_t, array_view<MetadataObject>)>> callback)
{
    ListenerTemplate<MetadataOutputImpl>::Off(this, callback, "metadataObjectsAvailable");
}

void MetadataOutputImpl::RemoveMetadataObjectTypes(array_view<MetadataObjectType> types)
{
    MEDIA_INFO_LOG("RemoveMetadataObjectTypes is called");
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi RemoveMetadataObjectTypes is called!");
    std::vector<OHOS::CameraStandard::MetadataObjectType> metadataObjectType;
    for (const auto& item : types) {
        metadataObjectType.push_back(static_cast<OHOS::CameraStandard::MetadataObjectType>(item.get_value()));
    }
    int32_t retCode = metadataOutput_->RemoveMetadataObjectTypes(metadataObjectType);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode), "RemoveMetadataObjectTypes failure!");
}

void MetadataOutputImpl::AddMetadataObjectTypes(array_view<MetadataObjectType> types)
{
    MEDIA_INFO_LOG("AddMetadataObjectTypes is called");
    CHECK_RETURN_ELOG(!OHOS::CameraStandard::CameraAniSecurity::CheckSystemApp(),
        "SystemApi AddMetadataObjectTypes is called!");
    std::vector<OHOS::CameraStandard::MetadataObjectType> metadataObjectType;
    for (const auto& item : types) {
        metadataObjectType.push_back(static_cast<OHOS::CameraStandard::MetadataObjectType>(item.get_value()));
    }
    int32_t retCode = metadataOutput_->AddMetadataObjectTypes(metadataObjectType);
    CHECK_PRINT_ELOG(!CameraUtilsTaihe::CheckError(retCode), "AddMetadataObjectTypes failure!");
}
} // namespace Camera
} // namespace Ani
