/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "metadata_output_impl.h"
#include "camera_error.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

thread_local sptr<MetadataOutput> CJMetadataOutput::sMetadataOutput_ = nullptr;

void CJMetadataOutputCallback::OnMetadataObjectsAvailable(std::vector<sptr<MetadataObject>> metaObjects) const
{
    ExecuteCallback(metaObjects);
}

void CJMetadataStateCallback::OnError(const int32_t errorType) const
{
    ExecuteCallback(errorType);
}

CJMetadataOutput::CJMetadataOutput()
{
    metadataOutput_ = sMetadataOutput_;
    sMetadataOutput_ = nullptr;
}

int32_t CJMetadataOutput::CreateMetadataOutput(std::vector<MetadataObjectType> metadataObjectTypes)
{
    int retCode = CameraManager::GetInstance()->CreateMetadataOutput(sMetadataOutput_, metadataObjectTypes);
    if (sMetadataOutput_ == nullptr) {
        MEDIA_ERR_LOG("failed to create MetadataOutput");
    }
    return retCode;
}

sptr<CameraStandard::CaptureOutput> CJMetadataOutput::GetCameraOutput()
{
    return metadataOutput_;
}

int32_t CJMetadataOutput::Release()
{
    if (metadataOutput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return metadataOutput_->Release();
}

int32_t CJMetadataOutput::Start()
{
    if (metadataOutput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return metadataOutput_->Start();
}

int32_t CJMetadataOutput::Stop()
{
    if (metadataOutput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return metadataOutput_->Stop();
}

void CJMetadataOutput::OnMetadataObjectsAvailable(int64_t callbackId)
{
    if (metadataOutputCallback_ == nullptr) {
        metadataOutputCallback_ = std::make_shared<CJMetadataOutputCallback>();
        metadataOutput_->SetCallback(metadataOutputCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(CArrCJMetadataObject metaObjects)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](std::vector<sptr<MetadataObject>> metaObjects) -> void {
        auto res = MetadataObjectsToCArrCJMetadataObject(metaObjects);
        lambda(res);
        free(res.head);
    };
    auto callbackRef = std::make_shared<CallbackRef<std::vector<sptr<MetadataObject>>>>(callback, callbackId);
    metadataOutputCallback_->SaveCallbackRef(callbackRef);
}

void CJMetadataOutput::OffMetadataObjectsAvailable(int64_t callbackId)
{
    if (metadataOutputCallback_ == nullptr) {
        return;
    }
    metadataOutputCallback_->RemoveCallbackRef(callbackId);
}

void CJMetadataOutput::OffAllMetadataObjectsAvailable()
{
    if (metadataOutputCallback_ == nullptr) {
        return;
    }
    metadataOutputCallback_->RemoveAllCallbackRef();
}

void CJMetadataOutput::OnError(int64_t callbackId)
{
    if (metadataStateCallback_ == nullptr) {
        metadataStateCallback_ = std::make_shared<CJMetadataStateCallback>();
        metadataOutput_->SetCallback(metadataStateCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(const int32_t errorType)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t errorType) -> void { lambda(errorType); };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t>>(callback, callbackId);
    metadataStateCallback_->SaveCallbackRef(callbackRef);
}

void CJMetadataOutput::OffError(int64_t callbackId)
{
    if (metadataStateCallback_ == nullptr) {
        return;
    }
    metadataStateCallback_->RemoveCallbackRef(callbackId);
}

void CJMetadataOutput::OffAllError()
{
    if (metadataStateCallback_ == nullptr) {
        return;
    }
    metadataStateCallback_->RemoveAllCallbackRef();
}

} // namespace CameraStandard
} // namespace OHOS