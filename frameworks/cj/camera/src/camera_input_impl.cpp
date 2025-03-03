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

#include "camera_input_impl.h"
#include "camera_error.h"
#include <cstdlib>
#include <iomanip>
#include <map>
#include <string>
#include <variant>
#include <vector>
#include "camera_log.h"
#include "camera_utils.h"
#include "cj_lambda.h"
#include "ffi_remote_data.h"
#include "securec.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace CameraStandard {
void CJErrorCallbackListener::OnError(const int32_t errorType, const int32_t errorMsg) const
{
    ExecuteCallback(errorType, errorMsg);
}

CJCameraInput::CJCameraInput(sptr<CameraInput> cameraInputInstance)
{
    cameraInput_ = cameraInputInstance;
}

CJCameraInput::~CJCameraInput()
{
}

sptr<CameraStandard::CameraInput> CJCameraInput::GetCameraInput()
{
    return cameraInput_;
}

int32_t CJCameraInput::Open()
{
    if (cameraInput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return cameraInput_->Open();
}

int32_t CJCameraInput::Open(bool isEnableSecureCamera, uint64_t *secureSeqId)
{
    if (cameraInput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return cameraInput_->Open(isEnableSecureCamera, secureSeqId);
}

int32_t CJCameraInput::Close()
{
    if (cameraInput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return cameraInput_->Close();
}

void CJCameraInput::OnError(int64_t callbackId)
{
    if (errorCallback_ == nullptr) {
        errorCallback_ = std::make_shared<CJErrorCallbackListener>();
        if (errorCallback_ == nullptr || cameraInput_ == nullptr) {
            return;
        }
        cameraInput_->SetErrorCallback(errorCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(CJErrorCallback error)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t errorType, const int32_t errorMsg) -> void {
        lambda(ErrorCallBackToCJErrorCallBack(errorType, errorMsg));
    };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t, const int32_t>>(callback, callbackId);
    errorCallback_->SaveCallbackRef(callbackRef);
}

void CJCameraInput::OffError(int64_t callbackId)
{
    if (errorCallback_ == nullptr) {
        return;
    }
    errorCallback_->RemoveCallbackRef(callbackId);
}

void CJCameraInput::OffAllError()
{
    if (errorCallback_ == nullptr) {
        return;
    }
    errorCallback_->RemoveAllCallbackRef();
}

} // namespace CameraStandard
} // namespace OHOS