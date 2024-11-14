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

#ifndef CAMERA_INPUT_IMPL_H
#define CAMERA_INPUT_IMPL_H

#include <mutex>
#include <refbase.h>
#include <string>
#include "camera_input.h"
#include "ffi_remote_data.h"
#include "listener_base.h"

namespace OHOS {
namespace CameraStandard {
class CJErrorCallbackListener : public ErrorCallback, public ListenerBase<const int32_t, const int32_t> {
public:
    CJErrorCallbackListener() = default;
    ~CJErrorCallbackListener() = default;
    void OnError(const int32_t errorType, const int32_t errorMsg) const override;
};

class CJCameraInput : public OHOS::FFI::FFIData {
public:
    OHOS::FFI::RuntimeType *GetRuntimeType() override
    {
        return GetClassType();
    }

    CJCameraInput(sptr<CameraInput> cameraInputInstance);
    ~CJCameraInput() override;

    sptr<CameraStandard::CameraInput> GetCameraInput();

    int32_t Open();
    int32_t Open(bool isEnableSecureCamera, uint64_t *secureSeqId);
    int32_t Close();
    void OnError(int64_t callbackId);
    void OffError(int64_t callbackId);
    void OffAllError();

private:
    sptr<CameraStandard::CameraInput> cameraInput_;
    friend class OHOS::FFI::RuntimeType;
    friend class OHOS::FFI::TypeBase;
    static OHOS::FFI::RuntimeType *GetClassType()
    {
        static OHOS::FFI::RuntimeType runtimeType = OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("CJCameraInput");
        return &runtimeType;
    }

    std::shared_ptr<CJErrorCallbackListener> errorCallback_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif