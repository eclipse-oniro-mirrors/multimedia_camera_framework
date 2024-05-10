/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "camera_log.h"
#include "camera_util.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;

class InnerCameraInputCallback : public ErrorCallback {
public:
    InnerCameraInputCallback(Camera_Input* cameraInput, CameraInput_Callbacks* callback)
        : cameraInput_(cameraInput), callback_(*callback) {}
    ~InnerCameraInputCallback() = default;
    void OnError(const int32_t errorType, const int32_t errorMsg) const override
    {
        MEDIA_DEBUG_LOG("OnError is called!, errorType: %{public}d", errorType);
        if (cameraInput_ != nullptr && callback_.onError != nullptr) {
            callback_.onError(cameraInput_, FrameworkToNdkCameraError(errorType));
        }
    }

private:
    Camera_Input* cameraInput_;
    CameraInput_Callbacks callback_;
};

Camera_Input::Camera_Input(sptr<CameraInput> &innerCameraInput) : innerCameraInput_(innerCameraInput)
{
    MEDIA_DEBUG_LOG("Camera_Input Constructor is called");
}

Camera_Input::~Camera_Input()
{
    MEDIA_DEBUG_LOG("~Camera_Input is called");
    if (innerCameraInput_) {
        innerCameraInput_ = nullptr;
    }
}

Camera_ErrorCode Camera_Input::RegisterCallback(CameraInput_Callbacks* callback)
{
    shared_ptr<InnerCameraInputCallback> innerCallback =
                make_shared<InnerCameraInputCallback>(this, callback);
    innerCameraInput_->SetErrorCallback(innerCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Input::UnregisterCallback(CameraInput_Callbacks* callback)
{
    innerCameraInput_->SetErrorCallback(nullptr);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_Input::Open()
{
    int32_t ret = innerCameraInput_->Open();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_Input::OpenSecureCamera(uint64_t* secureSeqId)
{
    int32_t ret = innerCameraInput_->Open(true, secureSeqId);
    MEDIA_INFO_LOG("Camera_Input::OpenSecureCamera secureSeqId = %{public}" PRIu64 "", *secureSeqId);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_Input::Close()
{
    int32_t ret = innerCameraInput_->Close();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_Input::Release()
{
    int32_t ret = innerCameraInput_->Release();
    return FrameworkToNdkCameraError(ret);
}

sptr<CameraInput> Camera_Input::GetInnerCameraInput()
{
    return innerCameraInput_;
}