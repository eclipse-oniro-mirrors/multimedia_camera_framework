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

#include "preview_output_impl.h"
#include "camera_log.h"
#include "camera_output_capability.h"
#include "camera_util.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::CameraStandard;
const std::unordered_map<CameraFormat, Camera_Format> g_fwToNdkCameraFormat = {
    {CameraFormat::CAMERA_FORMAT_RGBA_8888, Camera_Format::CAMERA_FORMAT_RGBA_8888},
    {CameraFormat::CAMERA_FORMAT_YUV_420_SP, Camera_Format::CAMERA_FORMAT_YUV_420_SP},
    {CameraFormat::CAMERA_FORMAT_JPEG, Camera_Format::CAMERA_FORMAT_JPEG},
    {CameraFormat::CAMERA_FORMAT_YCBCR_P010, Camera_Format::CAMERA_FORMAT_YCBCR_P010},
    {CameraFormat::CAMERA_FORMAT_YCRCB_P010, Camera_Format::CAMERA_FORMAT_YCRCB_P010}
};

class InnerPreviewOutputCallback : public PreviewStateCallback {
public:
    InnerPreviewOutputCallback(Camera_PreviewOutput* previewOutput, PreviewOutput_Callbacks* callback)
        : previewOutput_(previewOutput), callback_(*callback) {}
    ~InnerPreviewOutputCallback() = default;

    void OnFrameStarted() const override
    {
        MEDIA_DEBUG_LOG("OnFrameStarted is called!");
        if (previewOutput_ != nullptr && callback_.onFrameStart != nullptr) {
            callback_.onFrameStart(previewOutput_);
        }
    }

    void OnFrameEnded(const int32_t frameCount) const override
    {
        MEDIA_DEBUG_LOG("OnFrameEnded is called! frame count: %{public}d", frameCount);
        if (previewOutput_ != nullptr && callback_.onFrameEnd != nullptr) {
            callback_.onFrameEnd(previewOutput_, frameCount);
        }
    }

    void OnError(const int32_t errorCode) const override
    {
        MEDIA_DEBUG_LOG("OnError is called!, errorCode: %{public}d", errorCode);
        if (previewOutput_ != nullptr && callback_.onError != nullptr) {
            callback_.onError(previewOutput_, FrameworkToNdkCameraError(errorCode));
        }
    }

    void OnSketchStatusDataChanged(const SketchStatusData& statusData) const override {}

private:
    Camera_PreviewOutput* previewOutput_;
    PreviewOutput_Callbacks callback_;
};

Camera_PreviewOutput::Camera_PreviewOutput(sptr<PreviewOutput> &innerPreviewOutput)
    : innerPreviewOutput_(innerPreviewOutput)
{
    MEDIA_DEBUG_LOG("Camera_PreviewOutput Constructor is called");
}

Camera_PreviewOutput::~Camera_PreviewOutput()
{
    MEDIA_DEBUG_LOG("~Camera_PreviewOutput is called");
    if (innerPreviewOutput_) {
        innerPreviewOutput_ = nullptr;
    }
}

Camera_ErrorCode Camera_PreviewOutput::RegisterCallback(PreviewOutput_Callbacks* callback)
{
    shared_ptr<InnerPreviewOutputCallback> innerCallback =
                make_shared<InnerPreviewOutputCallback>(this, callback);
    innerPreviewOutput_->SetCallback(innerCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PreviewOutput::UnregisterCallback(PreviewOutput_Callbacks* callback)
{
    innerPreviewOutput_->SetCallback(nullptr);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PreviewOutput::Start()
{
    int32_t ret = innerPreviewOutput_->Start();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_PreviewOutput::Stop()
{
    int32_t ret = innerPreviewOutput_->Stop();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_PreviewOutput::Release()
{
    int32_t ret = innerPreviewOutput_->Release();
    return FrameworkToNdkCameraError(ret);
}

sptr<PreviewOutput> Camera_PreviewOutput::GetInnerPreviewOutput()
{
    return innerPreviewOutput_;
}

Camera_ErrorCode Camera_PreviewOutput::GetActiveProfile(Camera_Profile** profile)
{
    auto previewOutputProfile = innerPreviewOutput_->GetPreviewProfile();
    CHECK_AND_RETURN_RET_LOG(previewOutputProfile != nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PreviewOutput::GetActiveProfile failed to get preview profile!");

    CameraFormat cameraFormat = previewOutputProfile->GetCameraFormat();
    auto itr = g_fwToNdkCameraFormat.find(cameraFormat);
    CHECK_AND_RETURN_RET_LOG(itr != g_fwToNdkCameraFormat.end(), CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PreviewOutput::GetActiveProfile Unsupported camera format %{public}d", cameraFormat);

    Camera_Profile* newProfile = new Camera_Profile;
    CHECK_AND_RETURN_RET_LOG(newProfile != nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PreviewOutput::GetActiveProfile failed to allocate memory for camera profile!");

    newProfile->format = itr->second;
    newProfile->size.width = previewOutputProfile->GetSize().width;
    newProfile->size.height = previewOutputProfile->GetSize().height;

    *profile = newProfile;
    return CAMERA_OK;
}