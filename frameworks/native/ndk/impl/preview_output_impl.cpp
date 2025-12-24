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
#include <mutex>
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
namespace OHOS::CameraStandard {
class InnerPreviewOutputCallback : public PreviewStateCallback {
public:
    InnerPreviewOutputCallback(Camera_PreviewOutput* previewOutput, PreviewOutput_Callbacks* callback)
        : previewOutput_(previewOutput), callback_(*callback)
    {}
    ~InnerPreviewOutputCallback() = default;

    void OnFrameStarted() const override
    {
        MEDIA_DEBUG_LOG("OnFrameStarted is called!");
        CHECK_RETURN(previewOutput_ == nullptr || callback_.onFrameStart == nullptr);
        callback_.onFrameStart(previewOutput_);
    }

    void OnFrameEnded(const int32_t frameCount) const override
    {
        MEDIA_DEBUG_LOG("OnFrameEnded is called! frame count: %{public}d", frameCount);
        CHECK_RETURN(previewOutput_ == nullptr || callback_.onFrameEnd == nullptr);
        callback_.onFrameEnd(previewOutput_, frameCount);
    }

    void OnError(const int32_t errorCode) const override
    {
        MEDIA_DEBUG_LOG("OnError is called!, errorCode: %{public}d", errorCode);
        CHECK_RETURN(previewOutput_ == nullptr || callback_.onError == nullptr);
        callback_.onError(previewOutput_, FrameworkToNdkCameraError(errorCode));
    }

    void OnFramePaused() const override
    {
        MEDIA_DEBUG_LOG("OnFramePaused is called!");
    }

    void OnFrameResumed() const override
    {
        MEDIA_DEBUG_LOG("OnFrameResumed is called!");
    }

    void OnSketchStatusDataChanged(const SketchStatusData& statusData) const override {}

private:
    Camera_PreviewOutput* previewOutput_;
    PreviewOutput_Callbacks callback_;
};
} // namespace OHOS::CameraStandard

Camera_PreviewOutput::Camera_PreviewOutput(sptr<PreviewOutput> &innerPreviewOutput)
    : innerPreviewOutput_(innerPreviewOutput)
{
    MEDIA_DEBUG_LOG("Camera_PreviewOutput Constructor is called");
}

Camera_PreviewOutput::~Camera_PreviewOutput()
{
    MEDIA_DEBUG_LOG("~Camera_PreviewOutput is called");
    innerPreviewOutput_ = nullptr;
}

Camera_ErrorCode Camera_PreviewOutput::RegisterCallback(PreviewOutput_Callbacks* callback)
{
    shared_ptr<InnerPreviewOutputCallback> innerCallback = make_shared<InnerPreviewOutputCallback>(this, callback);
    CHECK_RETURN_RET(callbackMap_.SetMapValue(callback, innerCallback) == false, CAMERA_OK);
    innerPreviewOutput_->SetCallback(innerCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PreviewOutput::UnregisterCallback(PreviewOutput_Callbacks* callback)
{
    auto innerCallback = callbackMap_.RemoveValue(callback);
    CHECK_RETURN_RET(innerCallback == nullptr, CAMERA_OK);
    innerPreviewOutput_->RemoveCallback(innerCallback);
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
    CHECK_RETURN_RET_ELOG(previewOutputProfile == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PreviewOutput::GetActiveProfile failed to get preview profile!");

    CameraFormat cameraFormat = previewOutputProfile->GetCameraFormat();
    auto itr = g_fwToNdkCameraFormat.find(cameraFormat);
    CHECK_RETURN_RET_ELOG(itr == g_fwToNdkCameraFormat.end(), CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PreviewOutput::GetActiveProfile Unsupported camera format %{public}d", cameraFormat);

    Camera_Profile* newProfile = new Camera_Profile;
    CHECK_RETURN_RET_ELOG(newProfile == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PreviewOutput::GetActiveProfile failed to allocate memory for camera profile!");

    newProfile->format = itr->second;
    newProfile->size.width = previewOutputProfile->GetSize().width;
    newProfile->size.height = previewOutputProfile->GetSize().height;

    *profile = newProfile;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PreviewOutput::GetSupportedFrameRates(Camera_FrameRateRange** frameRateRange, uint32_t* size)
{
    std::vector<std::vector<int32_t>> frameRate = innerPreviewOutput_->GetSupportedFrameRates();
    if (frameRate.size() == 0) {
        *size = 0;
        return CAMERA_OK;
    }

    Camera_FrameRateRange* newframeRateRange =  new Camera_FrameRateRange[frameRate.size()];
    CHECK_RETURN_RET_ELOG(newframeRateRange == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Failed to allocate memory for Camera_FrameRateRange!");

    for (size_t index = 0; index < frameRate.size(); ++index) {
        if (frameRate[index].size() <= 1) {
            MEDIA_ERR_LOG("invalid frameRate size!");
            delete[] newframeRateRange;
            newframeRateRange = nullptr;
            return CAMERA_SERVICE_FATAL_ERROR;
        }
        newframeRateRange[index].min = static_cast<uint32_t>(frameRate[index][0]);
        newframeRateRange[index].max = static_cast<uint32_t>(frameRate[index][1]);
    }

    *frameRateRange = newframeRateRange;
    *size = frameRate.size();
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PreviewOutput::DeleteFrameRates(Camera_FrameRateRange* frameRateRange)
{
    CHECK_RETURN_RET(frameRateRange == nullptr, CAMERA_OK);
    delete[] frameRateRange;
    frameRateRange = nullptr;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PreviewOutput::SetFrameRate(int32_t minFps, int32_t maxFps)
{
    int32_t ret = innerPreviewOutput_->SetFrameRate(minFps, maxFps);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_PreviewOutput::GetActiveFrameRate(Camera_FrameRateRange* frameRateRange)
{
    std::vector<int32_t> activeFrameRate = innerPreviewOutput_->GetFrameRateRange();
    CHECK_RETURN_RET_ELOG(activeFrameRate.size() <= 1, CAMERA_SERVICE_FATAL_ERROR, "invalid activeFrameRate size!");

    frameRateRange->min = static_cast<uint32_t>(activeFrameRate[0]);
    frameRateRange->max = static_cast<uint32_t>(activeFrameRate[1]);

    return CAMERA_OK;
}
Camera_ErrorCode Camera_PreviewOutput::GetPreviewRotation(int32_t imageRotation,
    Camera_ImageRotation* cameraImageRotation)
{
    CHECK_RETURN_RET_ELOG(cameraImageRotation == nullptr, CAMERA_SERVICE_FATAL_ERROR, "GetCameraImageRotation failed");
    int32_t cameraOutputRotation = innerPreviewOutput_->GetPreviewRotation(imageRotation);
    CHECK_RETURN_RET_ELOG(cameraOutputRotation == CAMERA_INVALID_ARGUMENT, CAMERA_INVALID_ARGUMENT,
        "Camera_PreviewOutput::GetPreviewRotation camera invalid argument! ret: %{public}d", cameraOutputRotation);
    CHECK_RETURN_RET_ELOG(cameraOutputRotation == CAMERA_SERVICE_FATAL_ERROR, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PreviewOutput::GetPreviewRotation camera service fatal error! ret: %{public}d", cameraOutputRotation);
    *cameraImageRotation = static_cast<Camera_ImageRotation>(cameraOutputRotation);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PreviewOutput::SetPreviewRotation(int32_t imageRotation, bool isDisplayLocked)
{
    int32_t ret = innerPreviewOutput_->SetPreviewRotation(imageRotation, isDisplayLocked);
    CHECK_RETURN_RET_ELOG(ret == CAMERA_INVALID_ARGUMENT, CAMERA_INVALID_ARGUMENT,
        "Camera_PreviewOutput::SetPreviewRotation camera invalid argument! ret: %{public}d", ret);
    CHECK_RETURN_RET_ELOG(ret == CAMERA_SERVICE_FATAL_ERROR, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PhotoOutput::SetPreviewRotation camera service fatal error! ret: %{public}d", ret);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_PreviewOutput::IsBandwidthCompressionSupported(bool* isSupported)
{
    *isSupported = innerPreviewOutput_->IsBandwidthCompressionSupported();

    return CAMERA_OK;
}

Camera_ErrorCode Camera_PreviewOutput::EnableBandwidthCompression(bool enabled)
{
    int32_t ret = innerPreviewOutput_->EnableBandwidthCompression(enabled);
    CHECK_RETURN_RET_ELOG(ret == CAMERA_SERVICE_FATAL_ERROR, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_PreviewOutput::EnableBandwidthCompression camera service fatal error! ret: %{public}d", ret);
    CHECK_RETURN_RET_ELOG(ret == CAMERA_SESSION_NOT_CONFIG, CAMERA_SESSION_NOT_CONFIG,
        "Camera_PreviewOutput::EnableBandwidthCompression camera session not config! ret: %{public}d", ret);
    CHECK_RETURN_RET_ELOG(ret == CAMERA_OPERATION_NOT_ALLOWED, CAMERA_OPERATION_NOT_ALLOWED,
        "Camera_PreviewOutput::EnableBandwidthCompression camera operation not allowed! ret: %{public}d", ret);
    return CAMERA_OK;
}