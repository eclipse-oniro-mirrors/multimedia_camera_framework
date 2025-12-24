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

#include "video_output_impl.h"
#include "camera_log.h"
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

class InnerVideoOutputCallback : public VideoStateCallback {
public:
    InnerVideoOutputCallback(Camera_VideoOutput* videoOutput, VideoOutput_Callbacks* callback)
        : videoOutput_(videoOutput), callback_(*callback) {}
    ~InnerVideoOutputCallback() = default;

    void OnFrameStarted() const override
    {
        MEDIA_DEBUG_LOG("OnFrameStarted is called!");
        CHECK_RETURN(videoOutput_ == nullptr || callback_.onFrameStart == nullptr);
        callback_.onFrameStart(videoOutput_);
    }

    void OnFrameEnded(const int32_t frameCount) const override
    {
        MEDIA_DEBUG_LOG("OnFrameEnded is called! frame count: %{public}d", frameCount);
        CHECK_RETURN(videoOutput_ == nullptr || callback_.onFrameEnd == nullptr);
    }

    void OnError(const int32_t errorCode) const override
    {
        MEDIA_DEBUG_LOG("OnError is called!, errorCode: %{public}d", errorCode);
        CHECK_RETURN(videoOutput_ == nullptr || callback_.onError == nullptr);
    }

    void OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt info) const override
    {
        // empty impl
        MEDIA_DEBUG_LOG("OnDeferredVideoEnhancementInfo is called!");
    }

private:
    Camera_VideoOutput* videoOutput_;
    VideoOutput_Callbacks callback_;
};

Camera_VideoOutput::Camera_VideoOutput(sptr<VideoOutput> &innerVideoOutput) : innerVideoOutput_(innerVideoOutput)
{
    MEDIA_DEBUG_LOG("Camera_VideoOutput Constructor is called");
}

Camera_VideoOutput::~Camera_VideoOutput()
{
    MEDIA_DEBUG_LOG("~Camera_VideoOutput is called");
    innerVideoOutput_ = nullptr;
}

Camera_ErrorCode Camera_VideoOutput::RegisterCallback(VideoOutput_Callbacks* callback)
{
    shared_ptr<InnerVideoOutputCallback> innerCallback =
                make_shared<InnerVideoOutputCallback>(this, callback);
    innerVideoOutput_->SetCallback(innerCallback);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_VideoOutput::UnregisterCallback(VideoOutput_Callbacks* callback)
{
    innerVideoOutput_->SetCallback(nullptr);
    return CAMERA_OK;
}

Camera_ErrorCode Camera_VideoOutput::Start()
{
    int32_t ret = innerVideoOutput_->Start();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_VideoOutput::Stop()
{
    int32_t ret = innerVideoOutput_->Stop();
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_VideoOutput::Release()
{
    int32_t ret = innerVideoOutput_->Release();
    return FrameworkToNdkCameraError(ret);
}

sptr<VideoOutput> Camera_VideoOutput::GetInnerVideoOutput()
{
    return innerVideoOutput_;
}

Camera_ErrorCode Camera_VideoOutput::GetVideoProfile(Camera_VideoProfile** profile)
{
    auto videoOutputProfile = innerVideoOutput_->GetVideoProfile();
    CHECK_RETURN_RET_ELOG(videoOutputProfile == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_VideoOutput::GetVideoProfile failed to get video profile!");

    CameraFormat cameraFormat = videoOutputProfile->GetCameraFormat();
    auto itr = g_fwToNdkCameraFormat.find(cameraFormat);
    CHECK_RETURN_RET_ELOG(itr == g_fwToNdkCameraFormat.end(), CAMERA_SERVICE_FATAL_ERROR,
        "Camera_VideoOutput::GetVideoProfile unsupported camera format %{public}d", cameraFormat);

    auto frames = videoOutputProfile->GetFrameRates();
    CHECK_RETURN_RET_ELOG(frames.size() <= 1, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_VideoOutput::GetVideoProfile the current video profile is not configured correctly!");

    Camera_VideoProfile* newProfile = new Camera_VideoProfile;
    CHECK_RETURN_RET_ELOG(newProfile == nullptr, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_VideoOutput::GetVideoProfile failed to allocate memory for video profile!");

    newProfile->format = itr->second;
    newProfile->range.min = static_cast<uint32_t>(frames[0]);
    newProfile->range.max = static_cast<uint32_t>(frames[1]);
    newProfile->size.width = videoOutputProfile->GetSize().width;
    newProfile->size.height = videoOutputProfile->GetSize().height;

    *profile = newProfile;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_VideoOutput::GetSupportedFrameRates(Camera_FrameRateRange** frameRateRange, uint32_t* size)
{
    std::vector<std::vector<int32_t>> frameRate = innerVideoOutput_->GetSupportedFrameRates();
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

Camera_ErrorCode Camera_VideoOutput::DeleteFrameRates(Camera_FrameRateRange* frameRateRange)
{
    CHECK_RETURN_RET(frameRateRange == nullptr, CAMERA_OK);
    delete[] frameRateRange;
    frameRateRange = nullptr;
    return CAMERA_OK;
}

Camera_ErrorCode Camera_VideoOutput::SetFrameRate(int32_t minFps, int32_t maxFps)
{
    int32_t ret = innerVideoOutput_->SetFrameRate(minFps, maxFps);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_VideoOutput::GetActiveFrameRate(Camera_FrameRateRange* frameRateRange)
{
    std::vector<int32_t> activeFrameRate = innerVideoOutput_->GetFrameRateRange();
    CHECK_RETURN_RET_ELOG(activeFrameRate.size() <= 1, CAMERA_SERVICE_FATAL_ERROR, "invalid activeFrameRate size!");

    frameRateRange->min = static_cast<uint32_t>(activeFrameRate[0]);
    frameRateRange->max = static_cast<uint32_t>(activeFrameRate[1]);

    return CAMERA_OK;
}

Camera_ErrorCode Camera_VideoOutput::IsMirrorSupported(bool* isSupported)
{
    CHECK_RETURN_RET_ELOG(innerVideoOutput_ == nullptr, CAMERA_SERVICE_FATAL_ERROR, "innerVideoOutput_ is nullptr");
    CHECK_RETURN_RET_ELOG(isSupported == nullptr, CAMERA_SERVICE_FATAL_ERROR, "isSupported is nullptr");
    *isSupported = innerVideoOutput_->IsMirrorSupported();
    return CAMERA_OK;
}

Camera_ErrorCode Camera_VideoOutput::EnableMirror(bool mirrorMode)
{
    CHECK_RETURN_RET_ELOG(innerVideoOutput_ == nullptr, CAMERA_SERVICE_FATAL_ERROR, "innerVideoOutput_ is nullptr");
    int32_t ret = innerVideoOutput_->enableMirror(mirrorMode);
    return FrameworkToNdkCameraError(ret);
}

Camera_ErrorCode Camera_VideoOutput::GetVideoRotation(int32_t imageRotation, Camera_ImageRotation* cameraImageRotation)
{
    CHECK_RETURN_RET_ELOG(cameraImageRotation == nullptr, CAMERA_SERVICE_FATAL_ERROR, "GetCameraImageRotation failed");
    CHECK_RETURN_RET_ELOG(innerVideoOutput_ == nullptr, CAMERA_SERVICE_FATAL_ERROR, "innerVideoOutput_ is nullptr");
    int32_t cameraOutputRotation = innerVideoOutput_->GetVideoRotation(imageRotation);
    CHECK_RETURN_RET_ELOG(cameraOutputRotation == CAMERA_SERVICE_FATAL_ERROR, CAMERA_SERVICE_FATAL_ERROR,
        "Camera_VideoOutput::GetVideoRotation camera service fatal error! ret: %{public}d", cameraOutputRotation);
    *cameraImageRotation = static_cast<Camera_ImageRotation>(cameraOutputRotation);
    return CAMERA_OK;
}