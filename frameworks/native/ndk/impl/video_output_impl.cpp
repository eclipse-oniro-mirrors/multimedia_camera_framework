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

class InnerVideoOutputCallback : public VideoStateCallback {
public:
    InnerVideoOutputCallback(Camera_VideoOutput* videoOutput, VideoOutput_Callbacks* callback)
        : videoOutput_(videoOutput), callback_(*callback) {}
    ~InnerVideoOutputCallback() = default;

    void OnFrameStarted() const override
    {
        MEDIA_DEBUG_LOG("OnFrameStarted is called!");
        if (videoOutput_ != nullptr && callback_.onFrameStart != nullptr) {
            callback_.onFrameStart(videoOutput_);
        }
    }

    void OnFrameEnded(const int32_t frameCount) const override
    {
        MEDIA_DEBUG_LOG("OnFrameEnded is called! frame count: %{public}d", frameCount);
        if (videoOutput_ != nullptr && callback_.onFrameEnd != nullptr) {
            callback_.onFrameEnd(videoOutput_, frameCount);
        }
    }

    void OnError(const int32_t errorCode) const override
    {
        MEDIA_DEBUG_LOG("OnError is called!, errorCode: %{public}d", errorCode);
        if (videoOutput_ != nullptr && callback_.onError != nullptr) {
            callback_.onError(videoOutput_, FrameworkToNdkCameraError(errorCode));
        }
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
    if (innerVideoOutput_) {
        innerVideoOutput_ = nullptr;
    }
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