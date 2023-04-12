/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "output/video_output.h"
#include "camera_util.h"
#include "hstream_repeat_callback_stub.h"
#include "input/camera_device.h"
#include "input/camera_input.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
VideoOutput::VideoOutput(sptr<IStreamRepeat> &streamRepeat)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_VIDEO, StreamType::REPEAT, streamRepeat) {
}

VideoOutput::~VideoOutput()
{
    svcCallback_ = nullptr;
    appCallback_ = nullptr;
}

class HStreamRepeatCallbackImpl : public HStreamRepeatCallbackStub {
public:
    VideoOutput* videoOutput_ = nullptr;
    HStreamRepeatCallbackImpl() : videoOutput_(nullptr) {
    }

    explicit HStreamRepeatCallbackImpl(VideoOutput* videoOutput) : videoOutput_(videoOutput) {
    }

    ~HStreamRepeatCallbackImpl()
    {
        videoOutput_ = nullptr;
    }

    int32_t OnFrameStarted() override
    {
        CAMERA_SYNC_TRACE;
        if (videoOutput_ != nullptr && videoOutput_->GetApplicationCallback() != nullptr) {
            videoOutput_->GetApplicationCallback()->OnFrameStarted();
        } else {
            MEDIA_INFO_LOG("Discarding HStreamRepeatCallbackImpl::OnFrameStarted callback in video");
        }
        return CAMERA_OK;
    }

    int32_t OnFrameEnded(const int32_t frameCount) override
    {
        CAMERA_SYNC_TRACE;
        if (videoOutput_ != nullptr && videoOutput_->GetApplicationCallback() != nullptr) {
            videoOutput_->GetApplicationCallback()->OnFrameEnded(frameCount);
        } else {
            MEDIA_INFO_LOG("Discarding HStreamRepeatCallbackImpl::OnFrameEnded callback in video");
        }
        return CAMERA_OK;
    }

    int32_t OnFrameError(const int32_t errorCode) override
    {
        if (videoOutput_ != nullptr && videoOutput_->GetApplicationCallback() != nullptr) {
            videoOutput_->GetApplicationCallback()->OnError(errorCode);
        } else {
            MEDIA_INFO_LOG("Discarding HStreamRepeatCallbackImpl::OnFrameError callback in video");
        }
        return CAMERA_OK;
    }
};

void VideoOutput::SetCallback(std::shared_ptr<VideoStateCallback> callback)
{
    appCallback_ = callback;
    if (appCallback_ != nullptr) {
        if (svcCallback_ == nullptr) {
            svcCallback_ = new(std::nothrow) HStreamRepeatCallbackImpl(this);
            if (svcCallback_ == nullptr) {
                MEDIA_ERR_LOG("VideoOutput::SetCallback: new HStreamRepeatCallbackImpl Failed to register callback");
                appCallback_ = nullptr;
                return;
            }
        }
        if (GetStream() == nullptr) {
            MEDIA_ERR_LOG("VideoOutput Failed to SetCallback!, GetStream is nullptr");
            return;
        }
        int32_t errorCode = CAMERA_OK;
        auto itemStream = static_cast<IStreamRepeat *>(GetStream().GetRefPtr());
        if (itemStream) {
            errorCode = itemStream->SetCallback(svcCallback_);
        } else {
            MEDIA_ERR_LOG("VideoOutput::SetCallback itemStream is nullptr");
        }

        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("VideoOutput::SetCallback: Failed to register callback, errorCode: %{public}d", errorCode);
            svcCallback_ = nullptr;
            appCallback_ = nullptr;
        }
    }
}

int32_t VideoOutput::Start()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    CaptureSession* captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("VideoOutput Failed to Start!, session not config");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Start!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat *>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Start();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("VideoOutput Failed to Start!, errCode: %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("VideoOutput::Start() itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t VideoOutput::Stop()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Stop!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat *>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Stop();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("VideoOutput Failed to Stop!, errCode: %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("VideoOutput::Stop() itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t VideoOutput::Resume()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Resume!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat *>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Start();
    } else {
        MEDIA_ERR_LOG("VideoOutput::Resume() itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t VideoOutput::Pause()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Pause!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat *>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Stop();
    } else {
        MEDIA_ERR_LOG("VideoOutput::Pause() itemStream is nullptr");
    }
    return errCode;
}

int32_t VideoOutput::Release()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Release!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat *>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Release();
    } else {
        MEDIA_ERR_LOG("VideoOutput::Release() itemStream is nullptr");
    }
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to release VideoOutput!, errCode: %{public}d", errCode);
    }
    svcCallback_ = nullptr;
    appCallback_ = nullptr;
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

std::shared_ptr<VideoStateCallback> VideoOutput::GetApplicationCallback()
{
    return appCallback_;
}

const std::vector<int32_t>& VideoOutput::GetFrameRateRange()
{
    return videoFrameRateRange_;
}

void VideoOutput::SetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    MEDIA_DEBUG_LOG("VideoOutput::SetFrameRateRange min = %{public}d and max = %{public}d",
        minFrameRate, maxFrameRate);

    videoFrameRateRange_ = {minFrameRate, maxFrameRate};
}
} // CameraStandard
} // OHOS
