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

#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "hstream_repeat_callback_stub.h"
#include "input/camera_device.h"
#include "input/camera_input.h"

namespace OHOS {
namespace CameraStandard {
VideoOutput::VideoOutput(sptr<IStreamRepeat>& streamRepeat)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_VIDEO, StreamType::REPEAT, streamRepeat)
{}

VideoOutput::~VideoOutput()
{
}

int32_t VideoOutputCallbackImpl::OnFrameStarted()
{
    CAMERA_SYNC_TRACE;
    auto item = videoOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnFrameStarted();
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnFrameStarted callback in video");
    }
    return CAMERA_OK;
}

int32_t VideoOutputCallbackImpl::OnFrameEnded(const int32_t frameCount)
{
    CAMERA_SYNC_TRACE;
    auto item = videoOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnFrameEnded(frameCount);
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnFrameEnded callback in video");
    }
    return CAMERA_OK;
}

int32_t VideoOutputCallbackImpl::OnFrameError(const int32_t errorCode)
{
    auto item = videoOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnError(errorCode);
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnFrameError callback in video");
    }
    return CAMERA_OK;
}

int32_t VideoOutputCallbackImpl::OnSketchStatusChanged(SketchStatus status)
{
    // Empty implement
    return CAMERA_OK;
}

void VideoOutput::SetCallback(std::shared_ptr<VideoStateCallback> callback)
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appCallback_ = callback;
    if (appCallback_ != nullptr) {
        if (svcCallback_ == nullptr) {
            svcCallback_ = new (std::nothrow) VideoOutputCallbackImpl(this);
            if (svcCallback_ == nullptr) {
                MEDIA_ERR_LOG("new VideoOutputCallbackImpl Failed to register callback");
                appCallback_ = nullptr;
                return;
            }
        }
        if (GetStream() == nullptr) {
            MEDIA_ERR_LOG("VideoOutput Failed to SetCallback!, GetStream is nullptr");
            return;
        }
        int32_t errorCode = CAMERA_OK;
        auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
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
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Start");
    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("VideoOutput Failed to Start!, session not config");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Start!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
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
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Stop");
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Stop!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
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
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Resume");
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Resume!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
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
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Pause");
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Pause!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
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
    {
        std::lock_guard<std::mutex> lock(outputCallbackMutex_);
        svcCallback_ = nullptr;
        appCallback_ = nullptr;
    }
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Release");
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("VideoOutput Failed to Release!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Release();
    } else {
        MEDIA_ERR_LOG("VideoOutput::Release() itemStream is nullptr");
    }
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to release VideoOutput!, errCode: %{public}d", errCode);
    }
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

std::shared_ptr<VideoStateCallback> VideoOutput::GetApplicationCallback()
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appCallback_;
}

const std::vector<int32_t>& VideoOutput::GetFrameRateRange()
{
    return videoFrameRateRange_;
}

void VideoOutput::SetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    MEDIA_DEBUG_LOG("VideoOutput::SetFrameRateRange min = %{public}d and max = %{public}d", minFrameRate, maxFrameRate);

    videoFrameRateRange_ = { minFrameRate, maxFrameRate };
}

void VideoOutput::SetOutputFormat(int32_t format)
{
    MEDIA_DEBUG_LOG("VideoOutput::SetOutputFormat set format %{public}d", format);
    videoFormat_ = format;
}

void VideoOutput::SetSize(Size size)
{
    videoSize_ = size;
}
 
int32_t VideoOutput::SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate)
{
    int32_t result = canSetFrameRateRange(minFrameRate, maxFrameRate);
    if (result != CameraErrorCode::SUCCESS) {
        return result;
    }

    if (minFrameRate == videoFrameRateRange_[0] && maxFrameRate == videoFrameRateRange_[1]) {
        MEDIA_WARNING_LOG("The frame rate does not need to be set.");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    if (itemStream) {
        int32_t ret = itemStream->SetFrameRate(minFrameRate, maxFrameRate);
        if (ret != CAMERA_OK) {
            MEDIA_ERR_LOG("VideoOutput::setFrameRate failed to set stream frame rate");
            return ServiceToCameraError(ret);
        }
        SetFrameRateRange(minFrameRate, maxFrameRate);
    }
    return CameraErrorCode::SUCCESS;
}

std::vector<std::vector<int32_t>> VideoOutput::GetSupportedFrameRates()
{
    MEDIA_DEBUG_LOG("VideoOutput::GetSupportedFrameRates called.");
    sptr<CameraDevice> camera = GetSession()->inputDevice_->GetCameraDeviceInfo();
    sptr<CameraOutputCapability> cameraOutputCapability =
                                 CameraManager::GetInstance()->GetSupportedOutputCapability(camera, SceneMode::VIDEO);
    std::vector<VideoProfile> supportedProfiles = cameraOutputCapability->GetVideoProfiles();
    supportedProfiles.erase(std::remove_if(
        supportedProfiles.begin(), supportedProfiles.end(),
        [&](Profile& profile) {
            return profile.format_ != videoFormat_ ||
                   profile.GetSize().height != videoSize_.height ||
                   profile.GetSize().width != videoSize_.width;
        }), supportedProfiles.end());
    std::vector<std::vector<int32_t>> supportedFrameRatesRange;
    for (auto item : supportedProfiles) {
        supportedFrameRatesRange.emplace_back(item.GetFrameRates());
    }
    std::set<std::vector<int>> set(supportedFrameRatesRange.begin(), supportedFrameRatesRange.end());
    supportedFrameRatesRange.assign(set.begin(), set.end());
    MEDIA_DEBUG_LOG("VideoOutput::GetSupportedFrameRates frameRateRange size:%{public}zu",
                    supportedFrameRatesRange.size());
    return supportedFrameRatesRange;
}

void VideoOutput::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    {
        std::lock_guard<std::mutex> lock(outputCallbackMutex_);
        if (appCallback_ != nullptr) {
            MEDIA_DEBUG_LOG("appCallback not nullptr");
            int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
            appCallback_->OnError(serviceErrorType);
        }
    }
    if (GetStream() != nullptr) {
        (void)GetStream()->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
    deathRecipient_ = nullptr;
}

int32_t VideoOutput::canSetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    auto session = GetSession();
        if (session == nullptr) {
            MEDIA_WARNING_LOG("Can not set frame rate range without commit session");
            return CameraErrorCode::SESSION_NOT_CONFIG;
        }
    if (!session->CanSetFrameRateRange(minFrameRate, maxFrameRate, this)) {
        MEDIA_WARNING_LOG("Can not set frame rate range with wrong state of output");
        return CameraErrorCode::UNRESOLVED_CONFLICTS_BETWEEN_STREAMS;
    }
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<std::vector<int32_t>> supportedFrameRange = GetSupportedFrameRates();
    for (auto item : supportedFrameRange) {
        if (item[minIndex] <= minFrameRate && item[maxIndex] >= maxFrameRate) {
            return CameraErrorCode::SUCCESS;
        }
    }
    MEDIA_WARNING_LOG("Can not set frame rate range with invalid parameters");
    return CameraErrorCode::INVALID_ARGUMENT;
}
} // namespace CameraStandard
} // namespace OHOS
