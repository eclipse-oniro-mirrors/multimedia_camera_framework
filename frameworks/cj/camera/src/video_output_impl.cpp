/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdlib>
#include <iomanip>
#include <map>
#include <string>
#include <variant>
#include <vector>
#include "ffi_remote_data.h"
#include "securec.h"

#include "camera_error.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "surface_utils.h"
#include "video_output_impl.h"

using namespace OHOS::FFI;

namespace OHOS::CameraStandard {
thread_local sptr<VideoOutput> CJVideoOutput::sVideoOutput_ = nullptr;

void CJVideoCallbackListener::OnFrameStarted() const
{
    std::lock_guard<std::mutex> lock(frameStartedMutex);
    if (frameStartedCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < frameStartedCallbackList.size(); i++) {
        frameStartedCallbackList[i]->ref();
    }
}

void CJVideoCallbackListener::OnFrameEnded(const int32_t frameCount) const
{
    std::lock_guard<std::mutex> lock(frameEndedMutex);
    if (frameEndedCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < frameEndedCallbackList.size(); i++) {
        frameEndedCallbackList[i]->ref();
    }
}

void CJVideoCallbackListener::OnError(const int32_t errorCode) const
{
    std::lock_guard<std::mutex> lock(errorMutex);
    if (errorCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < errorCallbackList.size(); i++) {
        errorCallbackList[i]->ref(errorCode);
    }
}

void CJVideoCallbackListener::OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt info) const
{
}

CJVideoOutput::CJVideoOutput()
{
    videoOutput_ = sVideoOutput_;
    sVideoOutput_ = nullptr;
}

sptr<CameraStandard::CaptureOutput> CJVideoOutput::GetCameraOutput()
{
    return videoOutput_;
}

int32_t CJVideoOutput::Release()
{
    if (videoOutput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return videoOutput_->Release();
}

int32_t CJVideoOutput::CreateVideoOutput(VideoProfile &profile, std::string surfaceId)
{
    uint64_t iSurfaceId;
    std::istringstream iss(surfaceId);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (surface == nullptr) {
        MEDIA_ERR_LOG("failed to get surface from SurfaceUtils");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    int retCode = CameraManager::GetInstance()->CreateVideoOutput(profile, surface, &sVideoOutput_);
    if (sVideoOutput_ == nullptr) {
        MEDIA_ERR_LOG("failed to create VideoOutput");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return retCode;
}

int32_t CJVideoOutput::CreateVideoOutputWithOutProfile(std::string surfaceId)
{
    uint64_t iSurfaceId;
    std::istringstream iss(surfaceId);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (surface == nullptr) {
        MEDIA_ERR_LOG("failed to get surface from SurfaceUtils");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    int retCode = CameraManager::GetInstance()->CreateVideoOutputWithoutProfile(surface, &sVideoOutput_);
    if (sVideoOutput_ == nullptr) {
        MEDIA_ERR_LOG("failed to create VideoOutput");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return retCode;
}

int32_t CJVideoOutput::Start()
{
    if (videoOutput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return videoOutput_->Start();
}

int32_t CJVideoOutput::Stop()
{
    if (videoOutput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return videoOutput_->Stop();
}

CArrFrameRateRange CJVideoOutput::GetSupportedFrameRates(int32_t *errCode)
{
    MEDIA_INFO_LOG("GetSupportedFrameRates is called!");
    CArrFrameRateRange cArrFrameRateRange = CArrFrameRateRange{0};
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("videoOutput is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return cArrFrameRateRange;
    }
    std::vector<std::vector<int32_t>> supportedFrameRatesRange = videoOutput_->GetSupportedFrameRates();
    MEDIA_INFO_LOG("CJVideoOutput::GetSupportedFrameRates len = %{public}zu", supportedFrameRatesRange.size());
    if (supportedFrameRatesRange.size() > 0) {
        FrameRateRange *retArrFrameRateRange =
            (FrameRateRange *)malloc(sizeof(FrameRateRange) * supportedFrameRatesRange.size());
        if (retArrFrameRateRange == nullptr) {
            *errCode = CameraError::CAMERA_SERVICE_ERROR;
            return cArrFrameRateRange;
        }
        for (size_t i = 0; i < supportedFrameRatesRange.size(); i++) {
            retArrFrameRateRange[i].min = supportedFrameRatesRange[i][0];
            retArrFrameRateRange[i].max = supportedFrameRatesRange[i][1];
        }
        cArrFrameRateRange.head = retArrFrameRateRange;
        cArrFrameRateRange.size = static_cast<int64_t>(supportedFrameRatesRange.size());
    } else {
        MEDIA_ERR_LOG("cArrFrameRateRange is empty!");
    }
    return cArrFrameRateRange;
}

int32_t CJVideoOutput::SetFrameRate(int32_t minFps, int32_t maxFps)
{
    MEDIA_INFO_LOG("SetFrameRate is called");
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("videoOutput is nullptr.");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return videoOutput_->SetFrameRate(minFps, maxFps);
}

FrameRateRange CJVideoOutput::GetActiveFrameRate(int32_t *errCode)
{
    MEDIA_INFO_LOG("GetActiveFrameRate is called");
    FrameRateRange frameRateRange = FrameRateRange{0};
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("videoOutput is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return frameRateRange;
    }
    std::vector<int32_t> fRateRange = videoOutput_->GetFrameRateRange();
    frameRateRange.min = fRateRange[0];
    frameRateRange.max = fRateRange[1];
    return frameRateRange;
}

CJVideoProfile CJVideoOutput::GetActiveProfile(int32_t *errCode)
{
    MEDIA_DEBUG_LOG("VideoOutputNapi::GetActiveProfile is called");
    CJVideoProfile cjVideoProfile = CJVideoProfile{0};
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("videoOutput is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return cjVideoProfile;
    }
    auto profile = videoOutput_->GetVideoProfile();
    if (profile == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return cjVideoProfile;
    }
    cjVideoProfile.format = profile->GetCameraFormat();
    Size size = profile->GetSize();
    cjVideoProfile.width = size.width;
    cjVideoProfile.height = size.height;
    std::vector<int32_t> vpi_framerates = profile->GetFrameRates();
    cjVideoProfile.frameRateRange.min = vpi_framerates[0];
    cjVideoProfile.frameRateRange.max = vpi_framerates[1];
    return cjVideoProfile;
}

int32_t CJVideoOutput::GetVideoRotation(int32_t imageRotation, int32_t *errCode)
{
    MEDIA_DEBUG_LOG("GetVideoRotation is called!");
    if (videoOutput_ == nullptr) {
        MEDIA_ERR_LOG("videoOutput is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    int32_t retCode = videoOutput_->GetVideoRotation(imageRotation);
    if (retCode == CameraError::CAMERA_SERVICE_ERROR) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return -1;
    }
    return retCode;
}

void CJVideoOutput::OnFrameStart(int64_t callbackId)
{
    if (videoCallback_ == nullptr) {
        videoCallback_ = std::make_shared<CJVideoCallbackListener>();
        videoOutput_->SetCallback(videoCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)()>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)]() -> void { lambda(); };
    auto callbackRef = std::make_shared<CallbackRef<>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(videoCallback_->frameStartedMutex);
    videoCallback_->frameStartedCallbackList.push_back(callbackRef);
}

void CJVideoOutput::OffFrameStart(int64_t callbackId)
{
    if (videoCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(videoCallback_->frameStartedMutex);
    auto callbackList = videoCallback_->frameStartedCallbackList;
    for (auto it = callbackList.begin(); it != callbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            callbackList.erase(it);
            break;
        }
    }
}

void CJVideoOutput::OffAllFrameStart()
{
    if (videoCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(videoCallback_->frameStartedMutex);
    videoCallback_->frameStartedCallbackList.clear();
}

void CJVideoOutput::OnFrameEnd(int64_t callbackId)
{
    if (videoCallback_ == nullptr) {
        videoCallback_ = std::make_shared<CJVideoCallbackListener>();
        videoOutput_->SetCallback(videoCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)()>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)]() -> void { lambda(); };
    auto callbackRef = std::make_shared<CallbackRef<>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(videoCallback_->frameEndedMutex);
    videoCallback_->frameEndedCallbackList.push_back(callbackRef);
}

void CJVideoOutput::OffFrameEnd(int64_t callbackId)
{
    if (videoCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(videoCallback_->frameEndedMutex);
    auto callbackList = videoCallback_->frameEndedCallbackList;
    for (auto it = callbackList.begin(); it != callbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            callbackList.erase(it);
            break;
        }
    }
}

void CJVideoOutput::OffAllFrameEnd()
{
    if (videoCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(videoCallback_->frameEndedMutex);
    videoCallback_->frameEndedCallbackList.clear();
}

void CJVideoOutput::OnError(int64_t callbackId)
{
    if (videoCallback_ == nullptr) {
        videoCallback_ = std::make_shared<CJVideoCallbackListener>();
        videoOutput_->SetCallback(videoCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(const int32_t errorCode)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t errorCode) -> void { lambda(errorCode); };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(videoCallback_->errorMutex);
    videoCallback_->errorCallbackList.push_back(callbackRef);
}

void CJVideoOutput::OffError(int64_t callbackId)
{
    if (videoCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(videoCallback_->errorMutex);
    auto callbackList = videoCallback_->errorCallbackList;
    for (auto it = callbackList.begin(); it != callbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            callbackList.erase(it);
            break;
        }
    }
}

void CJVideoOutput::OffAllError()
{
    if (videoCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(videoCallback_->errorMutex);
    videoCallback_->errorCallbackList.clear();
}

} // namespace OHOS::CameraStandard