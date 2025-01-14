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

#include "preview_output_impl.h"
#include "camera_error.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "cj_lambda.h"
#include "image_receiver.h"
#include "surface_utils.h"

namespace OHOS {
namespace CameraStandard {

thread_local sptr<PreviewOutput> CJPreviewOutput::sPreviewOutput_ = nullptr;
void CJPreviewOutputCallback::OnFrameStarted() const
{
    std::lock_guard<std::mutex> lock(frameStartedMutex);
    if (frameStartedCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < frameStartedCallbackList.size(); i++) {
        frameStartedCallbackList[i]->ref();
    }
}

void CJPreviewOutputCallback::OnFrameEnded(const int32_t frameCount) const
{
    std::lock_guard<std::mutex> lock(frameEndedMutex);
    if (frameEndedCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < frameEndedCallbackList.size(); i++) {
        frameEndedCallbackList[i]->ref();
    }
}

void CJPreviewOutputCallback::OnError(const int32_t errorCode) const
{
    std::lock_guard<std::mutex> lock(errorMutex);
    if (errorCallbackList.size() == 0) {
        return;
    }
    for (size_t i = 0; i < errorCallbackList.size(); i++) {
        errorCallbackList[i]->ref(errorCode);
    }
}

void CJPreviewOutputCallback::OnSketchStatusDataChanged(const SketchStatusData &statusData) const
{
}

CJPreviewOutput::CJPreviewOutput()
{
    previewOutput_ = sPreviewOutput_;
    sPreviewOutput_ = nullptr;
}

sptr<CameraStandard::CaptureOutput> CJPreviewOutput::GetCameraOutput()
{
    return previewOutput_;
}

int32_t CJPreviewOutput::Release()
{
    if (previewOutput_ == nullptr) {
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    return previewOutput_->Release();
}

int32_t CJPreviewOutput::CreatePreviewOutput(Profile &profile, std::string &surfaceId)
{
    uint64_t iSurfaceId;
    std::istringstream iss(surfaceId);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (!surface) {
        surface = Media::ImageReceiver::getSurfaceById(surfaceId);
    }
    if (surface == nullptr) {
        MEDIA_ERR_LOG("Failed to get previewOutput surface");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    surface->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    int retCode = CameraManager::GetInstance()->CreatePreviewOutput(profile, surface, &sPreviewOutput_);
    if (sPreviewOutput_ == nullptr) {
        MEDIA_ERR_LOG("failed to create previewOutput");
        return CameraError::CAMERA_SERVICE_ERROR;
    }

    return retCode;
}

int32_t CJPreviewOutput::CreatePreviewOutputWithoutProfile(std::string &surfaceId)
{
    uint64_t iSurfaceId;
    std::istringstream iss(surfaceId);
    iss >> iSurfaceId;
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(iSurfaceId);
    if (!surface) {
        surface = Media::ImageReceiver::getSurfaceById(surfaceId);
    }
    if (surface == nullptr) {
        MEDIA_ERR_LOG("failed to get surface");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    int retCode = CameraManager::GetInstance()->CreatePreviewOutputWithoutProfile(surface, &sPreviewOutput_);
    if (sPreviewOutput_ == nullptr) {
        MEDIA_ERR_LOG("failed to create previewOutput");
        return CameraError::CAMERA_SERVICE_ERROR;
    }

    return retCode;
}

CArrFrameRateRange CJPreviewOutput::GetSupportedFrameRates(int32_t *errCode)
{
    MEDIA_INFO_LOG("GetSupportedFrameRates is called!");
    CArrFrameRateRange cArrFrameRateRange = CArrFrameRateRange{0};
    if (previewOutput_ == nullptr) {
        MEDIA_ERR_LOG("previewOutput_ is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return cArrFrameRateRange;
    }
    std::vector<std::vector<int32_t>> supportedFrameRatesRange = previewOutput_->GetSupportedFrameRates();
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
        cArrFrameRateRange.size = supportedFrameRatesRange.size();
    } else {
        MEDIA_INFO_LOG("supportedFrameRates is empty");
    }
    return cArrFrameRateRange;
}

int32_t CJPreviewOutput::SetFrameRate(int32_t min, int32_t max)
{
    MEDIA_INFO_LOG("SetFrameRate is called!");
    if (previewOutput_ == nullptr) {
        MEDIA_ERR_LOG("previewOutput is nullptr.");
        return CameraError::CAMERA_SERVICE_ERROR;
    }
    int32_t retCode = previewOutput_->SetFrameRate(min, max);
    if (retCode != 0) {
        MEDIA_ERR_LOG("SetFrameRate call Failed!");
    }
    return retCode;
}

FrameRateRange CJPreviewOutput::GetActiveFrameRate(int32_t *errCode)
{
    MEDIA_INFO_LOG("GetActiveFrameRate is called!");
    FrameRateRange frameRateRange = FrameRateRange{0};
    if (previewOutput_ == nullptr) {
        MEDIA_ERR_LOG("previewOutput is nullptr.");
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return frameRateRange;
    }
    std::vector<int32_t> fRateRange = previewOutput_->GetFrameRateRange();
    frameRateRange.min = fRateRange[0];
    frameRateRange.max = fRateRange[1];
    return frameRateRange;
}

CJProfile CJPreviewOutput::GetActiveProfile(int32_t *errCode)
{
    MEDIA_DEBUG_LOG("GetActiveProfile is called");
    auto profile = previewOutput_->GetPreviewProfile();
    if (profile == nullptr) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
        return CJProfile{0};
    }
    CJProfile cjProfile = CJProfile{
        .format = profile->GetCameraFormat(), .width = profile->GetSize().width, .height = profile->GetSize().height};
    return cjProfile;
}

int32_t CJPreviewOutput::GetPreviewRotation(int32_t value, int32_t *errCode)
{
    MEDIA_DEBUG_LOG("GetPreviewRotation is called!");
    int32_t res = previewOutput_->GetPreviewRotation(value);
    if (res == CameraError::CAMERA_SERVICE_ERROR) {
        *errCode = CameraError::CAMERA_SERVICE_ERROR;
    }
    return res;
}

int32_t CJPreviewOutput::SetPreviewRotation(int32_t imageRotation, bool isDisplayLocked)
{
    MEDIA_DEBUG_LOG("SetPreviewRotation is called!");
    int32_t errCode = previewOutput_->SetPreviewRotation(imageRotation, isDisplayLocked);
    if (errCode == CameraError::CAMERA_SERVICE_ERROR) {
        return errCode;
    }
    return CameraError::NO_ERROR;
}

void CJPreviewOutput::OnFrameStart(int64_t callbackId)
{
    if (previewCallback_ == nullptr) {
        previewCallback_ = std::make_shared<CJPreviewOutputCallback>();
        previewOutput_->SetCallback(previewCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)()>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)]() -> void { lambda(); };
    auto callbackRef = std::make_shared<CallbackRef<>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(previewCallback_->frameStartedMutex);
    previewCallback_->frameStartedCallbackList.push_back(callbackRef);
}

void CJPreviewOutput::OnFrameEnd(int64_t callbackId)
{
    if (previewCallback_ == nullptr) {
        previewCallback_ = std::make_shared<CJPreviewOutputCallback>();
        previewOutput_->SetCallback(previewCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)()>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)]() -> void { lambda(); };
    auto callbackRef = std::make_shared<CallbackRef<>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(previewCallback_->frameEndedMutex);
    previewCallback_->frameEndedCallbackList.push_back(callbackRef);
}

void CJPreviewOutput::OnError(int64_t callbackId)
{
    if (previewCallback_ == nullptr) {
        previewCallback_ = std::make_shared<CJPreviewOutputCallback>();
        previewOutput_->SetCallback(previewCallback_);
    }
    auto cFunc = reinterpret_cast<void (*)(const int32_t errorCode)>(callbackId);
    auto callback = [lambda = CJLambda::Create(cFunc)](const int32_t errorCode) -> void { lambda(errorCode); };
    auto callbackRef = std::make_shared<CallbackRef<const int32_t>>(callback, callbackId);

    std::lock_guard<std::mutex> lock(previewCallback_->errorMutex);
    previewCallback_->errorCallbackList.push_back(callbackRef);
}

void CJPreviewOutput::OffFrameStart(int64_t callbackId)
{
    if (previewCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(previewCallback_->frameStartedMutex);
    auto callbackList = previewCallback_->frameStartedCallbackList;
    for (auto it = callbackList.begin(); it != callbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            callbackList.erase(it);
            break;
        }
    }
}

void CJPreviewOutput::OffFrameEnd(int64_t callbackId)
{
    if (previewCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(previewCallback_->frameEndedMutex);
    auto callbackList = previewCallback_->frameEndedCallbackList;
    for (auto it = callbackList.begin(); it != callbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            callbackList.erase(it);
            break;
        }
    }
}

void CJPreviewOutput::OffError(int64_t callbackId)
{
    if (previewCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(previewCallback_->errorMutex);
    auto callbackList = previewCallback_->errorCallbackList;
    for (auto it = callbackList.begin(); it != callbackList.end(); it++) {
        if ((*it)->id == callbackId) {
            callbackList.erase(it);
            break;
        }
    }
}

void CJPreviewOutput::OffAllFrameStart()
{
    if (previewCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(previewCallback_->frameStartedMutex);
    previewCallback_->frameStartedCallbackList.clear();
}

void CJPreviewOutput::OffAllFrameEnd()
{
    if (previewCallback_ == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(previewCallback_->frameEndedMutex);
    previewCallback_->frameEndedCallbackList.clear();
}

void CJPreviewOutput::OffAllError()
{
    if (previewCallback_ == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> lock(previewCallback_->errorMutex);
    previewCallback_->errorCallbackList.clear();
}

} // namespace CameraStandard
} // namespace OHOS