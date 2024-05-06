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

#include "output/preview_output.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <utility>
#include <variant>

#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_metadata_operator.h"
#include "camera_output_capability.h"
#include "camera_util.h"
#include "hstream_repeat_callback_stub.h"
#include "image_format.h"
#include "metadata_common_utils.h"
#include "pixel_map.h"
#include "session/capture_session.h"
#include "sketch_wrapper.h"

namespace OHOS {
namespace CameraStandard {
namespace {
camera_format_t GetHdiFormatFromCameraFormat(CameraFormat cameraFormat)
{
    switch (cameraFormat) {
        case CAMERA_FORMAT_YCBCR_420_888:
            return OHOS_CAMERA_FORMAT_YCBCR_420_888;
        case CAMERA_FORMAT_YUV_420_SP:
            return OHOS_CAMERA_FORMAT_YCRCB_420_SP;
        case CAMERA_FORMAT_YCBCR_P010:
            return OHOS_CAMERA_FORMAT_YCBCR_P010;
        case CAMERA_FORMAT_YCRCB_P010:
            return OHOS_CAMERA_FORMAT_YCRCB_P010;
        case CAMERA_FORMAT_NV12:
            return OHOS_CAMERA_FORMAT_YCBCR_420_SP;
        case CAMERA_FORMAT_YUV_422_YUYV:
            return OHOS_CAMERA_FORMAT_422_YUYV;
        default:
            return OHOS_CAMERA_FORMAT_IMPLEMENTATION_DEFINED;
    }
    return OHOS_CAMERA_FORMAT_IMPLEMENTATION_DEFINED;
}
} // namespace
static constexpr int32_t SKETCH_MIN_WIDTH = 480;
PreviewOutput::PreviewOutput(sptr<IStreamRepeat>& streamRepeat)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_PREVIEW, StreamType::REPEAT, streamRepeat)
{}

PreviewOutput::~PreviewOutput()
{
}

int32_t PreviewOutput::Release()
{
    {
        std::lock_guard<std::mutex> lock(outputCallbackMutex_);
        svcCallback_ = nullptr;
        appCallback_ = nullptr;
    }
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::Release");
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("PreviewOutput Failed to Release!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Release();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("Failed to release PreviewOutput!, errCode: %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("PreviewOutput::Release() itemStream is nullptr");
    }
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

int32_t PreviewOutputCallbackImpl::OnFrameStarted()
{
    CAMERA_SYNC_TRACE;
    auto item = previewOutput_.promote();
    if (item != nullptr) {
        auto callback = item->GetApplicationCallback();
        if (callback != nullptr) {
            callback->OnFrameStarted();
        } else {
            MEDIA_INFO_LOG("Discarding PreviewOutputCallbackImpl::OnFrameStarted callback in preview");
        }
    } else {
        MEDIA_INFO_LOG("PreviewOutputCallbackImpl::OnFrameStarted PreviewOutput is nullptr");
    }
    return CAMERA_OK;
}

int32_t PreviewOutputCallbackImpl::OnFrameEnded(int32_t frameCount)
{
    CAMERA_SYNC_TRACE;
    auto item = previewOutput_.promote();
    if (item != nullptr) {
        auto callback = item->GetApplicationCallback();
        if (callback != nullptr) {
            callback->OnFrameEnded(frameCount);
        } else {
            MEDIA_INFO_LOG("Discarding PreviewOutputCallbackImpl::OnFrameEnded callback in preview");
        }
    } else {
        MEDIA_INFO_LOG("PreviewOutputCallbackImpl::OnFrameEnded PreviewOutput is nullptr");
    }
    return CAMERA_OK;
}

int32_t PreviewOutputCallbackImpl::OnFrameError(int32_t errorCode)
{
    CAMERA_SYNC_TRACE;
    auto item = previewOutput_.promote();
    if (item != nullptr) {
        auto callback = item->GetApplicationCallback();
        if (callback != nullptr) {
            callback->OnError(errorCode);
        } else {
            MEDIA_INFO_LOG("Discarding PreviewOutputCallbackImpl::OnFrameError callback in preview");
        }
    } else {
        MEDIA_INFO_LOG("PreviewOutputCallbackImpl::OnFrameError PreviewOutput is nullptr");
    }
    return CAMERA_OK;
}

int32_t PreviewOutputCallbackImpl::OnSketchStatusChanged(SketchStatus status)
{
    if (previewOutput_ != nullptr) {
        previewOutput_->OnSketchStatusChanged(status);
    } else {
        MEDIA_INFO_LOG("Discarding PreviewOutputCallbackImpl::OnFrameError callback in preview");
    }
    return CAMERA_OK;
}

int32_t PreviewOutput::OnSketchStatusChanged(SketchStatus status)
{
    if (sketchWrapper_ == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    auto session = GetSession();
    if (session == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    SketchWrapper* wrapper = static_cast<SketchWrapper*>(sketchWrapper_.get());
    wrapper->OnSketchStatusChanged(status, session->GetFeaturesMode());
    return CAMERA_OK;
}

void PreviewOutput::AddDeferredSurface(sptr<Surface> surface)
{
    MEDIA_INFO_LOG("PreviewOutput::AddDeferredSurface called");
    if (surface == nullptr) {
        MEDIA_ERR_LOG("PreviewOutput::AddDeferredSurface surface is null");
        return;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    if (!itemStream) {
        MEDIA_ERR_LOG("PreviewOutput::AddDeferredSurface itemStream is nullptr");
        return;
    }
    itemStream->AddDeferredSurface(surface->GetProducer());
}

int32_t PreviewOutput::Start()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::Start");
    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("PreviewOutput Failed to Start!, session not config");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("PreviewOutput Failed to Start!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Start();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("PreviewOutput Failed to Start!, errCode: %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("PreviewOutput::Start itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t PreviewOutput::Stop()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::Stop");
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("PreviewOutput Failed to Stop!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Stop();
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("PreviewOutput Failed to Stop!, errCode: %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("PreviewOutput::Stop itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
}

bool PreviewOutput::IsSketchSupported()
{
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::IsSketchSupported");

    auto sketchSize = FindSketchSize();
    if (sketchSize == nullptr) {
        return false;
    }
    MEDIA_INFO_LOG(
        "IsSketchSupported FindSketchSize Size is %{public}dx%{public}d", sketchSize->width, sketchSize->height);
    auto sketchRatio = GetSketchRatio();
    if (sketchRatio > 0) {
        return true;
    }
    MEDIA_DEBUG_LOG("IsSketchSupported GetSketchRatio failed, %{public}f ", sketchRatio);
    auto session = GetSession();
    if (session == nullptr) {
        return false;
    }
    SketchWrapper::UpdateSketchStaticInfo(GetDeviceMetadata());
    auto subModeNames = session->GetSubFeatureMods();
    for (auto subModeName : subModeNames) {
        float ratio = SketchWrapper::GetSketchEnableRatio(subModeName);
        if (ratio > 0) {
            MEDIA_DEBUG_LOG("IsSketchSupported GetSketchEnableRatio success,subMode:%{public}s, ratio:%{public}f ",
                subModeName.Dump().c_str(), ratio);
            return true;
        }
    }
    return false;
}

float PreviewOutput::GetSketchRatio()
{
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::GetSketchRatio");

    auto session = GetSession();
    if (session == nullptr) {
        MEDIA_WARNING_LOG("PreviewOutput::GetSketchRatio session is null");
        return -1.0f;
    }
    auto currentMode = session->GetFeaturesMode();
    SketchWrapper::UpdateSketchStaticInfo(GetDeviceMetadata());
    float ratio = SketchWrapper::GetSketchEnableRatio(currentMode);
    if (ratio <= 0) {
        MEDIA_WARNING_LOG("PreviewOutput::GetSketchRatio mode:%{public}s", currentMode.Dump().c_str());
    }
    return ratio;
}

int32_t PreviewOutput::CreateSketchWrapper(Size sketchSize)
{
    MEDIA_DEBUG_LOG("PreviewOutput::CreateSketchWrapper enter sketchSize is:%{public}d x %{public}d", sketchSize.width,
        sketchSize.height);
    auto session = GetSession();
    if (session == nullptr) {
        MEDIA_ERR_LOG("EnableSketch session null");
        return ServiceToCameraError(CAMERA_INVALID_STATE);
    }
    auto wrapper = std::make_shared<SketchWrapper>(GetStream(), sketchSize);
    if (wrapper == nullptr) {
        return ServiceToCameraError(CAMERA_ALLOC_ERROR);
    }
    sketchWrapper_ = wrapper;
    auto metadata = GetDeviceMetadata();
    int32_t retCode = wrapper->Init(metadata, session->GetFeaturesMode());
    wrapper->SetPreviewStateCallback(appCallback_);
    return ServiceToCameraError(retCode);
}

int32_t PreviewOutput::EnableSketch(bool isEnable)
{
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::EnableSketch %{public}d", isEnable);
    if (!IsSketchSupported()) {
        MEDIA_ERR_LOG("EnableSketch IsSketchSupported is false");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    std::lock_guard<std::mutex> lock(asyncOpMutex_);

    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionConfiged()) {
        MEDIA_ERR_LOG("PreviewOutput Failed EnableSketch!, session not config");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    if (isEnable) {
        if (sketchWrapper_ != nullptr) {
            return ServiceToCameraError(CAMERA_OPERATION_NOT_ALLOWED);
        }
        auto sketchSize = FindSketchSize();
        if (sketchSize == nullptr) {
            MEDIA_ERR_LOG("EnableSketch FindSketchSize is null");
            return ServiceToCameraError(errCode);
        }
        MEDIA_INFO_LOG(
            "EnableSketch FindSketchSize Size is %{public}dx%{public}d", sketchSize->width, sketchSize->height);
        return CreateSketchWrapper(*sketchSize);
    }

    // Disable sketch branch
    if (sketchWrapper_ == nullptr) {
        return ServiceToCameraError(CAMERA_OPERATION_NOT_ALLOWED);
    }
    errCode = sketchWrapper_->Destroy();
    sketchWrapper_ = nullptr;
    return ServiceToCameraError(errCode);
}

int32_t PreviewOutput::AttachSketchSurface(sptr<Surface> sketchSurface)
{
    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("PreviewOutput AttachSketchSurface!, session not commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (sketchWrapper_ == nullptr) {
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    if (sketchSurface == nullptr) {
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    int32_t errCode = sketchWrapper_->AttachSketchSurface(sketchSurface);
    return ServiceToCameraError(errCode);
}

const std::vector<int32_t>& PreviewOutput::GetFrameRateRange()
{
    return previewFrameRateRange_;
}

void PreviewOutput::SetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    MEDIA_DEBUG_LOG("PreviewOutput::SetFrameRateRange min = %{public}d and max = %{public}d",
                    minFrameRate, maxFrameRate);
    previewFrameRateRange_ = { minFrameRate, maxFrameRate };
}

void PreviewOutput::SetOutputFormat(int32_t format)
{
    MEDIA_DEBUG_LOG("PreviewOutput::SetOutputFormat set format %{public}d", format);
    PreviewFormat_ = format;
}

void PreviewOutput::SetSize(Size size)
{
    MEDIA_DEBUG_LOG("PreviewOutput::SetSize set size %{public}d, %{public}d", size.width, size.height);
    PreviewSize_ = size;
}

int32_t PreviewOutput::SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate)
{
    int32_t result = canSetFrameRateRange(minFrameRate, maxFrameRate);
    if (result != CameraErrorCode::SUCCESS) {
        return result;
    }
    if (minFrameRate == previewFrameRateRange_[0] && maxFrameRate == previewFrameRateRange_[1]) {
        MEDIA_WARNING_LOG("The frame rate does not need to be set.");
        return CameraErrorCode::INVALID_ARGUMENT;
    }
    std::vector<int32_t> frameRateRange = {minFrameRate, maxFrameRate};
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    if (itemStream) {
        int32_t ret = itemStream->SetFrameRate(minFrameRate, maxFrameRate);
        if (ret != CAMERA_OK) {
            MEDIA_ERR_LOG("PreviewOutput::setFrameRate failed to set stream frame rate");
            return ServiceToCameraError(ret);
        }
        SetFrameRateRange(minFrameRate, maxFrameRate);
    }
    return CameraErrorCode::SUCCESS;
}

std::vector<std::vector<int32_t>> PreviewOutput::GetSupportedFrameRates()
{
    MEDIA_DEBUG_LOG("PreviewOutput::GetSupportedFrameRates called.");
    sptr<CameraDevice> camera = GetSession()->inputDevice_->GetCameraDeviceInfo();
 
    sptr<CameraOutputCapability> cameraOutputCapability = CameraManager::GetInstance()->
                                                          GetSupportedOutputCapability(camera, SceneMode::VIDEO);
    std::vector<Profile> supportedProfiles = cameraOutputCapability->GetPreviewProfiles();
    supportedProfiles.erase(std::remove_if(
        supportedProfiles.begin(), supportedProfiles.end(),
        [&](Profile& profile) {
            return profile.format_ != PreviewFormat_ ||
                   profile.GetSize().height != PreviewSize_.height ||
                   profile.GetSize().width != PreviewSize_.width;
        }), supportedProfiles.end());
    std::vector<std::vector<int32_t>> supportedFrameRatesRange;
    for (auto item : supportedProfiles) {
        std::vector<int32_t> supportedFrameRatesItem = {item.fps_.minFps, item.fps_.maxFps};
        supportedFrameRatesRange.emplace_back(supportedFrameRatesItem);
    }
    std::set<std::vector<int>> set(supportedFrameRatesRange.begin(), supportedFrameRatesRange.end());
    supportedFrameRatesRange.assign(set.begin(), set.end());
    MEDIA_DEBUG_LOG("PreviewOutput::GetSupportedFrameRates frameRateRange size:%{public}zu",
                    supportedFrameRatesRange.size());
    return supportedFrameRatesRange;
}

int32_t PreviewOutput::StartSketch()
{
    int32_t errCode = CAMERA_UNKNOWN_ERROR;

    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("PreviewOutput Failed StartSketch!, session not commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (sketchWrapper_ != nullptr) {
        errCode = sketchWrapper_->StartSketchStream();
    }
    return ServiceToCameraError(errCode);
}

int32_t PreviewOutput::StopSketch()
{
    int32_t errCode = CAMERA_UNKNOWN_ERROR;

    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("PreviewOutput Failed StopSketch!, session not commited");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }

    if (sketchWrapper_ != nullptr) {
        errCode = sketchWrapper_->StopSketchStream();
    }
    return ServiceToCameraError(errCode);
}

std::shared_ptr<Camera::CameraMetadata> PreviewOutput::GetDeviceMetadata()
{
    auto session = GetSession();
    if (session == nullptr) {
        MEDIA_WARNING_LOG("PreviewOutput::GetDeviceMetadata session is null");
        return nullptr;
    }
    auto inputDevice = session->inputDevice_;
    if (inputDevice == nullptr) {
        MEDIA_WARNING_LOG("PreviewOutput::GetDeviceMetadata inputDevice is null");
        return nullptr;
    }
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    if (deviceInfo == nullptr) {
        MEDIA_WARNING_LOG("PreviewOutput::GetDeviceMetadata deviceInfo is null");
        return nullptr;
    }
    auto metaData = deviceInfo->GetMetadata();
    if (metaData == nullptr) {
        MEDIA_WARNING_LOG("PreviewOutput::GetDeviceMetadata metaData is null");
        return nullptr;
    }
    return metaData;
}

std::shared_ptr<Size> PreviewOutput::FindSketchSize()
{
    auto session = GetSession();
    auto metaData = GetDeviceMetadata();
    if (session == nullptr || metaData == nullptr) {
        MEDIA_ERR_LOG("PreviewOutput::FindSketchSize GetDeviceMetadata is fail");
        return nullptr;
    }
    Profile profile = GetPreviewProfile();
    CameraFormat cameraFormat = profile.GetCameraFormat();
    camera_format_t hdi_format = GetHdiFormatFromCameraFormat(cameraFormat);
    if (hdi_format == OHOS_CAMERA_FORMAT_IMPLEMENTATION_DEFINED) {
        MEDIA_ERR_LOG("PreviewOutput::FindSketchSize preview format is illegal");
        return nullptr;
    }
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(
        session->GetFeaturesMode().GetSceneMode(), hdi_format, metaData);
    if (sizeList == nullptr || sizeList->size() == 0) {
        return nullptr;
    }
    Size previewSize = profile.GetSize();
    if (previewSize.width <= 0 || previewSize.height <= 0) {
        return nullptr;
    }
    float ratio = static_cast<float>(previewSize.width) / previewSize.height;
    MEDIA_INFO_LOG("PreviewOutput::FindSketchSize preview size:%{public}dx%{public}d,ratio:%{public}f",
        previewSize.width, previewSize.height, ratio);
    std::shared_ptr<Size> outSize;
    for (auto size : *sizeList.get()) {
        if (size.width >= previewSize.width || size.width < SKETCH_MIN_WIDTH) {
            continue;
        }
        float checkRatio = static_cast<float>(size.width) / size.height;
        MEDIA_DEBUG_LOG("PreviewOutput::FindSketchSize List size:%{public}dx%{public}d,ratio:%{public}f", size.width,
            size.height, checkRatio);
        if (abs(checkRatio - ratio) / ratio <= 0.05f) { // 0.05f is 5% tolerance
            if (outSize == nullptr) {
                outSize = std::make_shared<Size>(size);
            } else if (size.width < outSize->width) {
                outSize = std::make_shared<Size>(size);
            }
        }
    }
    return outSize;
}

void PreviewOutput::SetCallback(std::shared_ptr<PreviewStateCallback> callback)
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appCallback_ = callback;
    if (appCallback_ != nullptr) {
        if (svcCallback_ == nullptr) {
            svcCallback_ = new (std::nothrow) PreviewOutputCallbackImpl(this);
            if (svcCallback_ == nullptr) {
                MEDIA_ERR_LOG("new PreviewOutputCallbackImpl Failed to register callback");
                appCallback_ = nullptr;
                return;
            }
        }
        if (GetStream() == nullptr) {
            MEDIA_ERR_LOG("PreviewOutput Failed to SetCallback!, GetStream is nullptr");
            return;
        }
        auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
        int32_t errorCode = CAMERA_OK;
        if (itemStream) {
            errorCode = itemStream->SetCallback(svcCallback_);
        } else {
            MEDIA_ERR_LOG("PreviewOutput::SetCallback itemStream is nullptr");
        }
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("PreviewOutput::SetCallback: Failed to register callback, errorCode: %{public}d", errorCode);
            svcCallback_ = nullptr;
            appCallback_ = nullptr;
        }
    }
    if (sketchWrapper_ != nullptr) {
        SketchWrapper* wrapper = static_cast<SketchWrapper*>(sketchWrapper_.get());
        wrapper->SetPreviewStateCallback(appCallback_);
    }
    return;
}

const std::set<camera_device_metadata_tag_t>& PreviewOutput::GetObserverControlTags()
{
    const static std::set<camera_device_metadata_tag_t> tags = { OHOS_CONTROL_ZOOM_RATIO, OHOS_CONTROL_CAMERA_MACRO,
        OHOS_CONTROL_MOON_CAPTURE_BOOST, OHOS_CONTROL_SMOOTH_ZOOM_RATIOS };
    return tags;
}

int32_t PreviewOutput::OnControlMetadataChanged(
    const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    // Don't trust outer public interface passthrough data. Check the legitimacy of the data.
    if (metadataItem.count <= 0) {
        return CAM_META_INVALID_PARAM;
    }
    if (sketchWrapper_ == nullptr) {
        return CAM_META_FAILURE;
    }
    auto session = GetSession();
    if (session == nullptr) {
        return CAM_META_FAILURE;
    }
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    SketchWrapper* wrapper = reinterpret_cast<SketchWrapper*>(sketchWrapper_.get());
    wrapper->OnMetadataDispatch(session->GetFeaturesMode(), tag, metadataItem);
    return CAM_META_SUCCESS;
}

int32_t PreviewOutput::OnResultMetadataChanged(
    const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    // Don't trust outer public interface passthrough data. Check the legitimacy of the data.
    if (metadataItem.count <= 0) {
        return CAM_META_INVALID_PARAM;
    }
    if (sketchWrapper_ == nullptr) {
        return CAM_META_FAILURE;
    }
    auto session = GetSession();
    if (session == nullptr) {
        return CAM_META_FAILURE;
    }
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    SketchWrapper* wrapper = reinterpret_cast<SketchWrapper*>(sketchWrapper_.get());
    wrapper->OnMetadataDispatch(session->GetFeaturesMode(), tag, metadataItem);
    return CAM_META_SUCCESS;
}

std::shared_ptr<PreviewStateCallback> PreviewOutput::GetApplicationCallback()
{
    std::lock_guard<std::mutex>lock(outputCallbackMutex_);
    return appCallback_;
}

void PreviewOutput::OnNativeRegisterCallback(const std::string& eventString)
{
    if (eventString == CONST_SKETCH_STATUS_CHANGED) {
        std::lock_guard<std::mutex> lock(asyncOpMutex_);
        if (sketchWrapper_ == nullptr) {
            return;
        }
        auto session = GetSession();
        if (session == nullptr) {
            return;
        }
        if (!session->IsSessionCommited()) {
            return;
        }
        auto metadata = GetDeviceMetadata();
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
        if (ret != CAM_META_SUCCESS || item.count <= 0) {
            return;
        }
        float tagRatio = *item.data.f;
        if (tagRatio <= 0) {
            return;
        }
        float sketchRatio = sketchWrapper_->GetSketchEnableRatio(session->GetFeaturesMode());
        MEDIA_DEBUG_LOG("PreviewOutput::OnNativeRegisterCallback OHOS_CONTROL_ZOOM_RATIO >>> tagRatio:%{public}f -- "
                        "sketchRatio:%{public}f",
            tagRatio, sketchRatio);
        sketchWrapper_->UpdateSketchRatio(sketchRatio);
        sketchWrapper_->UpdateZoomRatio(tagRatio);
    }
}

void PreviewOutput::OnNativeUnregisterCallback(const std::string& eventString)
{
    if (eventString == CONST_SKETCH_STATUS_CHANGED) {
        std::lock_guard<std::mutex> lock(asyncOpMutex_);
        if (sketchWrapper_ == nullptr) {
            return;
        }
        sketchWrapper_->StopSketchStream();
    }
}

void PreviewOutput::CameraServerDied(pid_t pid)
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

int32_t PreviewOutput::canSetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
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
