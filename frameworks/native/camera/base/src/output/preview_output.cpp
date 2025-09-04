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
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <utility>
#include <variant>

#include "camera/v1_3/types.h"
#include "camera_device_ability_items.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_metadata_operator.h"
#include "camera_output_capability.h"
#include "camera_rotation_api_utils.h"
#include "camera_util.h"
#include "display_manager.h"
#include "stream_repeat_callback_stub.h"
#include "image_format.h"
#include "istream_repeat.h"
#include "istream_repeat_callback.h"
#include "metadata_common_utils.h"
#include "parameters.h"
#include "session/capture_session.h"
#include "sketch_wrapper.h"
#include "surface.h"
#include "surface_utils.h"

namespace OHOS {
namespace CameraStandard {
namespace {
camera_format_t GetHdiFormatFromCameraFormat(CameraFormat cameraFormat)
{
    // LCOV_EXCL_START
    switch (cameraFormat) {
        case CAMERA_FORMAT_YCBCR_420_888:
            return OHOS_CAMERA_FORMAT_YCBCR_420_888;
        case CAMERA_FORMAT_YUV_420_SP: // nv21
            return OHOS_CAMERA_FORMAT_YCRCB_420_SP;
        case CAMERA_FORMAT_YCBCR_P010:
            return OHOS_CAMERA_FORMAT_YCBCR_P010;
        case CAMERA_FORMAT_YCRCB_P010:
            return OHOS_CAMERA_FORMAT_YCRCB_P010;
        case CAMERA_FORMAT_NV12: // nv12
            return OHOS_CAMERA_FORMAT_YCBCR_420_SP;
        case CAMERA_FORMAT_YUV_422_YUYV:
            return OHOS_CAMERA_FORMAT_422_YUYV;
        case CAMERA_FORMAT_YUV_422_UYVY:
            return OHOS_CAMERA_FORMAT_422_UYVY;
        default:
            return OHOS_CAMERA_FORMAT_IMPLEMENTATION_DEFINED;
    }
    return OHOS_CAMERA_FORMAT_IMPLEMENTATION_DEFINED;
    // LCOV_EXCL_STOP
}
} // namespace

static constexpr int32_t SKETCH_MIN_WIDTH = 480;
static constexpr int32_t RENDER_FIL_FILL = 9;
static constexpr int32_t RENDER_FIL_COVER = 13;
static constexpr float TARGET_MIN_RATIO = 0.01;
PreviewOutput::PreviewOutput(sptr<IBufferProducer> bufferProducer)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_PREVIEW, StreamType::REPEAT, bufferProducer, nullptr)
{
    MEDIA_INFO_LOG("PreviewOutput::PreviewOutput construct");
    previewFormat_ = 0;
    previewSize_.height = 0;
    previewSize_.width = 0;
    previewOutputListenerManager_->SetPreviewOutput(this);
}

PreviewOutput::PreviewOutput() : PreviewOutput(nullptr) {}

PreviewOutput::~PreviewOutput()
{
    MEDIA_INFO_LOG("PreviewOutput::PreviewOutput destruct");
}

int32_t PreviewOutput::Release()
{
    // LCOV_EXCL_START
    previewOutputListenerManager_->ClearListeners();
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::Release");
    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(stream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "PreviewOutput Failed to Release!, GetStream is nullptr");
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_PRINT_ELOG(itemStream == nullptr, "register surface consumer listener failed!");
    if (itemStream) {
        errCode = itemStream->Release();
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to release PreviewOutput!, errCode: %{public}d", errCode);
    }
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

int32_t PreviewOutputListenerManager::OnFrameStarted()
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto previewOutput = GetPreviewOutput();
    CHECK_RETURN_RET_ELOG(
        previewOutput == nullptr, CAMERA_OK, "PreviewOutputListenerManager::OnFrameStarted previewOutput is null");
    previewOutput->GetPreviewOutputListenerManager()->TriggerListener(
        [](auto listener) { listener->OnFrameStarted(); });
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutputListenerManager::OnFrameEnded(int32_t frameCount)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto previewOutput = GetPreviewOutput();
    CHECK_RETURN_RET_ELOG(
        previewOutput == nullptr, CAMERA_OK, "PreviewOutputListenerManager::OnFrameEnded previewOutput is null");
    previewOutput->GetPreviewOutputListenerManager()->TriggerListener(
        [&frameCount](auto listener) { listener->OnFrameEnded(frameCount); });
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutputListenerManager::OnFrameError(int32_t errorCode)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto previewOutput = GetPreviewOutput();
    CHECK_RETURN_RET_ELOG(
        previewOutput == nullptr, CAMERA_OK, "PreviewOutputListenerManager::OnFrameError previewOutput is null");
    previewOutput->GetPreviewOutputListenerManager()->TriggerListener(
        [&errorCode](auto listener) { listener->OnError(errorCode); });
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutputListenerManager::OnSketchStatusChanged(SketchStatus status)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto previewOutput = GetPreviewOutput();
    CHECK_RETURN_RET_ELOG(previewOutput == nullptr, CAMERA_OK,
        "PreviewOutputListenerManager::OnSketchStatusChanged previewOutput is null");
    previewOutput->OnSketchStatusChanged(status);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutputListenerManager::OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt &captureEndedInfo)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("PreviewOutput::OnDeferredVideoEnhancementInfo called");
    // empty impl
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

void PreviewOutputListenerManager::SetPreviewOutput(wptr<PreviewOutput> previewOutput)
{
    previewOutput_ = previewOutput;
}

sptr<PreviewOutput> PreviewOutputListenerManager::GetPreviewOutput()
{
    return previewOutput_.promote();
}

int32_t PreviewOutput::OnSketchStatusChanged(SketchStatus status)
{
    // LCOV_EXCL_START
    CHECK_RETURN_RET(sketchWrapper_ == nullptr, CAMERA_INVALID_STATE);
    auto session = GetSession();
    CHECK_RETURN_RET(session == nullptr, CAMERA_INVALID_STATE);
    SketchWrapper* wrapper = static_cast<SketchWrapper*>(sketchWrapper_.get());
    wrapper->OnSketchStatusChanged(status, session->GetFeaturesMode());
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

void PreviewOutput::AddDeferredSurface(sptr<Surface> surface)
{
    MEDIA_INFO_LOG("PreviewOutput::AddDeferredSurface called");
    CHECK_RETURN_ELOG(surface == nullptr, "PreviewOutput::AddDeferredSurface surface is null");
    auto stream = GetStream();
    CHECK_RETURN_ELOG(!stream, "PreviewOutput::AddDeferredSurface itemStream is null");
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    itemStream->AddDeferredSurface(surface->GetProducer());
}

int32_t PreviewOutput::Start()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::Start");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "PreviewOutput Failed to Start, session not commited");
    // LCOV_EXCL_START
    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(
        stream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR, "PreviewOutput Failed to Start, GetStream is nullptr");
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Start();
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "PreviewOutput Failed to Start!, errCode: %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("PreviewOutput::Start itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::Stop()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::Stop");
    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(
        stream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR, "PreviewOutput Failed to Stop, GetStream is nullptr");
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Stop();
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "PreviewOutput Failed to Stop!, errCode: %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("PreviewOutput::Stop itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
}

bool PreviewOutput::IsDynamicSketchNotifySupported()
{
    // LCOV_EXCL_START
    auto session = GetSession();
    CHECK_RETURN_RET(session == nullptr, false);
    auto metadata = GetDeviceMetadata();
    CHECK_RETURN_RET(metadata == nullptr, false);

    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_SKETCH_INFO_NOTIFICATION, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, false,
        "PreviewOutput::IsDynamicSketchNotifySupported Failed with return code %{public}d", ret);
    std::vector<int32_t> supportedModes = {};
    for (uint32_t i = 0; i < item.count; i++) {
        auto opMode = static_cast<OHOS::HDI::Camera::V1_3::OperationMode>(item.data.i32[i]);
        auto it = g_metaToFwSupportedMode_.find(opMode);
        if (it == g_metaToFwSupportedMode_.end()) {
            continue;
        }
        if (session->GetMode() == it->second) {
            return true;
        }
        supportedModes.emplace_back(item.data.i32[i]);
    }
    MEDIA_DEBUG_LOG("PreviewOutput::IsDynamicSketchNotifySupported modes:%{public}s",
        Container2String(supportedModes.begin(), supportedModes.end()).c_str());
    return false;
    // LCOV_EXCL_STOP
}

bool PreviewOutput::IsSketchSupported()
{
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::IsSketchSupported");

    auto sketchSize = FindSketchSize();
    CHECK_RETURN_RET(sketchSize == nullptr, false);
    // LCOV_EXCL_START
    if (IsDynamicSketchNotifySupported()) {
        return true;
    }
    MEDIA_INFO_LOG(
        "IsSketchSupported FindSketchSize Size is %{public}dx%{public}d", sketchSize->width, sketchSize->height);
    auto sketchRatio = GetSketchRatio();
    CHECK_RETURN_RET(sketchRatio > 0, true);
    MEDIA_DEBUG_LOG("IsSketchSupported GetSketchRatio failed, %{public}f ", sketchRatio);
    auto session = GetSession();
    CHECK_RETURN_RET(session == nullptr, false);
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
    // LCOV_EXCL_STOP
}

float PreviewOutput::GetSketchRatio()
{
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::GetSketchRatio");

    auto session = GetSession();
    if (session == nullptr) {
        MEDIA_WARNING_LOG("PreviewOutput::GetSketchRatio session is null");
        return -1.0f;
    }
    // LCOV_EXCL_START
    auto currentMode = session->GetFeaturesMode();
    SketchWrapper::UpdateSketchStaticInfo(GetDeviceMetadata());
    float ratio = SketchWrapper::GetSketchEnableRatio(currentMode);
    if (ratio <= 0) {
        MEDIA_WARNING_LOG("PreviewOutput::GetSketchRatio mode:%{public}s", currentMode.Dump().c_str());
    }
    return ratio;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::CreateSketchWrapper(Size sketchSize)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("PreviewOutput::CreateSketchWrapper enter sketchSize is:%{public}d x %{public}d", sketchSize.width,
        sketchSize.height);
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(
        session == nullptr, ServiceToCameraError(CAMERA_INVALID_STATE), "EnableSketch session null");
    auto wrapper = std::make_shared<SketchWrapper>(GetStream(), sketchSize, IsDynamicSketchNotifySupported());
    sketchWrapper_ = wrapper;
    wrapper->SetPreviewOutputCallbackManager(previewOutputListenerManager_);
    auto metadata = GetDeviceMetadata();
    int32_t retCode = wrapper->Init(metadata, session->GetFeaturesMode());
    return ServiceToCameraError(retCode);
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::EnableSketch(bool isEnable)
{
    MEDIA_DEBUG_LOG("Enter Into PreviewOutput::EnableSketch %{public}d", isEnable);
    CHECK_RETURN_RET_ELOG(!IsSketchSupported(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "EnableSketch IsSketchSupported is false");
    // LCOV_EXCL_START
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    std::lock_guard<std::mutex> lock(asyncOpMutex_);

    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionConfiged(),
        CameraErrorCode::SESSION_NOT_CONFIG, "PreviewOutput Failed EnableSketch!, session not config");

    if (isEnable) {
        CHECK_RETURN_RET(sketchWrapper_ != nullptr, ServiceToCameraError(CAMERA_OPERATION_NOT_ALLOWED));
        auto sketchSize = FindSketchSize();
        CHECK_RETURN_RET_ELOG(sketchSize == nullptr, ServiceToCameraError(errCode),
            "PreviewOutput EnableSketch FindSketchSize is null");
        MEDIA_INFO_LOG("EnableSketch FindSketchSize Size is %{public}dx%{public}d",
            sketchSize->width, sketchSize->height);
        return CreateSketchWrapper(*sketchSize);
    }

    // Disable sketch branch
    CHECK_RETURN_RET(sketchWrapper_ == nullptr, ServiceToCameraError(CAMERA_OPERATION_NOT_ALLOWED));
    errCode = sketchWrapper_->Destroy();
    sketchWrapper_ = nullptr;
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::AttachSketchSurface(sptr<Surface> sketchSurface)
{
    // LCOV_EXCL_START
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_CONFIG, "PreviewOutput Failed to AttachSketchSurface, session not commited");
    CHECK_RETURN_RET(sketchWrapper_ == nullptr, CameraErrorCode::INVALID_ARGUMENT);
    CHECK_RETURN_RET(sketchSurface == nullptr, CameraErrorCode::INVALID_ARGUMENT);
    int32_t errCode = sketchWrapper_->AttachSketchSurface(sketchSurface);
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

void PreviewOutput::SetStream(sptr<IStreamCommon> stream)
{
    CaptureOutput::SetStream(stream);
    CHECK_RETURN_ELOG(stream == nullptr, "PreviewOutput::SetStream stream is null");
    sptr<IStreamRepeatCallback> callback = previewOutputListenerManager_;
    static_cast<IStreamRepeat*>(stream.GetRefPtr())->SetCallback(callback);
}

int32_t PreviewOutput::CreateStream()
{
    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(
        stream != nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED, "PreviewOutput::CreateStream stream is not null");
    // LCOV_EXCL_START
    auto producer = GetBufferProducer();
    CHECK_RETURN_RET_ELOG(
        producer == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED, "PreviewOutput::CreateStream producer is null");
    sptr<IStreamRepeat> streamPtr = nullptr;
    auto previewProfile = GetPreviewProfile();
    CHECK_RETURN_RET_ELOG(previewProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "PreviewOutput::CreateStream previewProfile is null");
    int32_t res =
        CameraManager::GetInstance()->CreatePreviewOutputStream(streamPtr, *previewProfile, GetBufferProducer());
    SetStream(streamPtr);
    CHECK_RETURN_RET_ELOG(
        streamPtr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR, "PreviewOutput::CreateStream streamPtr is null");
    sptr<IStreamRepeatCallback> callback = previewOutputListenerManager_;
    streamPtr->SetCallback(callback);
    return res;
    // LCOV_EXCL_STOP
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
    previewFormat_ = format;
}

void PreviewOutput::SetSize(Size size)
{
    MEDIA_DEBUG_LOG("PreviewOutput::SetSize set size %{public}d, %{public}d", size.width, size.height);
    previewSize_ = size;
}

int32_t PreviewOutput::SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate)
{
    int32_t result = canSetFrameRateRange(minFrameRate, maxFrameRate);
    CHECK_RETURN_RET(result != CameraErrorCode::SUCCESS, result);
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(minFrameRate == previewFrameRateRange_[0] && maxFrameRate == previewFrameRateRange_[1],
        CameraErrorCode::INVALID_ARGUMENT, "PreviewOutput::SetFrameRate The frame rate does not need to be set.");
    std::vector<int32_t> frameRateRange = {minFrameRate, maxFrameRate};
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    if (itemStream) {
        int32_t ret = itemStream->SetFrameRate(minFrameRate, maxFrameRate);
        CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ServiceToCameraError(ret),
            "PreviewOutput::setFrameRate failed to set stream frame rate");
        SetFrameRateRange(minFrameRate, maxFrameRate);
    }
    auto session = GetSession();
    wptr<PreviewOutput> weakThis(this);
    CHECK_EXECUTE(session != nullptr, session->AddFunctionToMap("preview" + std::to_string(OHOS_CONTROL_FPS_RANGES),
        [weakThis, minFrameRate, maxFrameRate]() {
            auto sharedThis = weakThis.promote();
            CHECK_RETURN_ELOG(!sharedThis, "SetFrameRate previewOutput is nullptr.");
            sharedThis->SetFrameRate(minFrameRate, maxFrameRate);
        }));
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

std::vector<std::vector<int32_t>> PreviewOutput::GetSupportedFrameRates()
{
    MEDIA_DEBUG_LOG("PreviewOutput::GetSupportedFrameRates called.");
    auto session = GetSession();
    CHECK_RETURN_RET(session == nullptr, {});
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET(inputDevice == nullptr, {});
    sptr<CameraDevice> camera = inputDevice->GetCameraDeviceInfo();
    SceneMode curMode = session->GetMode();

    sptr<CameraOutputCapability> cameraOutputCapability = CameraManager::GetInstance()->
                                                          GetSupportedOutputCapability(camera, curMode);
    CHECK_RETURN_RET(cameraOutputCapability == nullptr, {});
    std::vector<Profile> supportedProfiles = cameraOutputCapability->GetPreviewProfiles();
    supportedProfiles.erase(std::remove_if(
        supportedProfiles.begin(), supportedProfiles.end(),
        [&](Profile& profile) {
            return profile.format_ != previewFormat_ ||
                   profile.GetSize().height != previewSize_.height ||
                   profile.GetSize().width != previewSize_.width;
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
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::StartSketch()
{
    int32_t errCode = CAMERA_UNKNOWN_ERROR;

    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_CONFIG,
        "PreviewOutput Failed to StartSketch, session not commited");
    // LCOV_EXCL_START
    if (sketchWrapper_ != nullptr) {
        errCode = sketchWrapper_->StartSketchStream();
    }
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::StopSketch()
{
    int32_t errCode = CAMERA_UNKNOWN_ERROR;

    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_CONFIG,
        "PreviewOutput Failed to StopSketch, session not commited");
    // LCOV_EXCL_START
    if (sketchWrapper_ != nullptr) {
        errCode = sketchWrapper_->StopSketchStream();
    }
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

std::shared_ptr<Camera::CameraMetadata> PreviewOutput::GetDeviceMetadata()
{
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, nullptr, "PreviewOutput::GetDeviceMetadata session is null");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, nullptr, "PreviewOutput::GetDeviceMetadata input is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, nullptr, "PreviewOutput::GetDeviceMetadata info is null");
    auto metaData = deviceInfo->GetCachedMetadata();
    CHECK_RETURN_RET_ELOG(metaData == nullptr, nullptr, "PreviewOutput::GetDeviceMetadata metaData is null");
    return metaData;
    // LCOV_EXCL_STOP
}

std::shared_ptr<Size> PreviewOutput::FindSketchSize()
{
    auto session = GetSession();
    auto metaData = GetDeviceMetadata();
    CHECK_RETURN_RET_ELOG(session == nullptr || metaData == nullptr, nullptr,
        "PreviewOutput::FindSketchSize GetDeviceMetadata failed");
    // LCOV_EXCL_START
    auto profile = GetPreviewProfile();
    CHECK_RETURN_RET_ELOG(profile == nullptr, nullptr, "PreviewOutput::FindSketchSize profile is nullptr");
    camera_format_t hdi_format = GetHdiFormatFromCameraFormat(profile->GetCameraFormat());
    CHECK_RETURN_RET_ELOG(hdi_format == OHOS_CAMERA_FORMAT_IMPLEMENTATION_DEFINED, nullptr,
        "PreviewOutput::FindSketchSize preview format is illegal");
    auto sizeList = MetadataCommonUtils::GetSupportedPreviewSizeRange(
        session->GetFeaturesMode().GetSceneMode(), hdi_format, metaData);
    CHECK_RETURN_RET(sizeList == nullptr || sizeList->size() == 0, nullptr);
    Size previewSize = profile->GetSize();
    CHECK_RETURN_RET(previewSize.width <= 0 || previewSize.height <= 0, nullptr);
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
    // LCOV_EXCL_STOP
}

void PreviewOutput::SetCallback(std::shared_ptr<PreviewStateCallback> callback)
{
    // LCOV_EXCL_START
    auto stream = GetStream();
    CHECK_RETURN(stream == nullptr);
    bool isSuccess = previewOutputListenerManager_->AddListener(callback);
    CHECK_RETURN(!isSuccess);
    CHECK_RETURN(!(previewOutputListenerManager_->GetListenerCount() == 1));
    sptr<IStreamRepeatCallback> ipcCallback = previewOutputListenerManager_;
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = itemStream->SetCallback(ipcCallback);
    CHECK_RETURN(errCode == CAMERA_OK);
    MEDIA_ERR_LOG("PreviewOutput::SetCallback fail");
    previewOutputListenerManager_->RemoveListener(callback);
    // LCOV_EXCL_STOP
}

void PreviewOutput::RemoveCallback(std::shared_ptr<PreviewStateCallback> callback)
{
    // LCOV_EXCL_START
    previewOutputListenerManager_->RemoveListener(callback);
    if (previewOutputListenerManager_->GetListenerCount() == 0) {
        auto stream = GetStream();
        CHECK_RETURN(stream == nullptr);
        sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
        itemStream->UnSetCallback();
    }
    // LCOV_EXCL_STOP
}

const std::set<camera_device_metadata_tag_t>& PreviewOutput::GetObserverControlTags()
{
    const static std::set<camera_device_metadata_tag_t> tags = { OHOS_CONTROL_ZOOM_RATIO, OHOS_CONTROL_CAMERA_MACRO,
        OHOS_CONTROL_MOON_CAPTURE_BOOST, OHOS_CONTROL_SMOOTH_ZOOM_RATIOS };
    return tags;
}

const std::set<camera_device_metadata_tag_t>& PreviewOutput::GetObserverResultTags()
{
    // LCOV_EXCL_START
    const static std::set<camera_device_metadata_tag_t> tags = { OHOS_STATUS_SKETCH_STREAM_INFO };
    return tags;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::OnControlMetadataChanged(
    const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    // LCOV_EXCL_START
    // Don't trust outer public interface passthrough data. Check the legitimacy of the data.
    CHECK_RETURN_RET(metadataItem.count <= 0, CAM_META_INVALID_PARAM);
    CHECK_RETURN_RET(sketchWrapper_ == nullptr, CAM_META_FAILURE);
    auto session = GetSession();
    CHECK_RETURN_RET(session == nullptr, CAM_META_FAILURE);
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    SketchWrapper* wrapper = reinterpret_cast<SketchWrapper*>(sketchWrapper_.get());
    wrapper->OnMetadataDispatch(session->GetFeaturesMode(), tag, metadataItem);
    return CAM_META_SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::OnResultMetadataChanged(
    const camera_device_metadata_tag_t tag, const camera_metadata_item_t& metadataItem)
{
    // LCOV_EXCL_START
    // Don't trust outer public interface passthrough data. Check the legitimacy of the data.
    CHECK_RETURN_RET(metadataItem.count <= 0, CAM_META_INVALID_PARAM);
    CHECK_RETURN_RET(sketchWrapper_ == nullptr, CAM_META_FAILURE);
    auto session = GetSession();
    CHECK_RETURN_RET(session == nullptr, CAM_META_FAILURE);
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    SketchWrapper* wrapper = reinterpret_cast<SketchWrapper*>(sketchWrapper_.get());
    wrapper->OnMetadataDispatch(session->GetFeaturesMode(), tag, metadataItem);
    return CAM_META_SUCCESS;
    // LCOV_EXCL_STOP
}

sptr<PreviewOutputListenerManager> PreviewOutput::GetPreviewOutputListenerManager()
{
    return previewOutputListenerManager_;
}

void PreviewOutput::OnNativeRegisterCallback(const std::string& eventString)
{
    // LCOV_EXCL_START
    if (eventString == CONST_SKETCH_STATUS_CHANGED) {
        std::lock_guard<std::mutex> lock(asyncOpMutex_);
        CHECK_RETURN(sketchWrapper_ == nullptr);
        auto session = GetSession();
        CHECK_RETURN(session == nullptr || !session->IsSessionCommited());
        auto metadata = GetDeviceMetadata();
        CHECK_RETURN_ELOG(metadata == nullptr, "metadata is nullptr");
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_ZOOM_RATIO, &item);
        CHECK_RETURN(ret != CAM_META_SUCCESS || item.count <= 0);
        float tagRatio = *item.data.f;
        CHECK_RETURN(tagRatio <= 0);
        float sketchRatio = sketchWrapper_->GetSketchEnableRatio(session->GetFeaturesMode());
        MEDIA_DEBUG_LOG("PreviewOutput::OnNativeRegisterCallback OHOS_CONTROL_ZOOM_RATIO >>> tagRatio:%{public}f -- "
                        "sketchRatio:%{public}f",
            tagRatio, sketchRatio);
        sketchWrapper_->UpdateSketchRatio(sketchRatio);
        sketchWrapper_->UpdateZoomRatio(tagRatio);
    }
    // LCOV_EXCL_STOP
}

void PreviewOutput::OnNativeUnregisterCallback(const std::string& eventString)
{
    // LCOV_EXCL_START
    if (eventString == CONST_SKETCH_STATUS_CHANGED) {
        std::lock_guard<std::mutex> lock(asyncOpMutex_);
        CHECK_RETURN(sketchWrapper_ == nullptr);
        sketchWrapper_->StopSketchStream();
    }
    // LCOV_EXCL_STOP
}

void PreviewOutput::CameraServerDied(pid_t pid)
{
    // LCOV_EXCL_START
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    previewOutputListenerManager_->TriggerListener([](auto listener) {
        int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
        listener->OnError(serviceErrorType);
    });
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::canSetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "PreviewOutput::canSetFrameRateRange Can not set frame rate range without commit session");
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(!session->CanSetFrameRateRange(minFrameRate, maxFrameRate, this),
        CameraErrorCode::UNRESOLVED_CONFLICTS_BETWEEN_STREAMS,
        "PreviewOutput::canSetFrameRateRange Can not set frame rate range with wrong state of output");
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<std::vector<int32_t>> supportedFrameRange = GetSupportedFrameRates();
    for (auto item : supportedFrameRange) {
        CHECK_RETURN_RET(item[minIndex] <= minFrameRate && item[maxIndex] >= maxFrameRate,
            CameraErrorCode::SUCCESS);
    }
    MEDIA_WARNING_LOG("PreviewOutput::canSetFrameRateRange Can not set frame rate range with invalid parameters");
    return CameraErrorCode::INVALID_ARGUMENT;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::GetPreviewRotation(int32_t imageRotation)
{
    MEDIA_INFO_LOG("PreviewOutput GetPreviewRotation is called, imageRotation: %{public}d", imageRotation);
    CHECK_RETURN_RET_ELOG(imageRotation < ROTATION_0 || imageRotation > CAPTURE_ROTATION_BASE ||
        imageRotation % ROTATION_90_DEGREES != 0, INVALID_ARGUMENT,
        "PreviewOutput GetPreviewRotation error!, invalid argument");
    int32_t sensorOrientation = 0;
    ImageRotation result = ImageRotation::ROTATION_0;
    sptr<CameraDevice> cameraObj;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR,
        "PreviewOutput GetPreviewRotation error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "PreviewOutput GetPreviewRotation error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "PreviewOutput GetPreviewRotation error!, cameraObj is nullptr");
    uint32_t apiCompatibleVersion = CameraApiVersion::GetApiVersion();
    if (apiCompatibleVersion < CameraApiVersion::APIVersion::API_FOURTEEN) {
        imageRotation = JudegRotationFunc(imageRotation);
    }
    sensorOrientation = static_cast<int32_t>(cameraObj->GetCameraOrientation());
    result = (ImageRotation)((imageRotation + sensorOrientation) % CAPTURE_ROTATION_BASE);
    MEDIA_INFO_LOG("PreviewOutput GetPreviewRotation :result %{public}d, sensorOrientation:%{public}d",
        result, sensorOrientation);
    return result;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::JudegRotationFunc(int32_t imageRotation)
{
    std::string deviceType = OHOS::system::GetDeviceType();
    if (imageRotation > CAPTURE_ROTATION_BASE) {
        return INVALID_ARGUMENT;
    }
    bool isTableFlag = system::GetBoolParameter("const.multimedia.enable_camera_rotation_compensation", 0);
    uint32_t apiCompatibleVersion = CameraApiVersion::GetApiVersion();
    if (isTableFlag && apiCompatibleVersion < CameraApiVersion::APIVersion::API_FOURTEEN) {
        imageRotation = ((imageRotation - ROTATION_90_DEGREES + CAPTURE_ROTATION_BASE) % CAPTURE_ROTATION_BASE);
    }
    return imageRotation;
}

int32_t PreviewOutput::SetPreviewRotation(int32_t imageRotation, bool isDisplayLocked)
{
    MEDIA_INFO_LOG("PreviewOutput SetPreviewRotation is called, imageRotation:%{public}d, isDisplayLocked:%{public}d",
        imageRotation, isDisplayLocked);
    CHECK_RETURN_RET_ELOG(imageRotation < ROTATION_0 || imageRotation > CAPTURE_ROTATION_BASE ||
        imageRotation % ROTATION_90_DEGREES != 0, INVALID_ARGUMENT,
        "PreviewOutput SetPreviewRotation error!, invalid argument");
    int32_t sensorOrientation = 0;
    ImageRotation result = ROTATION_0;
    sptr<CameraDevice> cameraObj;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR,
        "PreviewOutput SetPreviewRotation error!, session is nullptr");
    // LCOV_EXCL_START
    session->SetHasFitedRotation(true);
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "PreviewOutput SetPreviewRotation error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "PreviewOutput SetPreviewRotation error!, cameraObj is nullptr");
    sensorOrientation = static_cast<int32_t>(cameraObj->GetCameraOrientation());
    CameraPosition cameraPosition = cameraObj->GetPosition();
    if (cameraPosition == CAMERA_POSITION_FRONT) {
        int32_t displayrotation = (imageRotation - sensorOrientation + CAPTURE_ROTATION_BASE) % CAPTURE_ROTATION_BASE;
        imageRotation = (sensorOrientation - displayrotation + CAPTURE_ROTATION_BASE) % CAPTURE_ROTATION_BASE;
    }
    result = isDisplayLocked ? ImageRotation(sensorOrientation) : ImageRotation(imageRotation);
    MEDIA_INFO_LOG("PreviewOutput SetPreviewRotation :result %{public}d, sensorOrientation:%{public}d",
        result, sensorOrientation);
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_RETURN_RET_ELOG(itemStream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "PreviewOutput::SetCameraRotation() itemStream is nullptr");
    if (itemStream) {
        errCode = itemStream->SetCameraRotation(true, result);
        CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, SERVICE_FATL_ERROR,
            "Failed to SetCameraRotation!, errCode: %{public}d", errCode);
    }
    MEDIA_ERR_LOG("PreviewOutput SetPreviewRotation sucess");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

bool PreviewOutput::IsXComponentSwap()
{
    // LCOV_EXCL_START
    sptr<OHOS::Rosen::Display> display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    if (display == nullptr) {
        MEDIA_ERR_LOG("Get display info failed");
        display = OHOS::Rosen::DisplayManager::GetInstance().GetDisplayById(0);
        CHECK_RETURN_RET_ELOG(display == nullptr, true, "Get display info failed, display is nullptr");
    }
    uint32_t currentRotation = static_cast<uint32_t>(display->GetRotation()) * 90;
    std::string deviceType = OHOS::system::GetDeviceType();
    uint32_t apiCompatibleVersion = CameraApiVersion::GetApiVersion();
    MEDIA_INFO_LOG("deviceType=%{public}s, apiCompatibleVersion=%{public}d", deviceType.c_str(), apiCompatibleVersion);
    // The tablet has incompatible changes in API14; use version isolation for compilation.
    CHECK_EXECUTE(apiCompatibleVersion < CameraApiVersion::APIVersion::API_FOURTEEN && deviceType == "tablet",
        currentRotation = (currentRotation + STREAM_ROTATE_270) % STREAM_ROTATE_360);
    uint32_t cameraRotation = 0;
    CHECK_RETURN_RET_ELOG(GetCameraDeviceRotationAngle(cameraRotation) != CAMERA_OK,
        false, "Get camera rotation failed");
    MEDIA_INFO_LOG("display rotation: %{public}d, camera rotation: %{public}d", currentRotation, cameraRotation);
    uint32_t rotationAngle = (currentRotation + cameraRotation) % STREAM_ROTATE_360;
    return rotationAngle == STREAM_ROTATE_90 || rotationAngle == STREAM_ROTATE_270;
    // LCOV_EXCL_STOP
}

int32_t PreviewOutput::GetCameraDeviceRotationAngle(uint32_t &cameraRotation)
{
    // LCOV_EXCL_START
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR,
        "GetCameraDeviceRotationAngle sesion is null");
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "GetCameraDeviceRotationAngle inputDevice is null");
    auto deviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(deviceInfo == nullptr, SERVICE_FATL_ERROR,
        "GetCameraDeviceRotationAngle deviceInfo is null");
    cameraRotation = deviceInfo->GetCameraOrientation();
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

void PreviewOutput::AdjustRenderFit()
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    int32_t renderFitNumber = 0;
    bool isRenderFitNewVersionEnabled = false;
    auto surfaceId = GetSurfaceId();
    auto xcomponentControllerProxy = XComponentControllerProxy::CreateXComponentControllerProxy();
    CHECK_RETURN_ELOG(xcomponentControllerProxy == nullptr, "xcomponentControllerProxy is null");
    int32_t ret = xcomponentControllerProxy->GetRenderFitBySurfaceId(
        surfaceId, renderFitNumber, isRenderFitNewVersionEnabled);
    MEDIA_INFO_LOG("GetRenderFitBySurfaceId ret: %{public}d, renderFitNumber: %{public}d,"
        "isRenderFitNewVersionEnabled: %{public}d",
        ret, renderFitNumber, isRenderFitNewVersionEnabled);
    renderFit_.store(renderFitNumber);
    CHECK_RETURN_ELOG(ret != 0 || renderFitNumber != RENDER_FIL_FILL, "Conditions not met");
    uint64_t outputSurfaceId;
    std::stringstream iss(surfaceId);
    iss >> outputSurfaceId;
    OHNativeWindow *outputNativeWindow = nullptr;
    ret = OH_NativeWindow_CreateNativeWindowFromSurfaceId(outputSurfaceId, &outputNativeWindow);
    CHECK_RETURN_ELOG(ret != 0,
        "The AdjustRenderFit call failed due to a failure in the CreateNativeWindowFromSurfaceId interface call,"
        "ret: %{public}d", ret);
    int code = GET_BUFFER_GEOMETRY;
    int xComponentWidth = 0;
    int xComponentHeight = 0;
    // Get the width and height of XComponent
    ret = OH_NativeWindow_NativeWindowHandleOpt(outputNativeWindow, code, &xComponentHeight, &xComponentWidth);
    MEDIA_INFO_LOG("The width of the XComponent is %{public}d, and the height is %{public}d",
        xComponentWidth, xComponentHeight);
    xComponentHeight_.store(xComponentHeight);
    xComponentWidth_.store(xComponentWidth);
    OH_NativeWindow_DestroyNativeWindow(outputNativeWindow);
    CHECK_RETURN_ELOG(ret != 0 || xComponentHeight * xComponentWidth == 0,
        "The AdjustRenderFit call failed because the xComponentWidth x xComponentHeight equals 0."
        "ret: %{public}d", ret);
    if (IsXComponentSwap()) {
        MEDIA_INFO_LOG("XComponent width and height need to swap");
        int temp = xComponentWidth;
        xComponentWidth = xComponentHeight;
        xComponentHeight = temp;
    }
    CHECK_RETURN_ELOG(previewSize_.width * previewSize_.height == 0,
        "The AdjustRenderFit call failed because the previewWidth x previewHeight equals 0");
    float cameraRatio = (float)previewSize_.width / (float)previewSize_.height;
    float XComponentRatio = (float)xComponentWidth / (float)xComponentHeight;
    CHECK_RETURN_ELOG(abs(cameraRatio - XComponentRatio) < TARGET_MIN_RATIO,
        "XComponent ratio matched camera ratio, no need adjust renderFit");
    ret = xcomponentControllerProxy->SetRenderFitBySurfaceId(surfaceId, RENDER_FIL_COVER, true);
    isModified_.store(true);
    CHECK_RETURN_ELOG(ret != 0, "SetRenderFitBySurfaceId ret: %{public}d", ret);
    // LCOV_EXCL_STOP
}

void PreviewOutput::SetSurfaceId(const std::string& surfaceId)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(surfaceIdMutex_);
    surfaceId_ = surfaceId;
    // LCOV_EXCL_STOP
}

std::string PreviewOutput::GetSurfaceId()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(surfaceIdMutex_);
    return surfaceId_;
    // LCOV_EXCL_STOP
}

void PreviewOutput::ReportXComponentInfoEvent()
{
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "RECORD_RENDERFIT_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "RENDERFIT", renderFit_.load(),
        "XCOMPONENT_HEIGHT", xComponentHeight_.load(),
        "XCOMPONENT_WIDTH", xComponentWidth_.load(),
        "PREVIEW_HEIGHT", previewSize_.height,
        "PREVIEW_WIDTH", previewSize_.width,
        "IS_MODIFIED", isModified_.load());
}
} // namespace CameraStandard
} // namespace OHOS
