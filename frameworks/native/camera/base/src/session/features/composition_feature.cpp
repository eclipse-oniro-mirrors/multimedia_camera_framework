/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "features/composition_feature.h"
#include "camera_security_utils.h"
#include "camera_error_code.h"
#include <cstdint>

#include "abilities/sketch_ability.h"
#include "camera_log.h"
#include "capture_scene_const.h"
#include "session/capture_session.h"
#include "camera_metadata.h"
#include "video_key_info.h"
#include "istream_repeat.h"
#include "camera_manager.h"
#include "camera_log.h"
#include "pixel_map.h"

namespace OHOS {
namespace CameraStandard {
const std::unordered_set<SceneMode> CompositionFeature::SUPPORTED_MODES = { SceneMode::CAPTURE, SceneMode::PORTRAIT,
    SceneMode::NIGHT };

CompositionFeature::~CompositionFeature()
{
    MEDIA_INFO_LOG("CompositionFeature::~CompositionFeature enter");
    if (compositionStream_) {
        compositionStream_->Stop();
        compositionStream_->Release();
    }
    if (compositionSurface_ != nullptr) {
        compositionSurface_->UnregisterConsumerListener();
    }
}

int32_t CompositionFeature::IsCompositionEffectPreviewSupported(bool& isSupported)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CompositionFeature::IsCompositionEffectPreviewSupported is called");
    auto ret = CheckMode();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ret,
        "CompositionFeature::IsCompositionEffectPreviewSupported check mode failed");
    CHECK_RETURN_RET_ELOG(captureSession_ == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::IsCompositionEffectPreviewSupported captureSession_ is nullptr");
    auto metadata = captureSession_->GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::IsCompositionEffectPreviewSupported metadata is nullptr");
    auto item = GetMetadataItem(metadata->get(), OHOS_ABILITY_COMPOSITION_EFFECT_PREVIEW);
    CHECK_RETURN_RET_ELOG(!item || item->count <= 0, OPERATION_NOT_ALLOWED,
        "CompositionFeature::IsCompositionEffectPreviewSupported IsCompositionEffectPreviewSupported Failed");
    isSupported = static_cast<bool>(item->data.u8[0]);
    MEDIA_INFO_LOG("CompositionFeature::IsCompositionEffectPreviewSupported: %{public}u", isSupported);
    return CameraErrorCode::SUCCESS;
}

int32_t CompositionFeature::EnableCompositionEffectPreview(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CompositionFeature::EnableCompositionEffectPreview is called");
    auto ret = CheckCommonPreconditions();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ret,
        "CompositionFeature::EnableCompositionEffectPreview preconditions failed");

    uint8_t enableValue = static_cast<uint8_t>(isEnable);
    CHECK_RETURN_RET_ELOG(captureSession_ == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::EnableCompositionEffectPreview captureSession_ is nullptr");
    bool status = AddOrUpdateMetadata(
        captureSession_->changedMetadata_, OHOS_CONTROL_COMPOSITION_EFFECT_PREVIEW, &enableValue, 1);
    CHECK_PRINT_ELOG(
        !status, "CompositionFeature::EnableCompositionEffectPreview failed to enable composition preview");
    return isEnable ? StartCompositionStream() : StopCompositionStream();
}

int32_t CompositionFeature::GetSupportedRecommendedInfoLanguage(std::vector<std::string>& supportedLanguages)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CompositionFeature::GetSupportedRecommendedInfoLanguage is called");
    auto ret = CheckCommonPreconditions();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ret,
        "CompositionFeature::GetSupportedRecommendedInfoLanguage preconditions failed");

    CHECK_RETURN_RET_ELOG(captureSession_ == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::GetSupportedRecommendedInfoLanguage captureSession_ is nullptr");
    auto metadata = captureSession_->GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::GetSupportedRecommendedInfoLanguage metadata is nullptr");
    auto item = GetMetadataItem(metadata->get(), OHOS_ABILITY_RECOMMENDED_INFO_LANGUAGE);
    CHECK_RETURN_RET_ELOG(!item || item->count <= 0, OPERATION_NOT_ALLOWED,
        "CompositionFeature::GetSupportedRecommendedInfoLanguage Failed");
    supportedLanguages.clear();
    for (uint32_t i = 0; i < item->count; i++) {
        uint8_t iLanguage = item->data.u8[i];
        auto it = INT_TO_STR_LANGUAGE_MAP.find(iLanguage);
        CHECK_CONTINUE_ELOG(it == INT_TO_STR_LANGUAGE_MAP.end(),
            "CompositionFeature::GetSupportedRecommendedInfoLanguage unknown language: %{public}u", iLanguage);
        std::string sLanguage = it->second;
        supportedLanguages.push_back(sLanguage);
        MEDIA_DEBUG_LOG(
            "CompositionFeature::GetSupportedRecommendedInfoLanguage supportedLanguages: %{public}u, %{public}s",
            iLanguage, sLanguage.c_str());
    }
    MEDIA_INFO_LOG("CompositionFeature::GetSupportedRecommendedInfoLanguage supportedLanguages size: %{public}zu",
        supportedLanguages.size());
    return CameraErrorCode::SUCCESS;
}

int32_t CompositionFeature::SetRecommendedInfoLanguage(const std::string& language)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("CompositionFeature::SetRecommendedInfoLanguage SetSupportedRecommendedInfoLanguage is called");
    auto ret = CheckCommonPreconditions();
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ret,
        "CompositionFeature::SetRecommendedInfoLanguage Common preconditions failed");

    std::vector<std::string> supportedLanguages;
    ret = GetSupportedRecommendedInfoLanguage(supportedLanguages);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ret,
        "CompositionFeature::SetRecommendedInfoLanguage is not support, ret: %{public}d", ret);
    CHECK_RETURN_RET_ELOG(
        std::find(supportedLanguages.begin(), supportedLanguages.end(), language) == supportedLanguages.end(),
        CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::SetRecommendedInfoLanguage input language is not supported");
    auto it = STR_TO_INT_LANGUAGE_MAP.find(language);
    CHECK_RETURN_RET_ELOG(it == STR_TO_INT_LANGUAGE_MAP.end(), CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::SetRecommendedInfoLanguage unknown language: %{public}s", language.c_str());
    uint8_t iLanguage = it->second;
    CHECK_RETURN_RET_ELOG(
        captureSession_ == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED, "captureSession_ is nullptr");
    bool status =
        AddOrUpdateMetadata(captureSession_->changedMetadata_, OHOS_CONTROL_RECOMMENDED_INFO_LANGUAGE, &iLanguage, 1);
    CHECK_PRINT_ELOG(!status, "CompositionFeature::SetRecommendedInfoLanguage failed to set flash mode");
    return CameraErrorCode::SUCCESS;
}

int32_t CompositionFeature::SetCompositionEffectReceiveCallback(
    std::shared_ptr<NativeInfoCallback<CompositionEffectInfo>> callback)
{
    MEDIA_INFO_LOG("CompositionFeature::SetCompositionEffectReceiveCallback is called");
    std::lock_guard<std::mutex> lock(compositionEffectReceiveCallbackMutex_);
    CHECK_PRINT_ILOG(!callback, "CompositionFeature::SetCompositionEffectReceiveCallback set callback to nullptr");
    compositionEffectReceiveCallback_ = callback;
    return CameraErrorCode::SUCCESS;
}

int32_t CompositionFeature::CheckMode()
{
    MEDIA_INFO_LOG("CompositionFeature::CheckMode enter");
    CHECK_RETURN_RET_ELOG(captureSession_ == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::CheckMode captureSession_ is nullptr");
    sptr<CaptureSession> captureSession = captureSession_.promote();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::CheckMode captureSession is nullptr");
    if (SUPPORTED_MODES.find(captureSession->GetMode()) == SUPPORTED_MODES.end()) {
        MEDIA_ERR_LOG(
            "CompositionFeature::CheckMode mode not supported, curMode: %{public}d", captureSession->GetMode());
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    return CameraErrorCode::SUCCESS;
}

int32_t CompositionFeature::CheckCommonPreconditions()
{
    MEDIA_INFO_LOG("CompositionFeature::CheckCommonPreconditions enter");
    int32_t ret = CheckMode();
    CHECK_RETURN_RET_ELOG(
        ret != CameraErrorCode::SUCCESS, ret, "CompositionFeature::CheckCommonPreconditions mode check fail");
    bool isSupported = false;
    ret = IsCompositionEffectPreviewSupported(isSupported);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ret,
        "CompositionFeature::CheckCommonPreconditions composition is not supported");
    return CameraErrorCode::SUCCESS;
}

int32_t CompositionFeature::StartCompositionStream()
{
    MEDIA_INFO_LOG("CompositionFeature::StartCompositionStream enter");
    CHECK_RETURN_RET_ELOG(compositionStreamStatus_ == StreamStatus::STARTED, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::StartCompositionStream compositionStreamStatus_ has STARTED");
    auto captureSession= captureSession_.promote();
    CHECK_RETURN_RET_ELOG(!captureSession, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::StartCompositionStream captureSession is nullptr");
    auto innerCaptureSession = captureSession->GetCaptureSession();
    CHECK_RETURN_RET_ELOG(!innerCaptureSession, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::StartCompositionStream innerCaptureSession is nullptr");
    if(compositionStream_ == nullptr){
        MEDIA_INFO_LOG("CompositionFeature::StartCompositionStream compositionStream_ init enter");
        sptr<IRemoteObject> compositionStreamRemote = nullptr;
        auto ret = innerCaptureSession->GetCompositionStream(compositionStreamRemote);
        CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ret,
            "CompositionFeature::StartCompositionStream GetCompositionStream fail");
        compositionStream_ = iface_cast<IStreamRepeat>(compositionStreamRemote);
        CHECK_RETURN_RET_ELOG(!compositionStream_, CameraErrorCode::OPERATION_NOT_ALLOWED,
            "CompositionFeature::StartCompositionStream compositionStream_ is nullptr");

        compositionSurface_ = IConsumerSurface::Create();
        CHECK_RETURN_RET_ELOG(compositionSurface_ == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CompositionFeature::StartCompositionStream surface is null");
        sptr<IBufferConsumerListener> compositionListener =
            sptr<CompositionEffectListener>::MakeSptr(shared_from_this(), compositionSurface_);
        CHECK_RETURN_RET_ELOG(compositionListener == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
            "CompositionFeature::StartCompositionStream compositionListener is null");
        compositionSurface_->RegisterConsumerListener(compositionListener);
        compositionSurface_->SetUserData(
            CameraManager::surfaceFormat, std::to_string(COMPOSITION_FORMAT));
        compositionStream_->AddDeferredSurface(compositionSurface_->GetProducer());
    }
    int32_t retCode = compositionStream_->Start();
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, retCode,
        "CompositionFeature::StartCompositionStream fail, ret: %{public}d", retCode);
    compositionStreamStatus_ = StreamStatus::STARTED;
    return CameraErrorCode::SUCCESS;
}

int32_t CompositionFeature::StopCompositionStream()
{
    MEDIA_INFO_LOG("CompositionFeature::StopCompositionStream enter");
    CHECK_RETURN_RET_ELOG(!compositionStream_, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::StopCompositionStream compositionStream_ is nullptr");
    CHECK_RETURN_RET_ELOG(compositionStreamStatus_ == StreamStatus::STOPPED, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "CompositionFeature::StopCompositionStream compositionStreamStatus_ has STOPPED");
    int32_t retCode = compositionStream_->Stop();
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, retCode,
        "CompositionFeature::StopCompositionStream fail, ret: %{public}d", retCode);
    compositionStreamStatus_ = StreamStatus::STOPPED;
    return CameraErrorCode::SUCCESS;
}

void CompositionEffectListener::OnBufferAvailable()
{
    MEDIA_INFO_LOG("CompositionEffectListener::OnBufferAvailable enter");
    auto surface = surface_.promote();
    CHECK_RETURN_ELOG(surface == nullptr, "CompositionEffectListener::OnBufferAvailable surface is nullptr, return");
    sptr<SurfaceBuffer> buffer = nullptr;
    int64_t timestamp;
    OHOS::Rect damage;
    int32_t fence = -1;
    surface->AcquireBuffer(buffer, fence, timestamp, damage);
    sptr<BufferExtraData> exData = buffer->GetExtraData();
    CHECK_RETURN_ELOG(exData == nullptr, "CompositionEffectListener::OnBufferAvailable exData is nullptr, return");
    std::string compositionReasons;
    exData->ExtraGet(OHOS::Camera::compositionReasons, compositionReasons);
    int64_t compositionId;
    exData->ExtraGet(OHOS::Camera::compositionId, compositionId);
    int32_t compositionPointIndex;
    exData->ExtraGet(OHOS::Camera::compositionPointIndex, compositionPointIndex);
    MEDIA_INFO_LOG("CompositionEffectListener::OnBufferAvailable Reasons: %{public}s, id: %{public}" PRId64
                   ", index: %{public}d",
        compositionReasons.c_str(), compositionId, compositionPointIndex);
    auto pixelMap = Buffer2PixelMap(buffer);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("CompositionEffectListener::OnBufferAvailable CreatePixelMap fail");
        surface->ReleaseBuffer(buffer, -1);
        return;
    }
    std::shared_ptr<Media::PixelMap> sharedPixelMap = std::move(pixelMap);
    CompositionEffectInfo info { .compositionId_ = compositionId,
        .compositionPointIndex_ = compositionPointIndex,
        .compositionReasons_ = compositionReasons,
        .compositionImage_ = sharedPixelMap };
    if (auto compositionFeature = compositionFeature_.lock()) {
        if (compositionFeature->compositionEffectReceiveCallback_ != nullptr) {
            compositionFeature->compositionEffectReceiveCallback_->OnInfoChanged(info);
        } else {
            MEDIA_ERR_LOG("CompositionEffectListener::OnBufferAvailable compositionEffectReceiveCallback_ is nullptr");
        }
    }
    surface->ReleaseBuffer(buffer, -1);
}

std::unique_ptr<Media::PixelMap> CompositionEffectListener::Buffer2PixelMap(sptr<SurfaceBuffer> buffer)
{
    MEDIA_INFO_LOG("CompositionEffectListener::Buffer2PixelMap enter");
    CHECK_RETURN_RET_WLOG(
        buffer == nullptr, nullptr, "CompositionEffectListener::Buffer2PixelMap buffer is nullptr, return");
    MEDIA_INFO_LOG("CompositionEffectListener::Buffer2PixelMap surface width: %{public}d, height: "
                   "%{public}d, stride: %{public}d, size: %{public}d, format: %{public}d, usage: %{public}" PRIu64,
        buffer->GetWidth(), buffer->GetHeight(), buffer->GetStride(), buffer->GetSize(), buffer->GetFormat(),
        buffer->GetUsage());
    Media::InitializationOptions opts {
        .size = { .width = buffer->GetWidth(), .height = buffer->GetHeight() },
        .srcPixelFormat = Media::PixelFormat::NV21,
        .pixelFormat = Media::PixelFormat::RGBA_8888,
    };

    std::unique_ptr<Media::PixelMap> pixelMap =
        Media::PixelMap::Create(static_cast<const uint32_t*>(buffer->GetVirAddr()),
            buffer->GetStride() * buffer->GetHeight() * 3 / 2, 0, buffer->GetStride(), opts, true);
    return pixelMap;
};

} // namespace CameraStandard
} // namespace OHOS