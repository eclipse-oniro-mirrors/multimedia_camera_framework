/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include <cstdint>

#include "camera_log.h"
#include "camera_manager.h"
#include "session/stitching_photo_session.h"
#include "video_key_info.h"

namespace OHOS {
namespace CameraStandard {
StitchingPhotoSession::StitchingPhotoSession(sptr<ICaptureSession>& session)
    : CaptureSessionForSys(session)
{
    metadataResultProcessor_ = std::make_shared<StitchingPhotoSessionMetadataResultProcessor>(this);
    // create surface
    stitchingSurface_ = IConsumerSurface::Create();
    CHECK_RETURN_ELOG(stitchingSurface_ == nullptr, "%{public}s surface is null", __PRETTY_FUNCTION__);

    // create surface and register listener
    sptr<IBufferConsumerListener> stitchingSurfaceListener = new StitchingSurfaceListener(this, stitchingSurface_);
    CHECK_RETURN_ELOG(stitchingSurfaceListener == nullptr, "%{public}s surfaceLister is null", __PRETTY_FUNCTION__);
    stitchingSurface_->RegisterConsumerListener(stitchingSurfaceListener);
}

StitchingPhotoSession::~StitchingPhotoSession()
{
    CHECK_RETURN(stitchingSurface_ == nullptr);
    stitchingSurface_->UnregisterConsumerListener();
}

int32_t StitchingPhotoSession::AddOutput(sptr<CaptureOutput>& output)
{
    int32_t result = CameraErrorCode::SUCCESS;
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "ScanSession::AddOutput get nullptr to inputDevice");
    result = CaptureSessionForSys::AddOutput(output);
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_PREVIEW) {
        Size size { 238, 1062 };
        auto profileFormat = CameraFormat::CAMERA_FORMAT_RGBA_8888;
        bool isSucc = CreateStitchingPreviewOutput(this, size, profileFormat);
        CHECK_RETURN_RET_ELOG(!isSucc, CameraErrorCode::OPERATION_NOT_ALLOWED,
            "%{public}s failed to CreateStitchingPreviewOutput", __PRETTY_FUNCTION__);
    }
    return result;
}

bool StitchingPhotoSession::CreateStitchingPreviewOutput(
    wptr<StitchingPhotoSession> pStitchingPhotoSession, const Size& size, const CameraFormat& profileFormat)
{
    CHECK_RETURN_RET_ELOG(
        stitchingSurface_ == nullptr, false, "%{public}s stitchingSurface_ is nullptr", __PRETTY_FUNCTION__);

    // create profile
    Profile profile(profileFormat, size);

    // create preview output
    stitchingSurface_->SetUserData(CameraManager::surfaceFormat, std::to_string(profile.GetCameraFormat()));
    sptr<PreviewOutput> previewOutput = nullptr;
    int retCode = CameraManager::GetInstance()->CreatePreviewOutput(profile, stitchingSurface_, &previewOutput);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS || previewOutput == nullptr, false,
        "%{public}s fail to create previewOutput, ret: %{public}d", __PRETTY_FUNCTION__, retCode);

    sptr<CaptureOutput> pPreviewOutput = previewOutput;
    CaptureSessionForSys::AddOutput(pPreviewOutput, false);

    // enable stitching stream
    auto pCommonStream = previewOutput->GetStream().GetRefPtr();
    CHECK_RETURN_RET_ELOG(!pCommonStream, false, "%{public}s pCommonStream is nullptr", __PRETTY_FUNCTION__);

    retCode = static_cast<IStreamRepeat*>(pCommonStream)->EnableStitching(true);
    CHECK_RETURN_RET_ELOG(retCode != NO_ERROR, false, "%{public}s EnableStitching fail", __PRETTY_FUNCTION__);

    return true;
}

bool StitchingPhotoSession::CanAddOutput(sptr<CaptureOutput>& output)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    CHECK_RETURN_RET_ELOG(
        !IsSessionConfiged() || output == nullptr, false, "%{public}s operation is not allowed!", __PRETTY_FUNCTION__);
    return CaptureSessionForSys::CanAddOutput(output);
}

int32_t StitchingPhotoSession::SetStitchingType(StitchingType type)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "%{public}s Session is not Commited", __PRETTY_FUNCTION__);
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "%{public}s need to call LockForControl() before setting camera properties", __PRETTY_FUNCTION__);

    uint8_t uType = static_cast<uint8_t>(StitchingType::LONG_SCROLL);
    auto itr = fwkStitchingTypeMap_.find(type);
    CHECK_RETURN_RET_ELOG(itr == fwkStitchingTypeMap_.end(), CameraErrorCode::PARAMETER_ERROR,
        "%{public}s map failed, %{public}u", __PRETTY_FUNCTION__, uType);
    uType = itr->second;
    MEDIA_DEBUG_LOG("%{public}s set value: %{public}u", __PRETTY_FUNCTION__, uType);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_PHOTO_STITCHING_TYPE, &uType, 1);
    CHECK_PRINT_ELOG(!status, "%{public}s Failed to set value", __PRETTY_FUNCTION__);
    return CameraErrorCode::SUCCESS;
}

int32_t StitchingPhotoSession::GetStitchingType(StitchingType& type)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "%{public}s is not Commited", __PRETTY_FUNCTION__);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "%{public}s camera device is null", __PRETTY_FUNCTION__);
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "%{public}s camera deviceInfo is null", __PRETTY_FUNCTION__);
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "%{public}s camera metadata is null", __PRETTY_FUNCTION__);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_PHOTO_STITCHING_TYPE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "%{public}s failed with return code %{public}d", __PRETTY_FUNCTION__, ret);
    type = static_cast<StitchingType>(item.data.u8[0]);
    return CameraErrorCode::SUCCESS;
}

int32_t StitchingPhotoSession::SetStitchingDirection(StitchingDirection direction)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "%{public}s Session is not Commited", __PRETTY_FUNCTION__);
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "%{public}s need to call LockForControl() before setting camera properties", __PRETTY_FUNCTION__);

    uint8_t uDirection = static_cast<uint8_t>(StitchingDirection::LANDSCAPE);
    auto itr = fwkStitchingDirectionMap_.find(direction);
    CHECK_RETURN_RET_ELOG(itr == fwkStitchingDirectionMap_.end(), CameraErrorCode::PARAMETER_ERROR,
        "%{public}s map failed, %{public}u", __PRETTY_FUNCTION__, uDirection);
    uDirection = itr->second;
    MEDIA_DEBUG_LOG("%{public}s set value: %{public}u", __PRETTY_FUNCTION__, uDirection);
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_PHOTO_STITCHING_DIRECTION, &uDirection, 1);
    CHECK_PRINT_ELOG(!status, "%{public}s Failed to set value", __PRETTY_FUNCTION__);
    return CameraErrorCode::SUCCESS;
}

int32_t StitchingPhotoSession::GetStitchingDirection(StitchingDirection& direction)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "%{public}s is not Commited", __PRETTY_FUNCTION__);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "%{public}s camera device is null", __PRETTY_FUNCTION__);
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "%{public}s camera deviceInfo is null", __PRETTY_FUNCTION__);
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "%{public}s camera metadata is null", __PRETTY_FUNCTION__);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_PHOTO_STITCHING_DIRECTION, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "%{public}s failed with return code %{public}d", __PRETTY_FUNCTION__, ret);
    direction = static_cast<StitchingDirection>(item.data.u8[0]);
    return CameraErrorCode::SUCCESS;
}

int32_t StitchingPhotoSession::SetMovingClockwise(bool enable)
{
    CAMERA_SYNC_TRACE;
    CHECK_RETURN_RET_ELOG(!(IsSessionCommited() || IsSessionConfiged()), CameraErrorCode::SESSION_NOT_CONFIG,
        "%{public}s Session is not Commited", __PRETTY_FUNCTION__);
    CHECK_RETURN_RET_ELOG(changedMetadata_ == nullptr, CameraErrorCode::SUCCESS,
        "%{public}s need to call LockForControl() before setting camera properties", __PRETTY_FUNCTION__);
    MEDIA_DEBUG_LOG("%{public}s set value: %{public}d", __PRETTY_FUNCTION__, enable);
    uint8_t uEnable = enable;
    bool status = AddOrUpdateMetadata(changedMetadata_, OHOS_CONTROL_PHOTO_STITCHING_MOVING_CLOCKWISE, &uEnable, 1);
    CHECK_PRINT_ELOG(!status, "%{public}s Failed to set value", __PRETTY_FUNCTION__);
    return CameraErrorCode::SUCCESS;
}

int32_t StitchingPhotoSession::GetMovingClockwise(bool& enable)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    CHECK_RETURN_RET_ELOG(
        !IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG, "%{public}s is not Commited", __PRETTY_FUNCTION__);
    auto inputDevice = GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        !inputDevice, CameraErrorCode::SUCCESS, "%{public}s camera device is null", __PRETTY_FUNCTION__);
    auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        !inputDeviceInfo, CameraErrorCode::SUCCESS, "%{public}s camera deviceInfo is null", __PRETTY_FUNCTION__);
    std::shared_ptr<Camera::CameraMetadata> metadata = inputDeviceInfo->GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, CameraErrorCode::SUCCESS, "%{public}s camera metadata is null", __PRETTY_FUNCTION__);
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_PHOTO_STITCHING_MOVING_CLOCKWISE, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS || item.count == 0, CameraErrorCode::SUCCESS,
        "%{public}s failed with return code %{public}d", __PRETTY_FUNCTION__, ret);
    enable = static_cast<bool>(item.data.u8[0]);
    return CameraErrorCode::SUCCESS;
}

int32_t StitchingPhotoSession::SetStitchingTargetInfoCallback(std::shared_ptr<StitchingTargetInfoCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    stitchingTargetInfoCallback_ = callback;
    return CameraErrorCode::SUCCESS;
}

int32_t StitchingPhotoSession::SetStitchingCaptureInfoCallback(std::shared_ptr<StitchingCaptureInfoCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    stitchingCaptureInfoCallback_ = callback;
    return CameraErrorCode::SUCCESS;
}

int32_t StitchingPhotoSession::SetStitchingHintInfoCallback(std::shared_ptr<StitchingHintInfoCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    stitchingHintInfoCallback_ = callback;
    return CameraErrorCode::SUCCESS;
}

int32_t StitchingPhotoSession::SetStitchingCaptureStateCallback(std::shared_ptr<StitchingCaptureStateCallback> callback)
{
    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    stitchingCaptureStateCallback_.Set(callback);
    return CameraErrorCode::SUCCESS;
}

void StitchingPhotoSession::ProcessStitchingTargetChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    camera_metadata_item_t itemPosition;
    camera_metadata_item_t itemAngle;
    common_metadata_header_t* metadata = result->get();
    int retPosition = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_PHOTO_STITCHING_POSITION, &itemPosition);
    int retAngle = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_PHOTO_STITCHING_ANGLE, &itemAngle);
    bool isMetadataItemFound = retPosition != CAM_META_SUCCESS || retAngle != CAM_META_SUCCESS;
    CHECK_PRINT_WLOG(isMetadataItemFound,
        "%{public}s FindCameraMetadataItem retPostion: %{public}d, retAngle: %{public}d", __PRETTY_FUNCTION__,
        retPosition, retAngle);
    CHECK_RETURN_ELOG(retPosition != CAM_META_SUCCESS && retAngle != CAM_META_SUCCESS,
        "%{public}s find item fail, return", __PRETTY_FUNCTION__);

    std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
    StitchingTargetInfo info { .positions_ = {}, .angle_ = 0 };
    if (retPosition == CAM_META_SUCCESS) {
        uint32_t dataCount = itemPosition.count;
        const int two = 2;
        bool isOdd = dataCount % two;
        CHECK_RETURN_ELOG(
            isOdd, "%{public}s invalid position array length: %{public}u", __PRETTY_FUNCTION__, dataCount);

        auto& pointArray = itemPosition.data.f;
        for (uint32_t i = 0; i < dataCount; ++i) {
            info.positions_.emplace_back(pointArray[i]);
        }
    }
    if (retAngle == CAM_META_SUCCESS && itemAngle.data.f != nullptr && itemAngle.count) {
        info.angle_ = itemAngle.data.f[0];
    }

    bool canSetInfoCallback = stitchingTargetInfoCallback_ != nullptr &&
        (stitchingTargetInfoRecord_ == nullptr || info != *stitchingTargetInfoRecord_);

    CHECK_RETURN(!canSetInfoCallback);
    MEDIA_INFO_LOG("%{public}s angle: %{public}f", __PRETTY_FUNCTION__, info.angle_);
    const int two = 2;
    CHECK_PRINT_ILOG(info.positions_.size() >= two, "%{public}s pos x: %{public}f, pos y: %{public}f",
        __PRETTY_FUNCTION__, info.positions_[0], info.positions_[1]);
    stitchingTargetInfoCallback_->OnInfoChanged(info);
    stitchingTargetInfoRecord_ = std::make_shared<StitchingTargetInfo>(info);
}

void StitchingPhotoSession::ProcessStitchingHintChange(const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_PHOTO_STITCHING_HINT, &item);
    bool isReported = false;
    if (ret == CAM_META_SUCCESS) {
        bool isEmpty = item.count == 0;
        if (isEmpty) {
            MEDIA_WARNING_LOG("%{public}s item.count is zero. ", __PRETTY_FUNCTION__);
        } else {
            isReported = true;
            std::lock_guard<std::mutex> lock(sessionCallbackMutex_);
            StitchingHintInfo info;
            info.hint_ = static_cast<StitchingHintInfo::StitchingHint>(item.data.u8[0]);

            bool isNeedChange = stitchingHintInfoCallback_ != nullptr &&
                (stitchingHintInfoRecord_ == nullptr || info != *stitchingHintInfoRecord_);

            if (isNeedChange) {
                MEDIA_INFO_LOG("%{public}s hint: %{public}d", __PRETTY_FUNCTION__, static_cast<int32_t>(info.hint_));
                stitchingHintInfoCallback_->OnInfoChanged(info);
                stitchingHintInfoRecord_ = std::make_shared<StitchingHintInfo>(info);
            }
        }
    }

    CHECK_RETURN(isReported);
    stitchingHintInfoRecord_ = nullptr;
}

void StitchingPhotoSession::ProcessStitchingCaptureStateChange(
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    camera_metadata_item_t item;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATUS_PHOTO_STITCHING_CAPTURE_STATE, &item);
    CHECK_RETURN_ELOG(ret != CAM_META_SUCCESS, "FindCameraMetadataItem fail.");
    auto stitchingCaptureStateCallback = stitchingCaptureStateCallback_.Get();
    CHECK_RETURN_ELOG(stitchingCaptureStateCallback == nullptr, "stitchingCaptureStateCallback is null.");
    uint32_t dataCount = item.count;
    bool isEmpty = dataCount == 0;
    CHECK_RETURN_ELOG(isEmpty, "%{public}s dataCount is zero. ", __PRETTY_FUNCTION__);
    StitchingCaptureStateInfo info;

    auto itr = metaStitchingCaptureStateSet_.find(static_cast<PhotoStitchingCaptureState>(item.data.u8[0]));
    CHECK_RETURN_DLOG(itr == metaStitchingCaptureStateSet_.end(), "capture state not found");
    info.state_ = item.data.u8[0];
    MEDIA_INFO_LOG("%{public}s hint: %{public}d", __PRETTY_FUNCTION__, info.state_);
    stitchingCaptureStateCallback->OnInfoChanged(info);
}

void StitchingPhotoSession::StitchingPhotoSessionMetadataResultProcessor::ProcessCallbacks(
    const uint64_t timestamp, const std::shared_ptr<OHOS::Camera::CameraMetadata>& result)
{
    auto session = session_.promote();
    CHECK_RETURN_ELOG(session == nullptr, "%{public}s ProcessCallbacks but session is null", __PRETTY_FUNCTION__);
    session->ProcessStitchingTargetChange(result);
    session->ProcessStitchingHintChange(result);
    session->ProcessStitchingCaptureStateChange(result);
}

const std::unordered_map<StitchingType, PhotoStitchingType> StitchingPhotoSession::fwkStitchingTypeMap_ = {
    { StitchingType::LONG_SCROLL, OHOS_CAMERA_PHOTO_STITCHING_LONG_SCROLL },
    { StitchingType::PAINTING_SCROLL, OHOS_CAMERA_PHOTO_STITCHING_PAINTING_SCROLL },
    { StitchingType::NINE_GRID, OHOS_CAMERA_PHOTO_STITCHING_NINE_GRID },
};

const std::unordered_map<PhotoStitchingType, StitchingType> StitchingPhotoSession::metaStitchingTypeMap_ = {
    { OHOS_CAMERA_PHOTO_STITCHING_LONG_SCROLL, StitchingType::LONG_SCROLL },
    { OHOS_CAMERA_PHOTO_STITCHING_PAINTING_SCROLL, StitchingType::PAINTING_SCROLL },
    { OHOS_CAMERA_PHOTO_STITCHING_NINE_GRID, StitchingType::NINE_GRID },
};

const std::unordered_map<StitchingDirection, PhotoStitchingDirection>
    StitchingPhotoSession::fwkStitchingDirectionMap_ = {
        { StitchingDirection::LANDSCAPE, OHOS_CAMERA_PHOTO_STITCHING_LANDSCAPE },
        { StitchingDirection::PORTRAIT, OHOS_CAMERA_PHOTO_STITCHING_PORTRAIT },
    };

const std::unordered_map<PhotoStitchingDirection, StitchingDirection>
    StitchingPhotoSession::metaStitchingDirectionMap_ = {
        { OHOS_CAMERA_PHOTO_STITCHING_LANDSCAPE, StitchingDirection::LANDSCAPE },
        { OHOS_CAMERA_PHOTO_STITCHING_PORTRAIT, StitchingDirection::PORTRAIT },
    };

const std::unordered_set<PhotoStitchingCaptureState> StitchingPhotoSession::metaStitchingCaptureStateSet_ = {
    OHOS_CAMERA_PHOTO_STITCHING_CAPTURE_BEGIN, OHOS_CAMERA_PHOTO_STITCHING_CAPTURE_END,
    OHOS_CAMERA_PHOTO_STITCHING_CAPTURE_COMPLETED
};

StitchingSurfaceListener::StitchingSurfaceListener(
    wptr<StitchingPhotoSession> pStitchingPhotoSession, wptr<IConsumerSurface> surface)
    : pStitchingPhotoSession_(pStitchingPhotoSession), surface_(surface) {};

void StitchingSurfaceListener::OnBufferAvailable()
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    auto surface = surface_.promote();
    CHECK_RETURN_WLOG(surface == nullptr, "surface is nullptr, return");
    sptr<SurfaceBuffer> buffer = nullptr;
    int64_t timestamp;
    OHOS::Rect damage;
    int32_t fence = -1;
    surface->AcquireBuffer(buffer, fence, timestamp, damage);
    auto pStitchingPhotoSession = pStitchingPhotoSession_.promote();
    if (pStitchingPhotoSession == nullptr) {
        surface->ReleaseBuffer(buffer, -1);
        MEDIA_ERR_LOG("StitchingSurfaceListener::OnBufferAvailable session is nullptr");
        return;
    }
    auto pixelMap = Buffer2PixelMap(buffer);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("%{public}s CreatePixelMap fail", __PRETTY_FUNCTION__);
        surface->ReleaseBuffer(buffer, -1);
        return;
    }
    std::shared_ptr<Media::PixelMap> sharedPixelMap = std::move(pixelMap);
    StitchingCaptureInfo info { .captureNumber_ = 0, .previewStitching_ = sharedPixelMap };
    CHECK_RETURN_ELOG(pStitchingPhotoSession->stitchingCaptureInfoCallback_ == nullptr,
        "%{public}s stitchingCaptureInfoCallback_ is nullptr", __PRETTY_FUNCTION__);
    pStitchingPhotoSession->stitchingCaptureInfoCallback_->OnInfoChanged(info);
    surface->ReleaseBuffer(buffer, -1);
}

std::unique_ptr<OHOS::Media::PixelMap> StitchingSurfaceListener::Buffer2PixelMap(OHOS::sptr<OHOS::SurfaceBuffer> buffer)
{
    MEDIA_INFO_LOG("%{public}s enter", __PRETTY_FUNCTION__);
    CHECK_RETURN_RET_WLOG(buffer == nullptr, nullptr, "buffer is nullptr, return");
    CHECK_RETURN_RET_WLOG(buffer->GetExtraData() == nullptr, nullptr, "buffer GetExtraData is nullptr, return");
    int32_t width;
    buffer->GetExtraData()->ExtraGet(OHOS::Camera::dataWidth, width);
    int32_t height;
    buffer->GetExtraData()->ExtraGet(OHOS::Camera::dataHeight, height);
    int32_t size;
    buffer->GetExtraData()->ExtraGet(OHOS::Camera::dataSize, size);

    MEDIA_INFO_LOG(
        "stitch surface Width:%{public}d, sketch height: %{public}d, bufSize: %{public}d", width, height, size);
    MEDIA_INFO_LOG(
        "before stitch surface Width:%{public}d, sketch height: %{public}d, bufSize: %{public}d", width, height, size);
    const int ByteSize = 4;
    if (size != width * height * ByteSize) {
        MEDIA_WARNING_LOG("size is incompatible, reset.");
        size = width * height * ByteSize;
    }
    MEDIA_INFO_LOG(
        "after stitch surface Width:%{public}d, sketch height: %{public}d, bufSize: %{public}d", width, height, size);

    Media::InitializationOptions opts {
        .size = { .width = width, .height = height },
        .srcPixelFormat = Media::PixelFormat::RGBA_8888,
        .pixelFormat = Media::PixelFormat::RGBA_8888,
    };

    std::unique_ptr<Media::PixelMap> pixelMap =
        Media::PixelMap::Create(static_cast<const uint32_t*>(buffer->GetVirAddr()), size, 0, width, opts, true);
    return pixelMap;
};

} // namespace CameraStandard
} // namespace OHOS