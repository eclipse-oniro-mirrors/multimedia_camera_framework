/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "output/photo_output.h"

#include <mutex>
#include <securec.h>

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "hstream_capture_callback_stub.h"
#include "input/camera_device.h"
#include "metadata_common_utils.h"
#include "session/capture_session.h"
#include "session/night_session.h"

using namespace std;

namespace OHOS {
namespace CameraStandard {
PhotoCaptureSetting::PhotoCaptureSetting()
{
    int32_t items = 10;
    int32_t dataLength = 100;
    captureMetadataSetting_ = std::make_shared<Camera::CameraMetadata>(items, dataLength);
}

PhotoCaptureSetting::QualityLevel PhotoCaptureSetting::GetQuality()
{
    QualityLevel quality = QUALITY_LEVEL_LOW;
    camera_metadata_item_t item;

    int ret = Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_QUALITY, &item);
    if (ret != CAM_META_SUCCESS) {
        return QUALITY_LEVEL_MEDIUM;
    }
    if (item.data.u8[0] == OHOS_CAMERA_JPEG_LEVEL_HIGH) {
        quality = QUALITY_LEVEL_HIGH;
    } else if (item.data.u8[0] == OHOS_CAMERA_JPEG_LEVEL_MIDDLE) {
        quality = QUALITY_LEVEL_MEDIUM;
    }
    return quality;
}

void PhotoCaptureSetting::SetQuality(PhotoCaptureSetting::QualityLevel qualityLevel)
{
    bool status = false;
    camera_metadata_item_t item;
    uint8_t quality = OHOS_CAMERA_JPEG_LEVEL_LOW;

    if (qualityLevel == QUALITY_LEVEL_HIGH) {
        quality = OHOS_CAMERA_JPEG_LEVEL_HIGH;
    } else if (qualityLevel == QUALITY_LEVEL_MEDIUM) {
        quality = OHOS_CAMERA_JPEG_LEVEL_MIDDLE;
    }
    int ret = Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_QUALITY, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = captureMetadataSetting_->addEntry(OHOS_JPEG_QUALITY, &quality, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = captureMetadataSetting_->updateEntry(OHOS_JPEG_QUALITY, &quality, 1);
    }

    if (!status) {
        MEDIA_ERR_LOG("PhotoCaptureSetting::SetQuality Failed to set Quality");
    }
}

PhotoCaptureSetting::RotationConfig PhotoCaptureSetting::GetRotation()
{
    RotationConfig rotation;
    camera_metadata_item_t item;

    int ret = Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION, &item);
    if (ret == CAM_META_SUCCESS) {
        rotation = static_cast<RotationConfig>(item.data.i32[0]);
        return rotation;
    }
    return RotationConfig::Rotation_0;
}

void PhotoCaptureSetting::SetRotation(PhotoCaptureSetting::RotationConfig rotationValue)
{
    bool status = false;
    camera_metadata_item_t item;
    int32_t rotation = rotationValue;

    int ret = Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_ORIENTATION, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = captureMetadataSetting_->addEntry(OHOS_JPEG_ORIENTATION, &rotation, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = captureMetadataSetting_->updateEntry(OHOS_JPEG_ORIENTATION, &rotation, 1);
    }

    if (!status) {
        MEDIA_ERR_LOG("PhotoCaptureSetting::SetRotation Failed to set Rotation");
    }
    return;
}

void PhotoCaptureSetting::SetGpsLocation(double latitude, double longitude)
{
    std::unique_ptr<Location> location = std::make_unique<Location>();
    if (location == nullptr) {
        return;
    }
    location->latitude = latitude;
    location->longitude = longitude;
    location->altitude = 0;
    SetLocation(location);
}

void PhotoCaptureSetting::SetLocation(std::unique_ptr<Location>& location)
{
    if (location == nullptr) {
        return;
    }
    double gpsCoordinates[3] = {location->latitude, location->longitude, location->altitude};
    bool status = false;
    camera_metadata_item_t item;

    MEDIA_DEBUG_LOG("PhotoCaptureSetting::SetLocation lat=%{public}f, long=%{public}f and alt=%{public}f",
        location->latitude, location->longitude, location->altitude);
    int ret = Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_GPS_COORDINATES, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = captureMetadataSetting_->addEntry(
            OHOS_JPEG_GPS_COORDINATES, gpsCoordinates, sizeof(gpsCoordinates) / sizeof(gpsCoordinates[0]));
    } else if (ret == CAM_META_SUCCESS) {
        status = captureMetadataSetting_->updateEntry(
            OHOS_JPEG_GPS_COORDINATES, gpsCoordinates, sizeof(gpsCoordinates) / sizeof(gpsCoordinates[0]));
    }

    if (!status) {
        MEDIA_ERR_LOG("PhotoCaptureSetting::SetLocation Failed to set GPS co-ordinates");
    }
}

void PhotoCaptureSetting::SetMirror(bool enable)
{
    bool status = false;
    camera_metadata_item_t item;
    uint8_t mirror = enable;

    MEDIA_DEBUG_LOG("PhotoCaptureSetting::SetMirror value=%{public}d", enable);
    int ret = Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_CONTROL_CAPTURE_MIRROR, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = captureMetadataSetting_->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, &mirror, 1);
    } else if (ret == CAM_META_SUCCESS) {
        status = captureMetadataSetting_->updateEntry(OHOS_CONTROL_CAPTURE_MIRROR, &mirror, 1);
    }

    if (!status) {
        MEDIA_ERR_LOG("PhotoCaptureSetting::SetMirror Failed to set mirroring in photo capture setting");
    }
    return;
}

bool PhotoCaptureSetting::GetMirror()
{
    bool isMirror;
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_CONTROL_CAPTURE_MIRROR, &item);
    if (ret == CAM_META_SUCCESS) {
        isMirror = static_cast<bool>(item.data.u8[0]);
        return isMirror;
    }
    return false;
}

std::shared_ptr<Camera::CameraMetadata> PhotoCaptureSetting::GetCaptureMetadataSetting()
{
    return captureMetadataSetting_;
}

int32_t HStreamCaptureCallbackImpl::OnCaptureStarted(const int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    if (photoOutput == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureStarted photoOutput is nullptr");
        return CAMERA_OK;
    }
    auto callback = photoOutput->GetApplicationCallback();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureStarted callback is nullptr");
        return CAMERA_OK;
    }

    sptr<CaptureSession> captureSession = photoOutput->GetSession();
    switch (captureSession->GetMode()) {
        case SceneMode::HIGH_RES_PHOTO: {
            auto inputDevice = captureSession->GetInputDevice();
            if (inputDevice == nullptr) {
                MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureStarted inputDevice is nullptr");
                return CAMERA_OK;
            }
            sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
            std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
            camera_metadata_item_t meta;
            int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAPTURE_EXPECT_TIME, &meta);
            if (ret == CAM_META_SUCCESS) {
                photoOutput->GetApplicationCallback()->OnCaptureStarted(captureId, meta.data.ui32[1]);
            } else {
                MEDIA_WARNING_LOG("Discarding OnCaptureStarted callback, mode:%{public}d."
                                  "exposureTime is not found",
                    meta.data.ui32[0]);
            }
            break;
        }
        default:
            photoOutput->GetApplicationCallback()->OnCaptureStarted(captureId);
            break;
    }
    return CAMERA_OK;
}

int32_t HStreamCaptureCallbackImpl::OnCaptureStarted(const int32_t captureId, uint32_t exposureTime)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    if (photoOutput == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureStarted photoOutput is nullptr");
        return CAMERA_OK;
    }
    auto callback = photoOutput->GetApplicationCallback();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureStarted callback is nullptr");
        return CAMERA_OK;
    }
    photoOutput->GetApplicationCallback()->OnCaptureStarted(captureId, exposureTime);
    return CAMERA_OK;
}

int32_t HStreamCaptureCallbackImpl::OnCaptureEnded(const int32_t captureId, const int32_t frameCount)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    if (photoOutput == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureEnded photoOutput is nullptr");
        return CAMERA_OK;
    }
    auto callback = photoOutput->GetApplicationCallback();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureEnded callback is nullptr");
        return CAMERA_OK;
    }
    callback->OnCaptureEnded(captureId, frameCount);
    return CAMERA_OK;
}

int32_t HStreamCaptureCallbackImpl::OnCaptureError(const int32_t captureId, const int32_t errorCode)
{
    auto photoOutput = GetPhotoOutput();
    if (photoOutput == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureError photoOutput is nullptr");
        return CAMERA_OK;
    }
    auto callback = photoOutput->GetApplicationCallback();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureError callback is nullptr");
        return CAMERA_OK;
    }
    callback->OnCaptureError(captureId, errorCode);
    return CAMERA_OK;
}

int32_t HStreamCaptureCallbackImpl::OnFrameShutter(const int32_t captureId, const uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    if (photoOutput == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnFrameShutter photoOutput is nullptr");
        return CAMERA_OK;
    }
    auto callback = photoOutput->GetApplicationCallback();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnFrameShutter callback is nullptr");
        return CAMERA_OK;
    }
    callback->OnFrameShutter(captureId, timestamp);
    return CAMERA_OK;
}

int32_t HStreamCaptureCallbackImpl::OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    if (photoOutput == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnFrameShutter photoOutput is nullptr");
        return CAMERA_OK;
    }
    auto callback = photoOutput->GetApplicationCallback();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnFrameShutter callback is nullptr");
        return CAMERA_OK;
    }
    callback->OnFrameShutterEnd(captureId, timestamp);
    return CAMERA_OK;
}

int32_t HStreamCaptureCallbackImpl::OnCaptureReady(const int32_t captureId, const uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    if (photoOutput == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureReady photoOutput is nullptr");
        return CAMERA_OK;
    }
    auto callback = photoOutput->GetApplicationCallback();
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamCaptureCallbackImpl::OnCaptureReady callback is nullptr");
        return CAMERA_OK;
    }
    callback->OnCaptureReady(captureId, timestamp);
    return CAMERA_OK;
}

PhotoOutput::PhotoOutput(sptr<IBufferProducer> bufferProducer)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_PHOTO, StreamType::CAPTURE, bufferProducer, nullptr)
{
    defaultCaptureSetting_ = nullptr;
}

PhotoOutput::~PhotoOutput()
{
    MEDIA_DEBUG_LOG("Enter Into PhotoOutput::~PhotoOutput()");
    defaultCaptureSetting_ = nullptr;
}

void PhotoOutput::SetNativeSurface(bool isNativeSurface)
{
    MEDIA_INFO_LOG("Enter Into SetNativeSurface: %{public}d", isNativeSurface);
    isNativeSurface_ = isNativeSurface;
}

void PhotoOutput::SetCallbackFlag(uint8_t callbackFlag)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (!isNativeSurface_) {
        MEDIA_INFO_LOG("SetCallbackFlag when register imageReciver");
        return;
    }
    bool beforeStatus = IsEnableDeferred();
    callbackFlag_ = callbackFlag;
    bool afterStatus = IsEnableDeferred();
    // if session is commit or start, and isEnableDeferred is oppsite, need to restart session config
    auto session = GetSession();
    if (beforeStatus != afterStatus && session) {
        if (session->IsSessionStarted()) {
            MEDIA_INFO_LOG("session restart when callback status changed");
            session->BeginConfig();
            session->CommitConfig();
            session->Start();
        } else if (session->IsSessionCommited()) {
            MEDIA_INFO_LOG("session recommit when callback status changed");
            session->BeginConfig();
            session->CommitConfig();
        }
    }
}

bool PhotoOutput::IsEnableDeferred()
{
    if (!isNativeSurface_) {
        return false;
    }
    bool isEnabled = (callbackFlag_ & CAPTURE_PHOTO_ASSET) != 0 || (callbackFlag_ & CAPTURE_PHOTO) == 0;
    MEDIA_INFO_LOG("Enter Into PhotoOutput::IsEnableDeferred %{public}d", isEnabled);
    return isEnabled;
}

void PhotoOutput::SetCallback(std::shared_ptr<PhotoStateCallback> callback)
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appCallback_ = callback;
    if (appCallback_ != nullptr) {
        if (cameraSvcCallback_ == nullptr) {
            cameraSvcCallback_ = new (std::nothrow) HStreamCaptureCallbackImpl(this);
            if (cameraSvcCallback_ == nullptr) {
                MEDIA_ERR_LOG("PhotoOutput::SetCallback new HStreamCaptureCallbackImpl Failed to register callback");
                appCallback_ = nullptr;
                return;
            }
        }
        auto itemStream = static_cast<IStreamCapture*>(GetStream().GetRefPtr());
        int32_t errorCode = CAMERA_OK;
        if (itemStream) {
            errorCode = itemStream->SetCallback(cameraSvcCallback_);
        } else {
            MEDIA_ERR_LOG("PhotoOutput::SetCallback() itemStream is nullptr");
        }
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("PhotoOutput::SetCallback: Failed to register callback, errorCode: %{public}d", errorCode);
            cameraSvcCallback_ = nullptr;
            appCallback_ = nullptr;
        }
    }
}

void PhotoOutput::SetThumbnailListener(sptr<IBufferConsumerListener>& listener)
{
    if (thumbnailSurface_) {
        SurfaceError ret = thumbnailSurface_->RegisterConsumerListener(listener);
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("PhotoOutput::SetThumbnailListener Surface consumer listener registration failed");
        }
    } else {
        MEDIA_ERR_LOG("PhotoOutput SetThumbnailListener surface is null");
    }
}

int32_t PhotoOutput::SetThumbnail(bool isEnabled)
{
    CAMERA_SYNC_TRACE;
    sptr<CameraDevice> cameraObj;
    auto captureSession = GetSession();
    if ((captureSession == nullptr)) {
        MEDIA_ERR_LOG("PhotoOutput isQuickThumbnailEnabled error!, captureSession is nullptr");
        return SESSION_NOT_RUNNING;
    }
    auto inputDevice = captureSession->GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput isQuickThumbnailEnabled error!, inputDevice is nullptr");
        return SESSION_NOT_RUNNING;
    }
    cameraObj = inputDevice->GetCameraDeviceInfo();
    if (cameraObj == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput SetThumbnail error!, cameraObj is nullptr");
        return SESSION_NOT_RUNNING;
    }
    !thumbnailSurface_ && (thumbnailSurface_ = Surface::CreateSurfaceAsConsumer("quickThumbnail"));
    if (thumbnailSurface_ == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput::SetThumbnail Failed to create surface");
        return SERVICE_FATL_ERROR;
    }
    auto streamCapturePtr = static_cast<IStreamCapture*>(GetStream().GetRefPtr());
    if (streamCapturePtr == nullptr) {
        return SERVICE_FATL_ERROR;
    }
    return streamCapturePtr->SetThumbnail(isEnabled, thumbnailSurface_->GetProducer());
}

int32_t PhotoOutput::SetRawPhotoInfo(sptr<Surface> &surface)
{
    CAMERA_SYNC_TRACE;
    auto streamCapturePtr = static_cast<IStreamCapture*>(GetStream().GetRefPtr());
    if (streamCapturePtr == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput::SetThumbnail Failed to create surface");
        return SERVICE_FATL_ERROR;
    }
    rawPhotoSurface_ = surface;
    return streamCapturePtr->SetRawPhotoStreamInfo(rawPhotoSurface_->GetProducer());
}

std::shared_ptr<PhotoStateCallback> PhotoOutput::GetApplicationCallback()
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appCallback_;
}

int32_t PhotoOutput::Capture(std::shared_ptr<PhotoCaptureSetting> photoCaptureSettings)
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("PhotoOutput Failed to Capture!, session not runing");
        return CameraErrorCode::SESSION_NOT_RUNNING;
    }
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput Failed to Capture!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    defaultCaptureSetting_ = photoCaptureSettings;
    auto itemStream = static_cast<IStreamCapture*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        MEDIA_DEBUG_LOG("Capture start");
        captureSession->StartMovingPhotoCapture(photoCaptureSettings->GetMirror(),
            photoCaptureSettings->GetRotation());
        errCode = itemStream->Capture(photoCaptureSettings->GetCaptureMetadataSetting());
        MEDIA_DEBUG_LOG("Capture End");
    } else {
        MEDIA_ERR_LOG("PhotoOutput::Capture() itemStream is nullptr");
    }
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("PhotoOutput Failed to Capture!, errCode: %{public}d", errCode);
    }
    return ServiceToCameraError(errCode);
}

int32_t PhotoOutput::Capture()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("PhotoOutput Failed to Capture!, session not runing");
        return CameraErrorCode::SESSION_NOT_RUNNING;
    }
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput Failed to Capture!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    int32_t items = 0;
    int32_t dataLength = 0;
    std::shared_ptr<Camera::CameraMetadata> captureMetadataSetting =
        std::make_shared<Camera::CameraMetadata>(items, dataLength);
    auto itemStream = static_cast<IStreamCapture*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        MEDIA_DEBUG_LOG("Capture start");
        captureSession->StartMovingPhotoCapture(false, 0);
        errCode = itemStream->Capture(captureMetadataSetting);
        MEDIA_DEBUG_LOG("Capture end");
    } else {
        MEDIA_ERR_LOG("PhotoOutput::Capture() itemStream is nullptr");
    }
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("PhotoOutput Failed to Capture!, errCode: %{public}d", errCode);
    }
    return ServiceToCameraError(errCode);
}

int32_t PhotoOutput::CancelCapture()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("PhotoOutput Failed to Capture!, session not runing");
        return CameraErrorCode::SESSION_NOT_RUNNING;
    }
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput Failed to CancelCapture!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamCapture*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->CancelCapture();
    } else {
        MEDIA_ERR_LOG("PhotoOutput::CancelCapture() itemStream is nullptr");
    }
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("PhotoOutput Failed to CancelCapture!, errCode: %{public}d", errCode);
    }
    return ServiceToCameraError(errCode);
}

int32_t PhotoOutput::ConfirmCapture()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    auto captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("PhotoOutput Failed to ConfirmCapture!, session not runing");
        return CameraErrorCode::SESSION_NOT_RUNNING;
    }
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput Failed to ConfirmCapture!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamCapture*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->ConfirmCapture();
    } else {
        MEDIA_ERR_LOG("PhotoOutput::ConfirmCapture() itemStream is nullptr");
    }
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("PhotoOutput Failed to ConfirmCapture!, errCode: %{public}d", errCode);
    }
    return ServiceToCameraError(errCode);
}

int32_t PhotoOutput::CreateStream()
{
    auto stream = GetStream();
    if (stream != nullptr) {
        MEDIA_ERR_LOG("PhotoOutput::CreateStream stream is not null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }
    auto producer = GetBufferProducer();
    if (producer == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput::CreateStream producer is null");
        return CameraErrorCode::OPERATION_NOT_ALLOWED;
    }

    sptr<IStreamCapture> streamPtr = nullptr;
    auto photoProfile = GetPhotoProfile();
    if (photoProfile == nullptr) {
        MEDIA_ERR_LOG("PreviewOutput::CreateStream photoProfile is null");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }

    int32_t res = CameraManager::GetInstance()->CreatePhotoOutputStream(streamPtr, *photoProfile, GetBufferProducer());
    if (res != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("PhotoOutput::CreateStream fail! error code :%{public}d", res);
    }
    SetStream(streamPtr);
    return res;
}

int32_t PhotoOutput::Release()
{
    {
        std::lock_guard<std::mutex> lock(outputCallbackMutex_);
        cameraSvcCallback_ = nullptr;
        appCallback_ = nullptr;
    }
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into PhotoOutput::Release");
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput Failed to Release!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    auto itemStream = static_cast<IStreamCapture*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Release();
    } else {
        MEDIA_ERR_LOG("PhotoOutput::Release() itemStream is nullptr");
    }
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("PhotoOutput Failed to release!, errCode: %{public}d", errCode);
    }
    defaultCaptureSetting_ = nullptr;
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

bool PhotoOutput::IsMirrorSupported()
{
    auto captureSession = GetSession();
    if (captureSession == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsMirrorSupported error!, captureSession is nullptr");
        return false;
    }
    auto inputDevice = captureSession->GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsMirrorSupported error!, inputDevice is nullptr");
        return false;
    }
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    if (cameraObj == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsMirrorSupported error!, cameraObj is nullptr");
        return false;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    if (metadata == nullptr) {
        return false;
    }
    bool isMirrorEnabled = false;
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    if (ret != CAM_META_SUCCESS) {
        MEDIA_WARNING_LOG("Can not find OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED");
        return isMirrorEnabled;
    }
    int step = 2;
    const int32_t canMirrorVideoAndPhoto = 2;
    const int32_t canMirrorPhotoOnly = 1;
    SceneMode currentSceneMode = captureSession->GetMode();
    for (int i = 0; i < static_cast<int>(item.count); i += step) {
        MEDIA_DEBUG_LOG("mode u8[%{public}d]: %{public}d, u8[%{public}d], %{public}d",
            i, item.data.u8[i], i + 1, item.data.u8[i + 1]);
        if (currentSceneMode == static_cast<int>(item.data.u8[i])) {
            isMirrorEnabled = (
                item.data.u8[i + 1] == canMirrorPhotoOnly ||
                item.data.u8[i + 1] == canMirrorVideoAndPhoto) ? true : false;
        }
    }
    MEDIA_DEBUG_LOG("IsMirrorSupported isSupport: %{public}d", isMirrorEnabled);
    return isMirrorEnabled;
}

int32_t PhotoOutput::IsQuickThumbnailSupported()
{
    int32_t isQuickThumbnailEnabled = -1;
    auto captureSession = GetSession();
    if (captureSession == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput isQuickThumbnailEnabled error!, captureSession is nullptr");
        return SESSION_NOT_RUNNING;
    }
    auto inputDevice = captureSession->GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput isQuickThumbnailEnabled error!, inputDevice is nullptr");
        return SESSION_NOT_RUNNING;
    }
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    if (cameraObj == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput isQuickThumbnailEnabled error!, cameraObj is nullptr");
        return SESSION_NOT_RUNNING;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    if (metadata == nullptr) {
        return SESSION_NOT_RUNNING;
    }
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_STREAM_QUICK_THUMBNAIL_AVAILABLE, &item);
    if (ret == CAM_META_SUCCESS) {
        isQuickThumbnailEnabled = (item.data.u8[0] == 1) ? 0 : -1;
    }
    const int32_t nightMode = 4;
    if (captureSession->GetMode() == nightMode && (cameraObj->GetPosition() != CAMERA_POSITION_FRONT)) {
        isQuickThumbnailEnabled = -1;
    }
    return isQuickThumbnailEnabled;
}

int32_t PhotoOutput::DeferImageDeliveryFor(DeferredDeliveryImageType type)
{
    MEDIA_INFO_LOG("PhotoOutput DeferImageDeliveryFor type:%{public}d!", type);
    CAMERA_SYNC_TRACE;
    sptr<CameraDevice> cameraObj;
    auto captureSession = GetSession();
    if ((captureSession == nullptr)) {
        MEDIA_ERR_LOG("PhotoOutput DeferImageDeliveryFor error!, captureSession is nullptr");
        return SESSION_NOT_RUNNING;
    }
    auto inputDevice = captureSession->GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput DeferImageDeliveryFor error!, inputDevice is nullptr");
        return SESSION_NOT_RUNNING;
    }

    cameraObj = inputDevice->GetCameraDeviceInfo();
    if (cameraObj == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput DeferImageDeliveryFor error!, cameraObj is nullptr");
        return SESSION_NOT_RUNNING;
    }
    captureSession->EnableDeferredType(type, true);
    captureSession->SetUserId();
    return 0;
}

int32_t PhotoOutput::IsDeferredImageDeliverySupported(DeferredDeliveryImageType type)
{
    MEDIA_INFO_LOG("IsDeferredImageDeliverySupported type:%{public}d!", type);
    int32_t isSupported = -1;
    if (type == DELIVERY_NONE) {
        return isSupported;
    }
    sptr<CameraDevice> cameraObj;
    auto captureSession = GetSession();
    if (captureSession == nullptr) {
        MEDIA_ERR_LOG("isDeferredImageDeliverySupported error!, captureSession is nullptr");
        return SESSION_NOT_RUNNING;
    }
    auto inputDevice = captureSession->GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("isDeferredImageDeliverySupported error!, inputDevice is nullptr");
        return SESSION_NOT_RUNNING;
    }
    cameraObj = inputDevice->GetCameraDeviceInfo();
    if (cameraObj == nullptr) {
        MEDIA_ERR_LOG("isDeferredImageDeliverySupported error!, cameraObj is nullptr");
        return SESSION_NOT_RUNNING;
    }

    int32_t curMode = captureSession->GetMode();
    int32_t modeSupportType = cameraObj->modeDeferredType_[curMode];
    MEDIA_INFO_LOG("IsDeferredImageDeliverySupported curMode:%{public}d, modeSupportType:%{public}d",
        curMode, modeSupportType);
    if (modeSupportType == type) {
        isSupported = 0;
    }
    return isSupported;
}

int32_t PhotoOutput::IsDeferredImageDeliveryEnabled(DeferredDeliveryImageType type)
{
    MEDIA_INFO_LOG("PhotoOutput IsDeferredImageDeliveryEnabled type:%{public}d!", type);
    int32_t isEnabled = -1;
    auto captureSession = GetSession();
    if (captureSession == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsDeferredImageDeliveryEnabled error!, captureSession is nullptr");
        return SESSION_NOT_RUNNING;
    }

    auto inputDevice = captureSession->GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsDeferredImageDeliveryEnabled error!, inputDevice is nullptr");
        return SESSION_NOT_RUNNING;
    }

    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    if (cameraObj == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsDeferredImageDeliveryEnabled error!, cameraObj is nullptr");
        return SESSION_NOT_RUNNING;
    }
    isEnabled = captureSession->IsImageDeferred() ? 0 : -1;
    return isEnabled;
}

int32_t PhotoOutput::IsAutoHighQualityPhotoSupported(int32_t &isAutoHighQualityPhotoSupported)
{
    MEDIA_INFO_LOG("PhotoOutput IsAutoHighQualityPhotoSupported is called");
    isAutoHighQualityPhotoSupported = -1;
    camera_metadata_item_t item;
    sptr<CameraDevice> cameraObj;
    auto captureSession = GetSession();
    if (captureSession == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsAutoHighQualityPhotoSupported error!, captureSession is nullptr");
        return SESSION_NOT_RUNNING;
    }
    auto inputDevice = captureSession->GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsAutoHighQualityPhotoSupported error!, inputDevice is nullptr");
        return SESSION_NOT_RUNNING;
    }
    cameraObj = inputDevice->GetCameraDeviceInfo();
    if (cameraObj == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsAutoHighQualityPhotoSupported error!, cameraObj is nullptr");
        return SESSION_NOT_RUNNING;
    }
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    if (metadata == nullptr) {
        return SESSION_NOT_RUNNING;
    }
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_HIGH_QUALITY_SUPPORT, &item);
    if (ret == CAM_META_SUCCESS) {
        isAutoHighQualityPhotoSupported = (item.data.u8[1] == 1) ? 0 : -1; // default mode
    }

    int headLenPerMode = 2;
    SceneMode currentSceneMode = captureSession->GetMode();
    for (int i = 0; i < static_cast<int>(item.count); i += headLenPerMode) {
        if (currentSceneMode == static_cast<int>(item.data.u8[i])) {
            isAutoHighQualityPhotoSupported = (item.data.u8[i + 1] == 1) ? 0 : -1;
        }
    }
    MEDIA_INFO_LOG("PhotoOutput IsAutoHighQualityPhotoSupported curMode:%{public}d, modeSupportType:%{public}d",
        currentSceneMode, isAutoHighQualityPhotoSupported);
    return CAMERA_OK;
}

int32_t PhotoOutput::EnableAutoHighQualityPhoto(bool enabled)
{
    MEDIA_DEBUG_LOG("PhotoOutput EnableAutoHighQualityPhoto");
    auto captureSession = GetSession();
    if (captureSession == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsAutoHighQualityPhotoSupported error!, captureSession is nullptr");
        return SESSION_NOT_RUNNING;
    }
    auto inputDevice = captureSession->GetInputDevice();
    if (inputDevice == nullptr) {
        MEDIA_ERR_LOG("PhotoOutput IsAutoHighQualityPhotoSupported error!, inputDevice is nullptr");
        return SESSION_NOT_RUNNING;
    }
    int32_t isAutoHighQualityPhotoSupported;
    int32_t ret = IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("PhotoOutput EnableAutoHighQualityPhoto error");
        return OPERATION_NOT_ALLOWED;
    }

    if (isAutoHighQualityPhotoSupported == -1) {
        MEDIA_ERR_LOG("PhotoOutput EnableAutoHighQualityPhoto not supported");
        return INVALID_ARGUMENT;
    }

    int32_t res = captureSession->EnableAutoHighQualityPhoto(enabled);
    return res;
}

void PhotoOutput::ProcessSnapshotDurationUpdates(int32_t snapshotDuration) __attribute__((no_sanitize("cfi")))
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    if (appCallback_ != nullptr) {
        MEDIA_DEBUG_LOG("appCallback not nullptr");
        appCallback_->OnEstimatedCaptureDuration(snapshotDuration);
    }
}

std::shared_ptr<PhotoCaptureSetting> PhotoOutput::GetDefaultCaptureSetting()
{
    return defaultCaptureSetting_;
}

void PhotoOutput::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    if (appCallback_ != nullptr) {
        MEDIA_DEBUG_LOG("appCallback not nullptr");
        int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
        int32_t captureId = -1;
        appCallback_->OnCaptureError(captureId, serviceErrorType);
    }
}
} // namespace CameraStandard
} // namespace OHOS
