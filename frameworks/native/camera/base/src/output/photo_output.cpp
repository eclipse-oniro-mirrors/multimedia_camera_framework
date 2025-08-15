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

#include "photo_output_callback.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_output_capability.h"
#include "camera_util.h"
#include "capture_scene_const.h"
#include "input/camera_device.h"
#include "session/capture_session.h"
#include "picture_interface.h"
#include "task_manager.h"
#include "dp_utils.h"
#include "display/graphic/common/v1_0/cm_color_space.h"
#include "display/graphic/common/v2_1/cm_color_space.h"
#include <pixel_map.h>
using namespace std;

namespace OHOS {
namespace CameraStandard {
constexpr uint32_t CAPTURE_TIMEOUT = 1;
PhotoCaptureSetting::PhotoCaptureSetting()
{
    int32_t items = 10;
    int32_t dataLength = 100;
    captureMetadataSetting_ = std::make_shared<Camera::CameraMetadata>(items, dataLength);
    location_ = std::make_shared<Location>();
}

PhotoCaptureSetting::QualityLevel PhotoCaptureSetting::GetQuality()
{
    QualityLevel quality = QUALITY_LEVEL_LOW;
    camera_metadata_item_t item;

    int ret = Camera::FindCameraMetadataItem(captureMetadataSetting_->get(), OHOS_JPEG_QUALITY, &item);
    CHECK_RETURN_RET(ret != CAM_META_SUCCESS, QUALITY_LEVEL_MEDIUM);
    if (item.data.u8[0] == OHOS_CAMERA_JPEG_LEVEL_HIGH) {
        quality = QUALITY_LEVEL_HIGH;
    } else if (item.data.u8[0] == OHOS_CAMERA_JPEG_LEVEL_MIDDLE) {
        quality = QUALITY_LEVEL_MEDIUM;
    }
    return quality;
}

void PhotoCaptureSetting::SetQuality(PhotoCaptureSetting::QualityLevel qualityLevel)
{
    uint8_t quality = OHOS_CAMERA_JPEG_LEVEL_LOW;
    if (qualityLevel == QUALITY_LEVEL_HIGH) {
        quality = OHOS_CAMERA_JPEG_LEVEL_HIGH;
    } else if (qualityLevel == QUALITY_LEVEL_MEDIUM) {
        quality = OHOS_CAMERA_JPEG_LEVEL_MIDDLE;
    }
    bool status = AddOrUpdateMetadata(captureMetadataSetting_, OHOS_JPEG_QUALITY, &quality, 1);
    CHECK_PRINT_ELOG(!status, "PhotoCaptureSetting::SetQuality Failed to set Quality");
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
    int32_t rotation = rotationValue;
    bool status = AddOrUpdateMetadata(captureMetadataSetting_, OHOS_JPEG_ORIENTATION, &rotation, 1);
    CHECK_PRINT_ELOG(!status, "PhotoCaptureSetting::SetRotation Failed to set Rotation");
    return;
}

void PhotoCaptureSetting::SetGpsLocation(double latitude, double longitude)
{
    std::shared_ptr<Location> location = std::make_shared<Location>();
    location->latitude = latitude;
    location->longitude = longitude;
    location->altitude = 0;
    SetLocation(location);
}

void PhotoCaptureSetting::SetLocation(std::shared_ptr<Location>& location)
{
    CHECK_RETURN(location == nullptr);
    std::lock_guard<std::mutex> lock(locationMutex_);
    location_ = location;
    std::vector<double> gpsCoordinates = {location->latitude, location->longitude, location->altitude};
    MEDIA_DEBUG_LOG("PhotoCaptureSetting::SetLocation lat=%{private}f, long=%{private}f and alt=%{private}f",
        location_->latitude, location_->longitude, location_->altitude);
    bool status = AddOrUpdateMetadata(
        captureMetadataSetting_, OHOS_JPEG_GPS_COORDINATES, gpsCoordinates.data(), gpsCoordinates.size());
    CHECK_PRINT_ELOG(!status, "PhotoCaptureSetting::SetLocation Failed to set GPS co-ordinates");
}

void PhotoCaptureSetting::GetLocation(std::shared_ptr<Location>& location)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(locationMutex_);
    location = location_;
    MEDIA_DEBUG_LOG("PhotoCaptureSetting::GetLocation lat=%{private}f, long=%{private}f and alt=%{private}f",
        location->latitude, location->longitude, location->altitude);
    // LCOV_EXCL_STOP
}


void PhotoCaptureSetting::SetMirror(bool enable)
{
    uint8_t mirror = enable;
    MEDIA_DEBUG_LOG("PhotoCaptureSetting::SetMirror value=%{public}d", enable);
    bool status = AddOrUpdateMetadata(captureMetadataSetting_, OHOS_CONTROL_CAPTURE_MIRROR, &mirror, 1);
    CHECK_PRINT_ELOG(!status, "PhotoCaptureSetting::SetMirror Failed to set mirroring in photo capture setting");
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

void PhotoCaptureSetting::SetBurstCaptureState(uint8_t burstState)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("SetBurstCaptureState");
    bool status = AddOrUpdateMetadata(captureMetadataSetting_, OHOS_CONTROL_BURST_CAPTURE, &burstState, 1);
    CHECK_PRINT_ELOG(!status, "PhotoCaptureSetting::SetBurstCaptureState Failed");
    return;
}

int32_t HStreamCaptureCallbackImpl::OnCaptureStarted(const int32_t captureId)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureStarted photoOutput is nullptr");
    auto callback = photoOutput->GetApplicationCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureStarted callback is nullptr");

    // LCOV_EXCL_START
    sptr<CaptureSession> session = photoOutput->GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureStarted session is nullptr");
    switch (session->GetMode()) {
        case SceneMode::HIGH_RES_PHOTO: {
            auto inputDevice = session->GetInputDevice();
            CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CAMERA_OK,
                "HStreamCaptureCallbackImpl::OnCaptureStarted inputDevice is nullptr");
            sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
            CHECK_RETURN_RET_ELOG(cameraObj == nullptr, CAMERA_OK,
                "HStreamCaptureCallbackImpl::OnCaptureStarted cameraObj is nullptr");
            std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
            CHECK_RETURN_RET_ELOG(metadata == nullptr, CAMERA_OK,
                "HStreamCaptureCallbackImpl::OnCaptureStarted metadata is nullptr");
            camera_metadata_item_t meta;
            int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CAPTURE_EXPECT_TIME, &meta);
            const int32_t CONST_2 = 2;
            if (ret == CAM_META_SUCCESS && meta.count >= CONST_2) {
                callback->OnCaptureStarted(captureId, meta.data.ui32[1]);
            } else if (meta.count) {
                MEDIA_WARNING_LOG("Discarding OnCaptureStarted callback, mode:%{public}d. exposureTime is not found",
                    meta.data.ui32[0]);
            } else {
                MEDIA_WARNING_LOG("Discarding OnCaptureStarted callback, mode and exposureTime are not found");
            }
            break;
        }
        default:
            callback->OnCaptureStarted(captureId);
            break;
    }
    // LCOV_EXCL_STOP
    return CAMERA_OK;
}

int32_t HStreamCaptureCallbackImpl::OnCaptureStarted(const int32_t captureId, uint32_t exposureTime)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureStarted photoOutput is nullptr");
    auto callback = photoOutput->GetApplicationCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureStarted callback is nullptr");
    // LCOV_EXCL_START
    photoOutput->GetApplicationCallback()->OnCaptureStarted(captureId, exposureTime);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCaptureCallbackImpl::OnCaptureEnded(const int32_t captureId, const int32_t frameCount)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureEnded photoOutput is nullptr");
    auto callback = photoOutput->GetApplicationCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureEnded callback is nullptr");
    // LCOV_EXCL_START
    callback->OnCaptureEnded(captureId, frameCount);
    auto timeStartIter = photoOutput->captureIdToCaptureInfoMap_.find(captureId);
    if (timeStartIter != photoOutput->captureIdToCaptureInfoMap_.end()) {
        DeferredProcessing::GetGlobalWatchdog().StopMonitor((timeStartIter->second).CaptureHandle);
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCaptureCallbackImpl::OnCaptureError(const int32_t captureId, const int32_t errorCode)
{
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureError photoOutput is nullptr");
    auto callback = photoOutput->GetApplicationCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureError callback is nullptr");
    // LCOV_EXCL_START
    callback->OnCaptureError(captureId, errorCode);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCaptureCallbackImpl::OnFrameShutter(const int32_t captureId, const uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnFrameShutter photoOutput is nullptr");
    auto callback = photoOutput->GetApplicationCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnFrameShutter callback is nullptr");
    // LCOV_EXCL_START
    callback->OnFrameShutter(captureId, timestamp);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCaptureCallbackImpl::OnFrameShutterEnd(const int32_t captureId, const uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnFrameShutterEnd photoOutput is nullptr");
    auto callback = photoOutput->GetApplicationCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnFrameShutterEnd callback is nullptr");
    // LCOV_EXCL_START
    callback->OnFrameShutterEnd(captureId, timestamp);
    CHECK_RETURN_RET(!photoOutput->IsHasEnableOfflinePhoto(), CAMERA_OK);
    uint32_t startCaptureHandle;
    constexpr uint32_t delayMilli = 10 * 1000; // 10S 1000 is ms
    MEDIA_INFO_LOG("offline GetGlobalWatchdog StartMonitor, captureId=%{public}d", captureId);
    DeferredProcessing::GetGlobalWatchdog().StartMonitor(
        startCaptureHandle, delayMilli, [captureId, photoOutput](uint32_t handle) {
            MEDIA_INFO_LOG("offline Watchdog executed, handle: %{public}d, captureId= %{public}d",
                static_cast<int>(handle), captureId);
            CHECK_RETURN_ELOG(photoOutput == nullptr, "photoOutput is release");
            bool canRelease =
                photoOutput->IsHasSwitchOfflinePhoto() && (photoOutput->captureIdToCaptureInfoMap_).size() == 0;
            CHECK_EXECUTE(canRelease, photoOutput->Release());
        });
    photoOutput->captureIdToCaptureInfoMap_[captureId].CaptureHandle = static_cast<int32_t>(startCaptureHandle);
    photoOutput->captureIdToCaptureInfoMap_[captureId].timeStart = std::chrono::steady_clock::now();
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCaptureCallbackImpl::OnCaptureReady(const int32_t captureId, const uint64_t timestamp)
{
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureReady photoOutput is nullptr");
    auto callback = photoOutput->GetApplicationCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnCaptureReady callback is nullptr");
    // LCOV_EXCL_START
    callback->OnCaptureReady(captureId, timestamp);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t HStreamCaptureCallbackImpl::OnOfflineDeliveryFinished(const int32_t captureId)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto photoOutput = GetPhotoOutput();
    CHECK_RETURN_RET_ELOG(photoOutput == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnOfflineDeliveryFinished photoOutput is nullptr");
    auto callback = photoOutput->GetApplicationCallback();
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_OK,
        "HStreamCaptureCallbackImpl::OnOfflineDeliveryFinished callback is nullptr");
    callback->OnOfflineDeliveryFinished(captureId);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

PhotoOutput::PhotoOutput(sptr<IBufferProducer> bufferProducer)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_PHOTO, StreamType::CAPTURE, bufferProducer, nullptr)
{
    defaultCaptureSetting_ = nullptr;
}

PhotoOutput::PhotoOutput(sptr<IBufferProducer> bufferProducer, sptr<Surface> photoSurface)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_PHOTO, StreamType::CAPTURE, bufferProducer, nullptr)
{
    // LCOV_EXCL_START
    defaultCaptureSetting_ = nullptr;
    photoSurface_ = photoSurface;
    // LCOV_EXCL_STOP
}

PhotoOutput::PhotoOutput()
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_PHOTO, StreamType::CAPTURE, nullptr)
{
    MEDIA_INFO_LOG("new PhotoOutput");
    isSurfaceOnService_ = true;
}

PhotoOutput::~PhotoOutput()
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("Enter Into PhotoOutput::~PhotoOutput()");
    defaultCaptureSetting_ = nullptr;
    // LCOV_EXCL_STOP
}

void PhotoOutput::SetNativeSurface(bool isNativeSurface)
{
    MEDIA_INFO_LOG("Enter Into SetNativeSurface %{public}d", isNativeSurface);
    isNativeSurface_ = isNativeSurface;
}

void PhotoOutput::SetCallbackFlag(uint8_t callbackFlag)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    CHECK_RETURN_ELOG(!isNativeSurface_, "SetCallbackFlag when register imageReciver");
    // LCOV_EXCL_START
    bool beforeStatus = IsEnableDeferred();
    callbackFlag_ = callbackFlag;
    bool afterStatus = IsEnableDeferred();
    // if session is commit or start, and isEnableDeferred is oppsite, need to restart session config
    auto session = GetSession();
    if (beforeStatus != afterStatus && session) {
        FocusMode focusMode = session->GetFocusMode();
        FlashMode flashMode = session->GetFlashMode();
        MEDIA_INFO_LOG("session restart when callback status changed %{public}d, %{public}d", focusMode, flashMode);
        if (session->IsSessionStarted()) {
            session->BeginConfig();
            session->CommitConfig();
            session->LockForControl();
            session->SetFocusMode(focusMode);
            session->SetFlashMode(flashMode);
            session->UnlockForControl();
            session->Start();
        } else if (session->IsSessionCommited()) {
            MEDIA_INFO_LOG("session recommit when callback status changed");
            session->BeginConfig();
            session->CommitConfig();
            session->LockForControl();
            session->SetFocusMode(focusMode);
            session->SetFlashMode(flashMode);
            session->UnlockForControl();
        }
    }
    // LCOV_EXCL_STOP
}

bool PhotoOutput::IsYuvOrHeifPhoto()
{
    CHECK_RETURN_RET(!GetPhotoProfile(), false);
    bool ret = GetPhotoProfile()->GetCameraFormat() == CAMERA_FORMAT_YUV_420_SP;
    MEDIA_INFO_LOG("IsYuvOrHeifPhoto res = %{public}d", ret);
    return ret;
}

void PhotoOutput::SetAuxiliaryPhotoHandle(uint32_t handle)
{
    std::lock_guard<std::mutex> lock(watchDogHandleMutex_);
    watchDogHandle_ = handle;
}


uint32_t PhotoOutput::GetAuxiliaryPhotoHandle()
{
    std::lock_guard<std::mutex> lock(watchDogHandleMutex_);
    return watchDogHandle_;
}

template<typename T>
sptr<T> CastStream(sptr<IStreamCommon> streamCommon)
{
    CHECK_RETURN_RET(streamCommon == nullptr, nullptr);
    return static_cast<T*>(streamCommon.GetRefPtr());
}

void PhotoOutput::CreateMultiChannel()
{
    CAMERA_SYNC_TRACE;
    auto streamCapturePtr = CastStream<IStreamCapture>(GetStream());
    CHECK_RETURN_ELOG(
        streamCapturePtr == nullptr, "PhotoOutput::CreateMultiChannel Failed!streamCapturePtr is nullptr");
    // LCOV_EXCL_START
    std::string retStr = "";
    int32_t ret = 0;
    if (gainmapSurface_ == nullptr) {
        std::string bufferName = "gainmapImage";
        gainmapSurface_ = Surface::CreateSurfaceAsConsumer(bufferName);
        ret = streamCapturePtr->SetBufferProducerInfo(bufferName, gainmapSurface_->GetProducer());
        retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
    }
    if (isDepthBufferSupported_ && deepSurface_ == nullptr) {
        std::string bufferName = "deepImage";
        deepSurface_ = Surface::CreateSurfaceAsConsumer(bufferName);
        ret = streamCapturePtr->SetBufferProducerInfo(bufferName, deepSurface_->GetProducer());
        retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
    }
    if (exifSurface_ == nullptr) {
        std::string bufferName = "exifImage";
        exifSurface_ = Surface::CreateSurfaceAsConsumer(bufferName);
        ret = streamCapturePtr->SetBufferProducerInfo(bufferName, exifSurface_->GetProducer());
        retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
    }
    if (debugSurface_ == nullptr) {
        std::string bufferName = "debugImage";
        debugSurface_ = Surface::CreateSurfaceAsConsumer(bufferName);
        ret = streamCapturePtr->SetBufferProducerInfo(bufferName, debugSurface_->GetProducer());
        retStr += (ret != CAMERA_OK ? bufferName + "," : retStr);
    }
    MEDIA_INFO_LOG("PhotoOutput::CreateMultiChannel! failed channel is = %{public}s", retStr.c_str());
    // LCOV_EXCL_STOP
}

bool PhotoOutput::IsEnableDeferred()
{
    CHECK_RETURN_RET(!isNativeSurface_, false);
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
            // LCOV_EXCL_START
            if (cameraSvcCallback_ == nullptr) {
                MEDIA_ERR_LOG("PhotoOutput::SetCallback new HStreamCaptureCallbackImpl Failed to register callback");
                appCallback_ = nullptr;
                return;
            }
            // LCOV_EXCL_STOP
        }
        auto itemStream = CastStream<IStreamCapture>(GetStream());
        int32_t errorCode = CAMERA_OK;
        if (itemStream) {
            errorCode = itemStream->SetCallback(cameraSvcCallback_);
        } else {
            MEDIA_ERR_LOG("PhotoOutput::SetCallback() itemStream is nullptr");
        }
        // LCOV_EXCL_START
        CHECK_RETURN(errorCode == CAMERA_OK);
        MEDIA_ERR_LOG("PhotoOutput::SetCallback: Failed to register callback, errorCode: %{public}d", errorCode);
        cameraSvcCallback_ = nullptr;
        appCallback_ = nullptr;
        // LCOV_EXCL_STOP
    }
}

void PhotoOutput::SetPhotoNativeConsumer()
{
    MEDIA_DEBUG_LOG("SetPhotoNativeConsumer E");
    CHECK_RETURN_ELOG(photoSurface_ == nullptr, "SetPhotoNativeConsumer err, surface is null");
    CHECK_RETURN(photoNativeConsumer_ != nullptr);
    photoSurface_->UnregisterConsumerListener();
    photoNativeConsumer_ = new (std::nothrow) PhotoNativeConsumer(wptr<PhotoOutput>(this));
    SurfaceError ret = photoSurface_->RegisterConsumerListener((sptr<IBufferConsumerListener> &)photoNativeConsumer_);
    CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "SetPhotoNativeConsumer failed:%{public}d", ret);
}

void PhotoOutput::SetPhotoAvailableCallback(std::shared_ptr<PhotoAvailableCallback> callback)
{
    MEDIA_DEBUG_LOG("SetPhotoAvailableCallback E");
    CHECK_RETURN_ELOG(callback == nullptr, "photo callback nullptr");
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appPhotoCallback_ = nullptr;
    svcPhotoCallback_ = nullptr;
    appPhotoCallback_ = callback;
    if (isSurfaceOnService_) {
        SetPhotoAvailableInSvc();
    } else {
        SetPhotoNativeConsumer();
    }
}

void PhotoOutput::SetPhotoAvailableInSvc()
{
    MEDIA_DEBUG_LOG("SetPhotoAvailableInSvc E");
    svcPhotoCallback_ = new (std::nothrow) HStreamCapturePhotoCallbackImpl(this);
    CHECK_RETURN_ELOG(svcPhotoCallback_ == nullptr, "new photo svc callback err");
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    int32_t errorCode = CAMERA_OK;
    if (itemStream) {
        errorCode = itemStream->SetPhotoAvailableCallback(svcPhotoCallback_);
    } else {
        reSetFlag_ = RESET_PHOTO;
        MEDIA_ERR_LOG("SetPhotoAvailableCallback itemStream is nullptr");
    }
    if (errorCode != CAMERA_OK) {
        MEDIA_ERR_LOG("SetPhotoAvailableCallback Failed to register callback, errorCode: %{public}d", errorCode);
        svcPhotoCallback_ = nullptr;
        appPhotoCallback_ = nullptr;
    }
    MEDIA_DEBUG_LOG("SetPhotoAvailableCallback X");
}

void PhotoOutput::UnSetPhotoAvailableCallback()
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("UnSetPhotoAvailableCallback E");
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appPhotoCallback_ = nullptr;
    svcPhotoCallback_ = nullptr;
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    if (itemStream) {
        itemStream->UnSetPhotoAvailableCallback();
    }
    // LCOV_EXCL_STOP
}

void PhotoOutput::SetPhotoAssetAvailableCallback(std::shared_ptr<PhotoAssetAvailableCallback> callback)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("SetPhotoAssetAvailableCallback E");
    CHECK_RETURN_ELOG(callback == nullptr, "photoAsset callback nullptr");
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appPhotoAssetCallback_ = nullptr;
    svcPhotoAssetCallback_ = nullptr;
    appPhotoAssetCallback_ = callback;
    if (isSurfaceOnService_) {
        SetPhotoAssetAvailableInSvc();
    } else {
        SetPhotoNativeConsumer();
    }
    // LCOV_EXCL_STOP
}

void PhotoOutput::SetPhotoAssetAvailableInSvc()
{
    MEDIA_DEBUG_LOG("SetPhotoAssetAvailableInSvc E");
    svcPhotoAssetCallback_ = new (std::nothrow) HStreamCapturePhotoAssetCallbackImpl(this);
    CHECK_RETURN_ELOG(svcPhotoAssetCallback_ == nullptr, "new photoAsset svc callback err");
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    int32_t errorCode = CAMERA_OK;
    if (itemStream) {
        errorCode = itemStream->SetPhotoAssetAvailableCallback(svcPhotoAssetCallback_);
    } else {
        reSetFlag_ = RESET_PHOTO_ASSET;
        MEDIA_ERR_LOG("SetPhotoAssetAvailableCallback itemStream is nullptr");
    }
    if (errorCode != CAMERA_OK) {
        MEDIA_ERR_LOG("SetPhotoAssetAvailableCallback Failed to register callback, errorCode: %{public}d", errorCode);
        svcPhotoAssetCallback_ = nullptr;
        appPhotoAssetCallback_ = nullptr;
    }
    MEDIA_DEBUG_LOG("SetPhotoAssetAvailableCallback X");
}

void PhotoOutput::UnSetPhotoAssetAvailableCallback()
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("UnSetPhotoAssetAvailableCallback E");
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appPhotoAssetCallback_ = nullptr;
    svcPhotoAssetCallback_ = nullptr;
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    if (itemStream) {
        itemStream->UnSetPhotoAssetAvailableCallback();
    }
    // LCOV_EXCL_STOP
}

void PhotoOutput::ReSetSavedCallback()
{
    MEDIA_DEBUG_LOG("ReSetSavedCallback E");
    CHECK_RETURN_ELOG(!isSurfaceOnService_, "ReSetSavedCallback no need");
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    CHECK_RETURN_ELOG(itemStream == nullptr, "ReSetSavedCallback faild");
    int32_t errorCode = CAMERA_OK;
    if (reSetFlag_ == RESET_PHOTO && appPhotoCallback_ && svcPhotoCallback_) {
        errorCode = itemStream->SetPhotoAvailableCallback(svcPhotoCallback_);
    } else if (reSetFlag_ == RESET_PHOTO_ASSET && appPhotoAssetCallback_ && svcPhotoAssetCallback_) {
        errorCode = itemStream->SetPhotoAssetAvailableCallback(svcPhotoAssetCallback_);
    }
    reSetFlag_ = NO_NEED_RESET;
    if (errorCode != CAMERA_OK) {
        MEDIA_ERR_LOG("ReSetSavedCallback failed, errorCode: %{public}d", errorCode);
    }
}

void PhotoOutput::SetThumbnailCallback(std::shared_ptr<ThumbnailCallback> callback)
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("SetThumbnailCallback E");
    CHECK_RETURN_ELOG(callback == nullptr, "photoAsset callback nullptr");
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appThumbnailCallback_ = nullptr;
    svcThumbnailCallback_ = nullptr;
    appThumbnailCallback_ = callback;
    svcThumbnailCallback_ = new (std::nothrow) HStreamCaptureThumbnailCallbackImpl(this);
    CHECK_RETURN_ELOG(svcThumbnailCallback_ == nullptr, "new photoAsset svc callback err");
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    int32_t errorCode = CAMERA_OK;
    if (itemStream) {
        errorCode = itemStream->SetThumbnailCallback(svcThumbnailCallback_);
    } else {
        MEDIA_ERR_LOG("SetThumbnailCallback itemStream is nullptr");
    }
    if (errorCode != CAMERA_OK) {
        MEDIA_ERR_LOG("SetThumbnailCallback Failed to register callback, errorCode: %{public}d", errorCode);
        svcThumbnailCallback_ = nullptr;
        appThumbnailCallback_ = nullptr;
    }
    MEDIA_DEBUG_LOG("SetThumbnailCallback X");
    // LCOV_EXCL_STOP
}

void PhotoOutput::UnSetThumbnailAvailableCallback()
{
    // LCOV_EXCL_START
    MEDIA_DEBUG_LOG("UnSetThumbnailAvailableCallback E");
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appThumbnailCallback_ = nullptr;
    svcThumbnailCallback_ = nullptr;
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    if (itemStream) {
        itemStream->UnSetThumbnailCallback();
    }
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::SetThumbnail(bool isEnabled)
{
    CAMERA_SYNC_TRACE;
    sptr<CameraDevice> cameraObj;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput SetThumbnail error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput SetThumbnail error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput SetThumbnail error!, cameraObj is nullptr");
    auto streamCapturePtr = CastStream<IStreamCapture>(GetStream());
    CHECK_RETURN_RET(streamCapturePtr == nullptr, SERVICE_FATL_ERROR);
    return streamCapturePtr->SetThumbnail(isEnabled);
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::EnableRawDelivery(bool enabled)
{
    CAMERA_SYNC_TRACE;
    MEDIA_DEBUG_LOG("enter into EnableRawDelivery");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput EnableRawDelivery error!, session is nullptr");
    // LCOV_EXCL_START
    auto streamCapturePtr = CastStream<IStreamCapture>(GetStream());
    CHECK_RETURN_RET_ELOG(streamCapturePtr == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput::EnableRawDelivery Failed to GetStream");
    int32_t ret = CAMERA_OK;
    if (session->EnableRawDelivery(enabled) == CameraErrorCode::SUCCESS) {
        ret = streamCapturePtr->EnableRawDelivery(enabled);
        CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, SERVICE_FATL_ERROR,
            "PhotoOutput::EnableRawDelivery session EnableRawDelivery Failed");
    }
    isRawImageDelivery_ = enabled;
    return ret;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::EnableMovingPhoto(bool enabled)
{
    CAMERA_SYNC_TRACE;
    int32_t ret = CAMERA_OK;
    MEDIA_DEBUG_LOG("enter into EnableMovingPhoto");

    auto streamCapturePtr = CastStream<IStreamCapture>(GetStream());
    CHECK_RETURN_RET_ELOG(streamCapturePtr == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput::EnableMovingPhoto Failed!streamCapturePtr is nullptr");
    // LCOV_EXCL_START
    ret = streamCapturePtr->EnableMovingPhoto(enabled);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, SERVICE_FATL_ERROR,
        "PhotoOutput::EnableMovingPhoto Failed");
    return ret;
    // LCOV_EXCL_STOP
}

std::shared_ptr<PhotoStateCallback> PhotoOutput::GetApplicationCallback()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appCallback_;
    // LCOV_EXCL_STOP
}

std::shared_ptr<ThumbnailCallback> PhotoOutput::GetAppThumbnailCallback()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appThumbnailCallback_;
    // LCOV_EXCL_STOP
}

std::shared_ptr<PhotoAvailableCallback> PhotoOutput::GetAppPhotoCallback()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appPhotoCallback_;
    // LCOV_EXCL_STOP
}

std::shared_ptr<PhotoAssetAvailableCallback> PhotoOutput::GetAppPhotoAssetCallback()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appPhotoAssetCallback_;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::Capture(std::shared_ptr<PhotoCaptureSetting> photoCaptureSettings)
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_RUNNING, "PhotoOutput Failed to Capture with setting, session not commited");
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr,
        CameraErrorCode::SERVICE_FATL_ERROR, "PhotoOutput Failed to Capture with setting, GetStream is nullptr");
    defaultCaptureSetting_ = photoCaptureSettings;
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_PRINT_ELOG(itemStream == nullptr, "PhotoOutput::Capture() itemStream is nullptr");
    if (itemStream) {
        MEDIA_INFO_LOG("Capture start");
        session->EnableMovingPhotoMirror(photoCaptureSettings->GetMirror(), true);
        errCode = itemStream->Capture(photoCaptureSettings->GetCaptureMetadataSetting());
        MEDIA_INFO_LOG("Capture End");
    }
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "PhotoOutput Failed to Capture!, errCode: %{public}d", errCode);
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::Capture()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_RUNNING, "PhotoOutput Failed to Capture, session not commited");
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "PhotoOutput Failed to Capture, GetStream is nullptr");
    int32_t items = 0;
    int32_t dataLength = 0;
    std::shared_ptr<Camera::CameraMetadata> captureMetadataSetting =
        std::make_shared<Camera::CameraMetadata>(items, dataLength);
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_PRINT_ELOG(itemStream == nullptr, "PhotoOutput::Capture() itemStream is nullptr");
    if (itemStream) {
        MEDIA_DEBUG_LOG("Capture start");
        session->EnableMovingPhotoMirror(false, true);
        errCode = itemStream->Capture(captureMetadataSetting);
        MEDIA_DEBUG_LOG("Capture end");
    }
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "PhotoOutput Failed to Capture!, errCode: %{public}d", errCode);
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::CancelCapture()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_RUNNING, "PhotoOutput Failed to CancelCapture, session not commited");
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr,
        CameraErrorCode::SERVICE_FATL_ERROR, "PhotoOutput Failed to CancelCapture, GetStream is nullptr");
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_PRINT_ELOG(itemStream == nullptr, "PhotoOutput::CancelCapture() itemStream is nullptr");
    if (itemStream) {
        errCode = itemStream->CancelCapture();
    }
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "PhotoOutput Failed to CancelCapture, errCode: %{public}d", errCode);
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::ConfirmCapture()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_RUNNING, "PhotoOutput Failed to ConfirmCapture, session not commited");
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "PhotoOutput Failed to ConfirmCapture, GetStream is nullptr");
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->ConfirmCapture();
    } else {
        MEDIA_ERR_LOG("PhotoOutput::ConfirmCapture() itemStream is nullptr");
    }
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "PhotoOutput Failed to ConfirmCapture, errCode: %{public}d", errCode);
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::CreateStream()
{
    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(stream != nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "PhotoOutput::CreateStream stream is not null");
    // LCOV_EXCL_START
    sptr<IStreamCapture> streamPtr = nullptr;
    auto photoProfile = GetPhotoProfile();
    CHECK_RETURN_RET_ELOG(photoProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "PhotoOutput::CreateStream photoProfile is null");
    int32_t res = CameraErrorCode::SUCCESS;
    if (isSurfaceOnService_) {
        res = CameraManager::GetInstance()->CreatePhotoOutputStream(streamPtr, *photoProfile);
    } else {
        auto producer = GetBufferProducer();
        CHECK_RETURN_RET_ELOG(
            !producer, CameraErrorCode::OPERATION_NOT_ALLOWED, "PhotoOutput::CreateStream producer is null");
        res = CameraManager::GetInstance()->CreatePhotoOutputStream(streamPtr, *photoProfile, producer);
    }
    CHECK_PRINT_ELOG(res != CameraErrorCode::SUCCESS,
        "PhotoOutput::CreateStream fail! error code :%{public}d", res);
    SetStream(streamPtr);
    CHECK_EXECUTE(isSurfaceOnService_, ReSetSavedCallback());
    return res;
    // LCOV_EXCL_STOP
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
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "PhotoOutput Failed to Release!, GetStream is nullptr");
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Release();
    } else {
        MEDIA_ERR_LOG("PhotoOutput::Release() itemStream is nullptr");
    }
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "PhotoOutput Failed to release!, errCode: %{public}d", errCode);
    defaultCaptureSetting_ = nullptr;
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

bool PhotoOutput::IsMirrorSupported()
{
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, false,
        "PhotoOutput IsMirrorSupported error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, false,
        "PhotoOutput IsMirrorSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, false,
        "PhotoOutput IsMirrorSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, false);

    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, false,
        "PhotoOutput Can not find OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED");
    int step = 2;
    const int32_t canMirrorVideoAndPhoto = 2;
    const int32_t canMirrorPhotoOnly = 1;
    bool isMirrorEnabled = false;
    SceneMode currentSceneMode = session->GetMode();
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
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::EnableMirror(bool isEnable)
{
    MEDIA_INFO_LOG("PhotoOutput::EnableMirror enter, isEnable: %{public}d", isEnable);
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, CameraErrorCode::SESSION_NOT_RUNNING,
        "PhotoOutput EnableMirror error!, session is nullptr");

    // LCOV_EXCL_START
    int32_t ret = CAMERA_UNKNOWN_ERROR;
    CHECK_RETURN_RET_ELOG(!(IsMirrorSupported()), ret,
        "PhotoOutput EnableMirror error!, mirror is not supported");
    auto isSessionConfiged = session->IsSessionCommited() || session->IsSessionStarted();
    ret = session->EnableMovingPhotoMirror(isEnable, isSessionConfiged);
    CHECK_RETURN_RET_ELOG(ret != CameraErrorCode::SUCCESS, ret,
        "PhotoOutput EnableMirror error!, ret is not success");
    return ret;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::IsQuickThumbnailSupported()
{
    int32_t isQuickThumbnailEnabled = -1;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsQuickThumbnailSupported error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsQuickThumbnailSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsQuickThumbnailSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, SESSION_NOT_RUNNING);
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_STREAM_QUICK_THUMBNAIL_AVAILABLE, &item);
    if (ret == CAM_META_SUCCESS) {
        isQuickThumbnailEnabled = (item.data.u8[0] == 1) ? 0 : -1;
    }
    const int32_t nightMode = 4;
    if ((session->GetMode() == nightMode && (cameraObj->GetPosition() != CAMERA_POSITION_FRONT)) ||
        session->GetMode() == LIGHT_PAINTING) {
        isQuickThumbnailEnabled = -1;
    }
    return isQuickThumbnailEnabled;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::IsRawDeliverySupported(bool &isRawDeliveryEnabled)
{
    MEDIA_DEBUG_LOG("enter into IsRawDeliverySupported");
    isRawDeliveryEnabled = false;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsRawDeliverySupported error!, session is nullptr");
    // LCOV_EXCL_START
    const int32_t professionalPhotoMode = 11;
    if ((session->GetMode() == professionalPhotoMode)) {
        isRawDeliveryEnabled = true;
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::DeferImageDeliveryFor(DeferredDeliveryImageType type)
{
    MEDIA_INFO_LOG("PhotoOutput DeferImageDeliveryFor type:%{public}d!", type);
    CAMERA_SYNC_TRACE;
    sptr<CameraDevice> cameraObj;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput DeferImageDeliveryFor error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput DeferImageDeliveryFor error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput DeferImageDeliveryFor error!, cameraObj is nullptr");
    session->EnableDeferredType(type, true);
    session->SetUserId();
    return 0;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::IsDeferredImageDeliverySupported(DeferredDeliveryImageType type)
{
    MEDIA_INFO_LOG("IsDeferredImageDeliverySupported type:%{public}d!", type);
    int32_t isSupported = -1;
    CHECK_RETURN_RET(type == DELIVERY_NONE, isSupported);
    sptr<CameraDevice> cameraObj;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsDeferredImageDeliverySupported error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsDeferredImageDeliverySupported error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsDeferredImageDeliverySupported error!, cameraObj is nullptr");
    int32_t curMode = session->GetMode();
    int32_t modeSupportType = cameraObj->modeDeferredType_[curMode];
    MEDIA_INFO_LOG("IsDeferredImageDeliverySupported curMode:%{public}d, modeSupportType:%{public}d",
        curMode, modeSupportType);
    if (modeSupportType == type) {
        isSupported = 0; // -1:not support 0:support
    }
    return isSupported;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::IsDeferredImageDeliveryEnabled(DeferredDeliveryImageType type)
{
    MEDIA_INFO_LOG("PhotoOutput IsDeferredImageDeliveryEnabled type:%{public}d!", type);
    int32_t isEnabled = -1;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsDeferredImageDeliveryEnabled error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsDeferredImageDeliveryEnabled error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsDeferredImageDeliveryEnabled error!, cameraObj is nullptr");
    isEnabled = session->IsImageDeferred() ? 0 : -1;
    return isEnabled;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::IsAutoHighQualityPhotoSupported(int32_t &isAutoHighQualityPhotoSupported)
{
    MEDIA_INFO_LOG("PhotoOutput IsAutoHighQualityPhotoSupported is called");
    isAutoHighQualityPhotoSupported = -1;
    camera_metadata_item_t item;
    sptr<CameraDevice> cameraObj;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsAutoHighQualityPhotoSupported error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsAutoHighQualityPhotoSupported error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput IsAutoHighQualityPhotoSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, SESSION_NOT_RUNNING);
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_HIGH_QUALITY_SUPPORT, &item);
    if (ret == CAM_META_SUCCESS) {
        isAutoHighQualityPhotoSupported = (item.data.u8[1] == 1) ? 0 : -1; // default mode
    }

    int headLenPerMode = 2;
    SceneMode currentSceneMode = session->GetMode();
    for (int i = 0; i + 1 < static_cast<int>(item.count); i += headLenPerMode) {
        if (currentSceneMode == static_cast<int>(item.data.u8[i])) {
            isAutoHighQualityPhotoSupported = (item.data.u8[i + 1] == 1) ? 0 : -1;
        }
    }
    MEDIA_INFO_LOG("PhotoOutput IsAutoHighQualityPhotoSupported curMode:%{public}d, modeSupportType:%{public}d",
        currentSceneMode, isAutoHighQualityPhotoSupported);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::EnableAutoHighQualityPhoto(bool enabled)
{
    MEDIA_DEBUG_LOG("PhotoOutput EnableAutoHighQualityPhoto");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput EnableAutoHighQualityPhoto error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput EnableAutoHighQualityPhoto error!, inputDevice is nullptr");
    int32_t isAutoHighQualityPhotoSupported;
    int32_t ret = IsAutoHighQualityPhotoSupported(isAutoHighQualityPhotoSupported);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, OPERATION_NOT_ALLOWED,
        "PhotoOutput EnableAutoHighQualityPhoto error");
    CHECK_RETURN_RET_ELOG(isAutoHighQualityPhotoSupported == -1, INVALID_ARGUMENT,
        "PhotoOutput EnableAutoHighQualityPhoto not supported");
    int32_t res = session->EnableAutoHighQualityPhoto(enabled);
    return res;
    // LCOV_EXCL_STOP
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

int32_t PhotoOutput::SetMovingPhotoVideoCodecType(int32_t videoCodecType)
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into PhotoOutput::SetMovingPhotoVideoCodecType");
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "PhotoOutput Failed to SetMovingPhotoVideoCodecType!, GetStream is nullptr");
    // LCOV_EXCL_START
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_PRINT_ELOG(itemStream == nullptr, "PhotoOutput::SetMovingPhotoVideoCodecType() itemStream is nullptr");
    if (itemStream) {
        errCode = itemStream->SetMovingPhotoVideoCodecType(videoCodecType);
    }
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "PhotoOutput Failed to SetMovingPhotoVideoCodecType!, "
        "errCode: %{public}d", errCode);
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
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

int32_t PhotoOutput::IsAutoCloudImageEnhancementSupported(bool &isAutoCloudImageEnhancementSupported)
{
    MEDIA_INFO_LOG("PhotoOutput IsAutoCloudImageEnhancementSupported is called");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput IsAutoCloudImageEnhancementSupported error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput IsAutoCloudImageEnhancementSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput IsAutoCloudImageEnhancementSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, SERVICE_FATL_ERROR);
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AUTO_CLOUD_IMAGE_ENHANCE, &item);
    if (ret == CAM_META_SUCCESS) {
        if (item.count == 0) {
            MEDIA_WARNING_LOG("isAutoCloudImageEnhancementSupported item is nullptr");
            return CAMERA_OK;
        }
        SceneMode currentScenemode = session->GetMode();
        for (int i = 0; i < static_cast<int>(item.count);i++) {
            if (currentScenemode == static_cast<int>(item.data.i32[i])) {
                isAutoCloudImageEnhancementSupported = true;
                return CAMERA_OK;
            }
        }
    }
    MEDIA_INFO_LOG("Judge Auto Cloud Image Enhancement Supported result %{public}d",
        isAutoCloudImageEnhancementSupported);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::EnableAutoCloudImageEnhancement(bool enabled)
{
    MEDIA_DEBUG_LOG("PhotoOutput EnableAutoCloudImageEnhancement is called");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput EnableAutoCloudImageEnhancement error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput EnableAutoCloudImageEnhancement error!, inputDevice is nullptr");
    bool isAutoCloudImageEnhancementSupported = false;
    int32_t ret = IsAutoCloudImageEnhancementSupported(isAutoCloudImageEnhancementSupported);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, SERVICE_FATL_ERROR,
        "PhotoOutput EnableAutoCloudImageEnhancement error");
    CHECK_RETURN_RET_ELOG(isAutoCloudImageEnhancementSupported == false, SERVICE_FATL_ERROR,
        "PhotoOutput EnableAutoCloudImageEnhancement not supported");
    int32_t res = session->EnableAutoCloudImageEnhancement(enabled);
    return res;
    // LCOV_EXCL_STOP
}

bool PhotoOutput::IsDepthDataDeliverySupported()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter IsDepthDataDeliverySupported");
    return false;
}

int32_t PhotoOutput::EnableDepthDataDelivery(bool enabled)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter EnableDepthDataDelivery, enabled:%{public}d", enabled);
    return CameraErrorCode::SUCCESS;
}

int32_t PhotoOutput::GetPhotoRotation(int32_t imageRotation)
{
    MEDIA_DEBUG_LOG("PhotoOutput GetPhotoRotation is called");
    int32_t sensorOrientation = 0;
    CameraPosition cameraPosition;
    ImageRotation result = ImageRotation::ROTATION_0;
    sptr<CameraDevice> cameraObj;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput GetPhotoRotation error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput GetPhotoRotation error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput GetPhotoRotation error!, cameraObj is nullptr");
    cameraPosition = cameraObj->GetPosition();
    CHECK_RETURN_RET_ELOG(cameraPosition == CAMERA_POSITION_UNSPECIFIED, SERVICE_FATL_ERROR,
        "PhotoOutput GetPhotoRotation error!, cameraPosition is unspecified");
    sensorOrientation = static_cast<int32_t>(cameraObj->GetCameraOrientation());
    imageRotation = (imageRotation + ROTATION_45_DEGREES) / ROTATION_90_DEGREES * ROTATION_90_DEGREES;
    if (cameraPosition == CAMERA_POSITION_BACK) {
        result = (ImageRotation)((imageRotation + sensorOrientation) % CAPTURE_ROTATION_BASE);
    } else if (cameraPosition == CAMERA_POSITION_FRONT || cameraPosition == CAMERA_POSITION_FOLD_INNER) {
        result = (ImageRotation)((sensorOrientation - imageRotation + CAPTURE_ROTATION_BASE) % CAPTURE_ROTATION_BASE);
    }
    auto streamCapturePtr = CastStream<IStreamCapture>(GetStream());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_RETURN_RET_ELOG(streamCapturePtr == nullptr, CameraErrorCode::SERVICE_FATL_ERROR;,
        "PhotoOutput::SetCameraPhotoRotation() streamCapturePtr is nullptr");
    if (streamCapturePtr) {
        errCode = streamCapturePtr->SetCameraPhotoRotation(true);
        CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, SERVICE_FATL_ERROR,
            "Failed to SetCameraPhotoRotation!, errCode: %{public}d", errCode);
    }
    MEDIA_INFO_LOG("PhotoOutput GetPhotoRotation :result %{public}d, sensorOrientation:%{public}d",
        result, sensorOrientation);
    return result;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::IsAutoAigcPhotoSupported(bool& isAutoAigcPhotoSupported)
{
    MEDIA_INFO_LOG("PhotoOutput::IsAutoAigcPhotoSupported enter");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput::IsAutoAigcPhotoSupportederror, captureSession is nullptr");

    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "PhotoOutput::IsAutoAigcPhotoSupported, inputDevice is nullptr");

    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        cameraObj == nullptr, SERVICE_FATL_ERROR, "PhotoOutput::IsAutoAigcPhotoSupported error, cameraObj is nullptr");

    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, SERVICE_FATL_ERROR, "PhotoOutput::IsAutoAigcPhotoSupported error, metadata is nullptr");

    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AUTO_AIGC_PHOTO, &item);
    MEDIA_DEBUG_LOG("PhotoOutput::IsAutoAigcPhotoSupported ret: %{public}d", ret);
    if (ret == CAM_META_SUCCESS) {
        if (item.count == 0) {
            MEDIA_WARNING_LOG("PhotoOutput::IsAutoAigcPhotoSupported item is nullptr");
            return CAMERA_OK;
        }
        SceneMode currentSceneMode = session->GetMode();
        MEDIA_DEBUG_LOG(
            "PhotoOutput::IsAutoAigcPhotoSupported curMode: %{public}d", static_cast<int>(currentSceneMode));
        for (int i = 0; i < static_cast<int>(item.count); i++) {
            MEDIA_DEBUG_LOG(
                "PhotoOutput::IsAutoAigcPhotoSupported item data: %{public}d", static_cast<int>(item.data.u8[i]));
            if (currentSceneMode == static_cast<int>(item.data.u8[i])) {
                isAutoAigcPhotoSupported = true;
                return CAMERA_OK;
            }
        }
    }
    MEDIA_INFO_LOG("PhotoOutput::IsAutoAigcPhotoSupported result: %{public}d ", isAutoAigcPhotoSupported);
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::EnableAutoAigcPhoto(bool enabled)
{
    MEDIA_INFO_LOG("PhotoOutput::EnableAutoAigcPhoto enter, enabled: %{public}d", enabled);
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput::EnableAutoAigcPhoto error, captureSession is nullptr");

    // LCOV_EXCL_START
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SESSION_NOT_RUNNING,
        "PhotoOutput::EnableAutoAigcPhoto error, inputDevice is nullptr");

    bool isAutoAigcPhotoSupported = false;
    int32_t ret = IsAutoAigcPhotoSupported(isAutoAigcPhotoSupported);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, SERVICE_FATL_ERROR, "PhotoOutput::EnableAutoAigcPhoto error");
    CHECK_RETURN_RET_ELOG(
        !isAutoAigcPhotoSupported, PARAMETER_ERROR, "PhotoOutput::EnableAutoAigcPhoto not supported");
    int32_t res = captureSession->EnableAutoAigcPhoto(enabled);
    MEDIA_INFO_LOG("PhotoOutput::EnableAutoAigcPhoto result: %{public}d", res);
    return res;
    // LCOV_EXCL_STOP
}

sptr<Surface> PhotoOutput::GetPhotoSurface()
{
    return photoSurface_;
}

bool PhotoOutput::IsOfflineSupported()
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Enter IsOfflineSupported");
    bool isOfflineSupported = false;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(
        session == nullptr, isOfflineSupported, "PhotoOutput IsOfflineSupported error!, session is nullptr");
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, isOfflineSupported, "PhotoOutput IsOfflineSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        cameraObj == nullptr, isOfflineSupported, "PhotoOutput IsOfflineSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    CHECK_RETURN_RET_ELOG(
        metadata == nullptr, isOfflineSupported, "PhotoOutput IsOfflineSupported error!, metadata is nullptr");
    camera_metadata_item_t item;
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_CHANGETO_OFFLINE_STREAM_OPEATOR, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        isOfflineSupported = static_cast<bool>(item.data.u8[0]);
        MEDIA_INFO_LOG("PhotoOutput isOfflineSupported %{public}d", isOfflineSupported);
        return isOfflineSupported;
    }
    return isOfflineSupported;
    // LCOV_EXCL_STOP
}

int32_t PhotoOutput::EnableOfflinePhoto()
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("PhotoOutput EnableOfflinePhoto");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(
        session == nullptr, SESSION_NOT_RUNNING, "PhotoOutput EnableOfflinePhoto error!, session is nullptr");
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, SESSION_NOT_RUNNING, "PhotoOutput EnableOfflinePhoto error!, inputDevice is nullptr");
    bool isOfflineSupported = IsOfflineSupported();
    CHECK_RETURN_RET_ELOG(isOfflineSupported == false, OPERATION_NOT_ALLOWED,
        "PhotoOutput EnableOfflinePhoto error, isOfflineSupported is false");
    auto isSessionConfiged = session->IsSessionCommited();
    CHECK_RETURN_RET_ELOG(isSessionConfiged == false, OPERATION_NOT_ALLOWED,
        "PhotoOutput EnableOfflinePhoto error, isSessionConfiged is false");
    mIsHasEnableOfflinePhoto_ = true; // 管理offlinephotooutput
    auto streamCapturePtr = CastStream<IStreamCapture>(GetStream());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (streamCapturePtr) {
        errCode = streamCapturePtr->EnableOfflinePhoto(true);
        CHECK_RETURN_RET_ELOG(
            errCode != CAMERA_OK, SERVICE_FATL_ERROR, "Failed to EnableOfflinePhoto! , errCode: %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("PhotoOutput::EnableOfflinePhoto() itemStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

bool PhotoOutput::IsHasEnableOfflinePhoto()
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("PhotoOutput::IsHasEnableOfflinePhoto %{public}d", mIsHasEnableOfflinePhoto_);
    return mIsHasEnableOfflinePhoto_;
    // LCOV_EXCL_STOP
}

void PhotoOutput::SetSwitchOfflinePhotoOutput(bool isHasSwitched)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(offlineStatusMutex_);
    isHasSwitched_ = isHasSwitched;
    // LCOV_EXCL_STOP
}

bool PhotoOutput::IsHasSwitchOfflinePhoto()
{
    std::lock_guard<std::mutex> lock(offlineStatusMutex_);
    return isHasSwitched_;
}

void PhotoOutput::NotifyOfflinePhotoOutput(int32_t captureId)
{
    // LCOV_EXCL_START
    auto timeStartIter = captureIdToCaptureInfoMap_.find(captureId);
    if (timeStartIter != captureIdToCaptureInfoMap_.end()) {
        auto timeEnd = std::chrono::steady_clock::now();
        uint32_t timeCost = static_cast<uint32_t>(std::chrono::duration<double>(timeEnd -
            (timeStartIter->second).timeStart).count());
        if (timeCost > CAPTURE_TIMEOUT) {
            MEDIA_INFO_LOG("OnCaptureEnded: capture ID: %{public}d timeCost is %{public}d)",
                captureId, timeCost);
        }
        captureIdToCaptureInfoMap_.erase(captureId);
        if (IsHasSwitchOfflinePhoto() && captureIdToCaptureInfoMap_.size() == 0) {
            MEDIA_INFO_LOG("OnCaptureEnded notify offline delivery finished with capture ID: %{public}d", captureId);
            auto callback = GetApplicationCallback();
            if (callback == nullptr) {
                MEDIA_INFO_LOG("PhotoOutput::NotifyOfflinePhotoOutput callback is nullptr");
                Release();
                return;
            }
            callback->OnOfflineDeliveryFinished(captureId);
        }
    }
    // LCOV_EXCL_STOP
}

void PhotoOutput::CreateMediaLibrary(sptr<CameraPhotoProxy> photoProxy, std::string &uri, int32_t &cameraShotType,
    std::string &burstKey, int64_t timestamp)
{
    MEDIA_INFO_LOG("PhotoOutput::CreateMediaLibrary E");
    CAMERA_SYNC_TRACE;
    int32_t errorCode = CAMERA_OK;
    auto itemStream = CastStream<IStreamCapture>(GetStream());
    if (itemStream) {
        errorCode = itemStream->CreateMediaLibrary(photoProxy, uri, cameraShotType, burstKey, timestamp);
        CHECK_RETURN_ELOG(errorCode != CAMERA_OK, "Failed to createMediaLibrary, errorCode: %{public}d", errorCode);
    } else {
        MEDIA_ERR_LOG("PhotoOutput::CreateMediaLibrary itemStream is nullptr");
    }
    MEDIA_INFO_LOG("PhotoOutput::CreateMediaLibrary X");
}
} // namespace CameraStandard
} // namespace OHOS
