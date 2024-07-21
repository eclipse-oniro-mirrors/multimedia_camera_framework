/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "output/metadata_output.h"

#include <cinttypes>
#include <mutex>
#include <new>
#include <set>

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_util.h"
#include "foundation/multimedia/camera_framework/interfaces/kits/native/include/camera/camera.h"
#include "input/camera_input.h"
#include "session/capture_session.h"
#include "camera_error_code.h"

namespace OHOS {
namespace CameraStandard {
MetadataFaceObject::MetadataFaceObject(double timestamp, Rect rect)
    : MetadataObject(MetadataObjectType::FACE, timestamp, rect)
{}

MetadataObject::MetadataObject(MetadataObjectType type, double timestamp, Rect rect)
    : type_(type), timestamp_(timestamp), box_(rect)
{}

MetadataObjectType MetadataObject::GetType()
{
    return type_;
}
double MetadataObject::GetTimestamp()
{
    return timestamp_;
}
Rect MetadataObject::GetBoundingBox()
{
    return box_;
}

MetadataOutput::MetadataOutput(sptr<IConsumerSurface> surface, sptr<IStreamMetadata>& streamMetadata)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_METADATA, StreamType::METADATA, surface->GetProducer(), nullptr),
      surface_(surface)
{
    MEDIA_DEBUG_LOG("MetadataOutput::MetadataOutput construct enter");
}

MetadataOutput::~MetadataOutput()
{
    ReleaseSurface();
}

std::shared_ptr<MetadataObjectCallback> MetadataOutput::GetAppObjectCallback()
{
    MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::GetAppObjectCallback");
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appObjectCallback_;
}

std::shared_ptr<MetadataStateCallback> MetadataOutput::GetAppStateCallback()
{
    MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::GetAppStateCallback");
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appStateCallback_;
}

std::vector<MetadataObjectType> MetadataOutput::GetSupportedMetadataObjectTypes()
{
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET(session == nullptr, {});
    auto inputDevice = session->GetInputDevice();
    CHECK_ERROR_RETURN_RET(inputDevice == nullptr, {});
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET(cameraObj == nullptr, {});
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    CHECK_ERROR_RETURN_RET(metadata == nullptr, {});
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_STATISTICS_FACE_DETECT_MODE, &item);
    CHECK_ERROR_RETURN_RET(ret, {});
    std::vector<MetadataObjectType> objectTypes;
    for (size_t index = 0; index < item.count; index++) {
        if (item.data.u8[index] == OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE) {
            objectTypes.emplace_back(MetadataObjectType::FACE);
        }
    }
    return objectTypes;
}

void MetadataOutput::SetCapturingMetadataObjectTypes(std::vector<MetadataObjectType> metadataObjectTypes)
{
    auto session = GetSession();
    CHECK_ERROR_RETURN((session == nullptr) || (session->GetInputDevice() == nullptr));
    std::set<camera_face_detect_mode_t> objectTypes;
    for (const auto& type : metadataObjectTypes) {
        if (type == MetadataObjectType::FACE) {
            objectTypes.insert(OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE);
        }
    }
    if (objectTypes.empty()) {
        objectTypes.insert(OHOS_CAMERA_FACE_DETECT_MODE_OFF);
    }

    session->SetCaptureMetadataObjectTypes(objectTypes);
}

void MetadataOutput::SetCallback(std::shared_ptr<MetadataObjectCallback> metadataObjectCallback)
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appObjectCallback_ = metadataObjectCallback;
}

void MetadataOutput::SetCallback(std::shared_ptr<MetadataStateCallback> metadataStateCallback)
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appStateCallback_ = metadataStateCallback;
}

int32_t MetadataOutput::CreateStream()
{
    return CameraErrorCode::SUCCESS;
}

int32_t MetadataOutput::Start()
{
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_CONFIG, "MetadataOutput Failed to Start!, session not commited");
    auto stream = GetStream();
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "MetadataOutput Failed to Start!, GetStream is nullptr");
    int32_t errCode = static_cast<IStreamMetadata*>(stream.GetRefPtr())->Start();
    CHECK_ERROR_PRINT_LOG(errCode != CAMERA_OK, "Failed to Start MetadataOutput!, errCode: %{public}d", errCode);
    return ServiceToCameraError(errCode);
}

void MetadataOutput::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    if (appStateCallback_ != nullptr) {
        MEDIA_DEBUG_LOG("appCallback not nullptr");
        int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
        appStateCallback_->OnError(serviceErrorType);
    }
}

int32_t MetadataOutput::Stop()
{
    auto stream = GetStream();
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "MetadataOutput Failed to Stop!, GetStream is nullptr");
    int32_t errCode = static_cast<IStreamMetadata*>(stream.GetRefPtr())->Stop();
    CHECK_ERROR_PRINT_LOG(errCode != CAMERA_OK, "Failed to Stop MetadataOutput!, errCode: %{public}d", errCode);
    return ServiceToCameraError(errCode);
}

int32_t MetadataOutput::Release()
{
    {
        std::lock_guard<std::mutex> lock(outputCallbackMutex_);
        appObjectCallback_ = nullptr;
        appStateCallback_ = nullptr;
    }
    auto stream = GetStream();
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "MetadataOutput Failed to Release!, GetStream is nullptr");
    int32_t errCode = static_cast<IStreamMetadata*>(stream.GetRefPtr())->Release();
    CHECK_ERROR_PRINT_LOG(errCode != CAMERA_OK, "Failed to Release MetadataOutput!, errCode: %{public}d", errCode);
    ReleaseSurface();
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

void MetadataOutput::ReleaseSurface()
{
    std::lock_guard<std::mutex> lock(surfaceMutex_);
    if (surface_ != nullptr) {
        SurfaceError ret = surface_->UnregisterConsumerListener();
        CHECK_ERROR_PRINT_LOG(ret != SURFACE_ERROR_OK, "Failed to unregister surface consumer listener");
        surface_ = nullptr;
    }
}

sptr<IConsumerSurface> MetadataOutput::GetSurface()
{
    std::lock_guard<std::mutex> lock(surfaceMutex_);
    return surface_;
}

void MetadataOutput::ProcessFaceRectangles(int64_t timestamp,
    const std::shared_ptr<OHOS::Camera::CameraMetadata>& result, std::vector<sptr<MetadataObject>>& metaObjects,
    bool isNeedMirror)
{
    if (result == nullptr) {
        return;
    }
    camera_metadata_item_t metadataItem;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATISTICS_FACE_RECTANGLES, &metadataItem);
    if (ret != CAM_META_SUCCESS) {
        reportLastFaceResults_ = false;
        if (reportFaceResults_) {
            reportLastFaceResults_ = true;
            reportFaceResults_ = false;
        }
        metaObjects.clear();
        MEDIA_DEBUG_LOG("Camera not ProcessFaceRectangles");
        return;
    }
    MEDIA_INFO_LOG("ProcessFaceRectangles: %{public}d count: %{public}d", metadataItem.item, metadataItem.count);
    constexpr int32_t rectangleUnitLen = 4;
    if (metadataItem.count % rectangleUnitLen) {
        MEDIA_ERR_LOG("Metadata item: %{public}d count: %{public}d is invalid", metadataItem.item, metadataItem.count);
        return;
    }
    metaObjects.reserve(metadataItem.count / rectangleUnitLen);

    ret = ProcessMetaObjects(timestamp, metaObjects, metadataItem, metadata, isNeedMirror);
    reportFaceResults_ = true;
    if (ret != CameraErrorCode::SUCCESS) {
        MEDIA_ERR_LOG("MetadataOutput::ProcessFaceRectangles() is failed.");
        return;
    }
    MEDIA_INFO_LOG("ProcessFaceRectangles: metaObjects size: %{public}zu", metaObjects.size());
    return;
}

int32_t MetadataOutput::ProcessMetaObjects(int64_t timestamp, std::vector<sptr<MetadataObject>>& metaObjects,
    camera_metadata_item_t& metadataItem, common_metadata_header_t* metadata, bool isNeedMirror)
{
    float* start = metadataItem.data.f;
    float* end = metadataItem.data.f + metadataItem.count;
    const int32_t offsetTopLeftX = 0;
    const int32_t offsetTopLeftY = 1;
    const int32_t offsetBottomRightX = 2;
    const int32_t offsetBottomRightY = 3;
    int64_t timeUnit = 1000000; // timestamp from nanoseconds to milliseconds
    int64_t formatTimestamp = timestamp / timeUnit;
    float topLeftX = 0;
    float topLeftY = 0;
    float width = 0;
    float height = 0;
    constexpr int32_t rectangleUnitLen = 4;
    std::string positionStr = isNeedMirror ? "FrontCamera" : "BackCamera";
    for (; start < end; start += rectangleUnitLen) {
        if (isNeedMirror) {
            topLeftX = 1 - start[offsetBottomRightY];
            topLeftY = 1 - start[offsetBottomRightX];
            width = start[offsetBottomRightY] - start[offsetTopLeftY];
            height = start[offsetBottomRightX] - start[offsetTopLeftX];
        } else {
            topLeftX = 1 - start[offsetBottomRightY];
            topLeftY = start[offsetTopLeftX];
            width = start[offsetBottomRightY] - start[offsetTopLeftY];
            height = start[offsetBottomRightX] - start[offsetTopLeftX];
        }
        topLeftX = topLeftX < 0 ? 0 : topLeftX;
        topLeftX = topLeftX > 1 ? 1 : topLeftX;
        topLeftY = topLeftY < 0 ? 0 : topLeftY;
        topLeftY = topLeftY > 1 ? 1 : topLeftY;
        sptr<MetadataObject> metadataObject = new(std::nothrow) MetadataFaceObject(formatTimestamp,
            (Rect) {topLeftX, topLeftY, width, height});
        MEDIA_INFO_LOG("ProcessFaceRectangles Metadata coordination: topleftX(%{public}f),topleftY(%{public}f),"
                       "BottomRightX(%{public}f),BottomRightY(%{public}f), timestamp: %{public}" PRId64,
                       start[offsetTopLeftX], start[offsetTopLeftY],
                       start[offsetBottomRightX], start[offsetBottomRightY], formatTimestamp);
        MEDIA_INFO_LOG("ProcessFaceRectangles Postion: %{public}s App coordination: "
                       "topleftX(%{public}f),topleftY(%{public}f),width(%{public}f),height(%{public}f)",
                       positionStr.c_str(), topLeftX, topLeftY, width, height);
        if (!metadataObject) {
            MEDIA_ERR_LOG("Failed to allocate MetadataFaceObject");
            return CameraErrorCode::OPERATION_NOT_ALLOWED;
        }
        metaObjects.emplace_back(metadataObject);
    }
    return CameraErrorCode::SUCCESS;
}

MetadataObjectListener::MetadataObjectListener(sptr<MetadataOutput> metadata) : metadata_(metadata) {}

int32_t MetadataObjectListener::ProcessMetadataBuffer(void* buffer, int64_t timestamp)
{
    return CameraErrorCode::SUCCESS;
}

void MetadataObjectListener::OnBufferAvailable()
{
    MEDIA_INFO_LOG("MetadataOutput::OnBufferAvailable() is Called");
    // metaoutput adapte later
    bool adapterLater = true;
    CHECK_ERROR_RETURN(adapterLater);
    auto metadataOutput = metadata_.promote();
    CHECK_ERROR_RETURN_LOG(metadataOutput == nullptr, "OnBufferAvailable metadataOutput is null");
    auto surface = metadataOutput->GetSurface();
    CHECK_ERROR_RETURN_LOG(surface == nullptr, "OnBufferAvailable Metadata surface is null");
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer = nullptr;
    SurfaceError surfaceRet = surface->AcquireBuffer(buffer, fence, timestamp, damage);
    CHECK_ERROR_RETURN_LOG(surfaceRet != SURFACE_ERROR_OK, "OnBufferAvailable Failed to acquire surface buffer");
    int32_t ret = ProcessMetadataBuffer(buffer->GetVirAddr(), timestamp);
    if (ret) {
        std::shared_ptr<MetadataStateCallback> appStateCallback = metadataOutput->GetAppStateCallback();
        if (appStateCallback) {
            appStateCallback->OnError(ret);
        }
    }
    surface->ReleaseBuffer(buffer, -1);
}
} // namespace CameraStandard
} // namespace OHOS
