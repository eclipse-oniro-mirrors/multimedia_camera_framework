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
#include <set>

#include "camera_util.h"
#include "camera_log.h"
#include "input/camera_input.h"
#include "session/capture_session.h"

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

MetadataOutput::MetadataOutput(sptr<IConsumerSurface> surface, sptr<IStreamMetadata> &streamMetadata)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_METADATA, StreamType::METADATA, streamMetadata)
{
    surface_ = surface;
}

MetadataOutput::~MetadataOutput()
{
    if (surface_) {
        SurfaceError ret = surface_->UnregisterConsumerListener();
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("Failed to unregister surface consumer listener");
        }
        surface_ = nullptr;
    }
    appObjectCallback_ = nullptr;
    appStateCallback_ = nullptr;
}

std::shared_ptr<MetadataObjectCallback> MetadataOutput::GetAppObjectCallback()
{
    MEDIA_DEBUG_LOG("CameraDeviceServiceCallback::GetResultCallback");
    return appObjectCallback_;
}

std::vector<MetadataObjectType> MetadataOutput::GetSupportedMetadataObjectTypes()
{
    CaptureSession* captureSession = GetSession();
    if ((captureSession == nullptr) || (captureSession->inputDevice_ == nullptr)) {
        return {};
    }
    sptr<CameraDevice> cameraObj = captureSession->inputDevice_->GetCameraDeviceInfo();
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_STATISTICS_FACE_DETECT_MODE, &item);
    if (ret) {
        return {};
    }
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
    CaptureSession* captureSession = GetSession();
    if ((captureSession == nullptr) || (captureSession->inputDevice_ == nullptr)) {
        return;
    }
    std::set<camera_face_detect_mode_t> objectTypes;
    for (const auto &type : metadataObjectTypes) {
        if (type == MetadataObjectType::FACE) {
            objectTypes.insert(OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE);
        }
    }
    if (objectTypes.empty()) {
        objectTypes.insert(OHOS_CAMERA_FACE_DETECT_MODE_OFF);
    }

    captureSession->SetCaptureMetadataObjectTypes(objectTypes);
}

void MetadataOutput::SetCallback(std::shared_ptr<MetadataObjectCallback> metadataObjectCallback)
{
    appObjectCallback_ = metadataObjectCallback;
}

void MetadataOutput::SetCallback(std::shared_ptr<MetadataStateCallback> metadataStateCallback)
{
    appStateCallback_ = metadataStateCallback;
}

int32_t MetadataOutput::Start()
{
    CaptureSession* captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("MetadataOutput Failed to Start!, session not config");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("MetadataOutput Failed to Start!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    int32_t errCode = static_cast<IStreamMetadata *>(GetStream().GetRefPtr())->Start();
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to Start MetadataOutput!, errCode: %{public}d", errCode);
    }
    return ServiceToCameraError(errCode);
}

int32_t MetadataOutput::Stop()
{
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("MetadataOutput Failed to Stop!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    int32_t errCode = static_cast<IStreamMetadata *>(GetStream().GetRefPtr())->Stop();
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to Stop MetadataOutput!, errCode: %{public}d", errCode);
    }
    return ServiceToCameraError(errCode);
}

int32_t MetadataOutput::Release()
{
    if (GetStream() == nullptr) {
        MEDIA_ERR_LOG("MetadataOutput Failed to Release!, GetStream is nullptr");
        return CameraErrorCode::SERVICE_FATL_ERROR;
    }
    int32_t errCode = static_cast<IStreamMetadata *>(GetStream().GetRefPtr())->Release();
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to release MetadataOutput!, errCode: %{public}d", errCode);
    }
    if (surface_) {
        SurfaceError ret = surface_->UnregisterConsumerListener();
        if (ret != SURFACE_ERROR_OK) {
            MEDIA_ERR_LOG("Failed to unregister surface consumer listener");
        }
        surface_ = nullptr;
    }
    appObjectCallback_ = nullptr;
    appStateCallback_ = nullptr;
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

void MetadataOutput::ProcessFaceRectangles(int64_t timestamp,
                                           const std::shared_ptr<OHOS::Camera::CameraMetadata> &result,
                                           std::vector<sptr<MetadataObject>> &metaObjects, bool isNeedMirror)
{
    camera_metadata_item_t metadataItem;
    common_metadata_header_t* metadata = result->get();
    int ret = Camera::FindCameraMetadataItem(metadata, OHOS_STATISTICS_FACE_RECTANGLES, &metadataItem);
    if (ret != CAM_META_SUCCESS) {
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
    std::string positionStr = isNeedMirror ? "FrontCamera" : "BackCamera";
    for (; start < end; start += rectangleUnitLen) {
        if (isNeedMirror) {
            topLeftX = 1 - start[offsetBottomRightY];
            topLeftY = 1- start[offsetBottomRightX];
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
            return;
        }
        metaObjects.emplace_back(metadataObject);
    }
    MEDIA_INFO_LOG("ProcessFaceRectangles: metaObjects size: %{public}zu", metaObjects.size());
    return;
}

MetadataObjectListener::MetadataObjectListener(sptr<MetadataOutput> metadata) : metadata_(metadata)
{}

int32_t MetadataObjectListener::ProcessFaceRectangles(int64_t timestamp, const camera_metadata_item_t &metadataItem,
                                                      std::vector<sptr<MetadataObject>> &metaObjects)
{
    return CAMERA_OK;
}

int32_t MetadataObjectListener::ProcessMetadataBuffer(void* buffer, int64_t timestamp)
{
    return CAMERA_OK;
}

void MetadataObjectListener::OnBufferAvailable()
{
    MEDIA_INFO_LOG("MetadataObjectListener::OnBufferAvailable() is Called");
    // metaoutput adapte later
    bool adapterLater = true;
    if (adapterLater) {
        return;
    }
    if (!metadata_) {
        MEDIA_ERR_LOG("Metadata is null");
        return;
    }
    sptr<IConsumerSurface> surface = metadata_->surface_;
    if (!surface) {
        MEDIA_ERR_LOG("Metadata surface is null");
        return;
    }
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer = nullptr;
    SurfaceError surfaceRet = surface->AcquireBuffer(buffer, fence, timestamp, damage);
    if (surfaceRet != SURFACE_ERROR_OK) {
        MEDIA_ERR_LOG("Failed to acquire surface buffer");
        return;
    }
    int32_t ret = ProcessMetadataBuffer(buffer->GetVirAddr(), timestamp);
    if (ret) {
        std::shared_ptr<MetadataStateCallback> appStateCallback = metadata_->appStateCallback_;
        if (appStateCallback) {
            appStateCallback->OnError(ret);
        }
    }

    surface->ReleaseBuffer(buffer, -1);
}
} // CameraStandard
} // OHOS
