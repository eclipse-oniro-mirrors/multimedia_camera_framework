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

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstdint>

#include "camera_device_ability_items.h"
#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_security_utils.h"
#include "camera_util.h"
#include "session/capture_session.h"

namespace OHOS {
namespace CameraStandard {
sptr<MetadataObjectFactory> MetadataObjectFactory::metaFactoryInstance_;
std::mutex MetadataObjectFactory::instanceMutex_;

MetadataObject::MetadataObject(const MetadataObjectType type, const int32_t timestamp, const Rect rect,
                               const int32_t objectId, const int32_t confidence)
    : type_(type),
      timestamp_(timestamp),
      box_(rect),
      objectId_(objectId),
      confidence_(confidence)
{}

MetadataObject::MetadataObject(const MetaObjectParms &parms)
{
    type_ = parms.type;
    timestamp_ = parms.timestamp;
    box_ = parms.box;
    objectId_ = parms.objectId;
    confidence_ = parms.confidence;
}

MetadataFaceObject::MetadataFaceObject(const MetaObjectParms &parms, const Rect leftEyeBoundingBox,
                                       const Rect rightEyeBoundingBox, const Emotion emotion,
                                       const int32_t emotionConfidence, const int32_t pitchAngle,
                                       const int32_t yawAngle, const int32_t rollAngle)
    : MetadataObject(parms),
      leftEyeBoundingBox_(leftEyeBoundingBox),
      rightEyeBoundingBox_(rightEyeBoundingBox),
      emotion_(emotion),
      emotionConfidence_(emotionConfidence),
      pitchAngle_(pitchAngle),
      yawAngle_(yawAngle),
      rollAngle_(rollAngle)
{}

MetadataHumanBodyObject::MetadataHumanBodyObject(const MetaObjectParms &parms) : MetadataObject(parms) {}

MetadataCatFaceObject::MetadataCatFaceObject(const MetaObjectParms &parms, const Rect leftEyeBoundingBox,
                                             const Rect rightEyeBoundingBox)
    : MetadataObject(parms),
      leftEyeBoundingBox_(leftEyeBoundingBox),
      rightEyeBoundingBox_(rightEyeBoundingBox)
{}

MetadataCatBodyObject::MetadataCatBodyObject(const MetaObjectParms &parms) : MetadataObject(parms) {}

MetadataDogFaceObject::MetadataDogFaceObject(const MetaObjectParms &parms, const Rect leftEyeBoundingBox,
                                             const Rect rightEyeBoundingBox)
    : MetadataObject(parms),
      leftEyeBoundingBox_(leftEyeBoundingBox),
      rightEyeBoundingBox_(rightEyeBoundingBox)
{}

MetadataDogBodyObject::MetadataDogBodyObject(const MetaObjectParms &parms) : MetadataObject(parms) {}

MetadataSalientDetectionObject::MetadataSalientDetectionObject(const MetaObjectParms &parms) : MetadataObject(parms) {}

MetadataBarCodeDetectionObject::MetadataBarCodeDetectionObject(const MetaObjectParms &parms) : MetadataObject(parms) {}

MetadataOutput::MetadataOutput(sptr<IConsumerSurface> surface, sptr<IStreamMetadata> &streamMetadata)
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
    CHECK_RETURN_RET(session == nullptr, {});
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET(inputDevice == nullptr, {});
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET(cameraObj == nullptr, {});
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, {});
    camera_metadata_item_t item;
    int ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_STATISTICS_FACE_DETECT_MODE, &item);
    CHECK_RETURN_RET(ret, {});
    std::vector<MetadataObjectType> objectTypes;
    for (size_t index = 0; index < item.count; index++) {
        CHECK_EXECUTE(item.data.u8[index] == OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE,
            objectTypes.emplace_back(MetadataObjectType::FACE));
    }
    return objectTypes;
}

void MetadataOutput::SetCapturingMetadataObjectTypes(std::vector<MetadataObjectType> metadataObjectTypes)
{
    auto session = GetSession();
    CHECK_RETURN((session == nullptr) || (session->GetInputDevice() == nullptr));
    std::set<camera_face_detect_mode_t> objectTypes;
    for (const auto& type : metadataObjectTypes) {
        CHECK_EXECUTE(type == MetadataObjectType::FACE, objectTypes.insert(OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE));
    }
    CHECK_EXECUTE(objectTypes.empty(), objectTypes.insert(OHOS_CAMERA_FACE_DETECT_MODE_OFF));

    session->SetCaptureMetadataObjectTypes(objectTypes);
}

int32_t MetadataOutput::AddMetadataObjectTypes(std::vector<MetadataObjectType> metadataObjectTypes)
{
    const size_t maxSize4NonSystemApp  = 1;
    if (!CameraSecurity::CheckSystemApp()) {
        MEDIA_DEBUG_LOG("MetadataOutput::AddMetadataObjectTypes public calling for metadataOutput");
        if (metadataObjectTypes.size() > maxSize4NonSystemApp ||
            std::any_of(metadataObjectTypes.begin(), metadataObjectTypes.end(),
                [](MetadataObjectType type) { return type != MetadataObjectType::FACE; })) {
            return CameraErrorCode::INVALID_ARGUMENT;
        }
    }
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "MetadataOutput Failed to AddMetadataObjectTypes!, session not commited");

    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "MetadataOutput Failed to AddMetadataObjectTypes!, inputDevice is null");

    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "MetadataOutput Failed to AddMetadataObjectTypes!, cameraObj is null");

    auto outoputCapability = CameraManager::GetInstance()->GetSupportedOutputCapability(cameraObj, session->GetMode());
    CHECK_RETURN_RET_ELOG(outoputCapability == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "MetadataOutput Failed to AddMetadataObjectTypes!, outoputCapability is null");

    std::vector<MetadataObjectType> supportMetadataType = outoputCapability->GetSupportedMetadataObjectType();
    for (const auto &type : supportMetadataType) {
        MEDIA_DEBUG_LOG("MetadataOutput::AddMetadataObjectTypes, support type: %{public}d", type);
    }
    CHECK_RETURN_RET_ELOG(!checkValidType(metadataObjectTypes, supportMetadataType), CameraErrorCode::INVALID_ARGUMENT,
        "MetadataOutput::AddMetadataObjectTypes, unsupported type!");

    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(stream == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "MetadataOutput Failed to AddMetadataObjectTypes!, GetStream is nullptr");
    std::vector<int32_t> numberOfTypes = convert(metadataObjectTypes);
    int32_t errCode = static_cast<IStreamMetadata *>(stream.GetRefPtr())->EnableMetadataType(numberOfTypes);
    CHECK_RETURN_RET_ELOG(
        errCode != CAMERA_OK, CameraErrorCode::SERVICE_FATL_ERROR,
        "MetadataOutput Failed to AddMetadataObjectTypes!, EnableMetadataType failed ret: %{public}d", errCode);
    return CameraErrorCode::SUCCESS;
}

int32_t MetadataOutput::RemoveMetadataObjectTypes(std::vector<MetadataObjectType> metadataObjectTypes)
{
    const size_t maxSize4NonSystemApp  = 1;
    if (!CameraSecurity::CheckSystemApp()) {
        MEDIA_DEBUG_LOG("MetadataOutput::RemoveMetadataObjectTypes public calling for metadataOutput");
        if (metadataObjectTypes.size() > maxSize4NonSystemApp ||
            std::any_of(metadataObjectTypes.begin(), metadataObjectTypes.end(),
                [](MetadataObjectType type) { return type != MetadataObjectType::FACE; })) {
            return CameraErrorCode::INVALID_ARGUMENT;
        }
    }
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
        "MetadataOutput Failed to RemoveMetadataObjectTypes!, session not commited");

    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(stream == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "MetadataOutput Failed to AddMetadataObjectTypes!, GetStream is nullptr");

    std::vector<int32_t> numberOfTypes = convert(metadataObjectTypes);
    int32_t errCode = static_cast<IStreamMetadata *>(stream.GetRefPtr())->DisableMetadataType(numberOfTypes);
    CHECK_RETURN_RET_ELOG(
        errCode != CAMERA_OK, CameraErrorCode::SERVICE_FATL_ERROR,
        "MetadataOutput Failed to AddMetadataObjectTypes!, EnableMetadataType failed ret: %{public}d", errCode);
    return CameraErrorCode::SUCCESS;
}

bool MetadataOutput::checkValidType(const std::vector<MetadataObjectType> &typeAdded,
                                    const std::vector<MetadataObjectType> &supportedType)
{
    return std::all_of(typeAdded.begin(), typeAdded.end(), [&supportedType](MetadataObjectType type) {
        return std::find(supportedType.begin(), supportedType.end(), type) != supportedType.end();
    });
}

std::vector<int32_t> MetadataOutput::convert(const std::vector<MetadataObjectType> &typesOfMetadata)
{
    std::vector<int32_t> result(typesOfMetadata.size());
    std::transform(typesOfMetadata.begin(), typesOfMetadata.end(), result.begin(),
                   [](MetadataObjectType obj) { return static_cast<int32_t>(obj); });
    return result;
}

void MetadataOutput::SetCallback(std::shared_ptr<MetadataObjectCallback> metadataObjectCallback)
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appObjectCallback_ = metadataObjectCallback;
    if (appObjectCallback_ != nullptr) {
        if (cameraMetadataCallback_ == nullptr) {
            cameraMetadataCallback_ = new HStreamMetadataCallbackImpl(this);
        }
    }
    auto stream = GetStream();
    sptr<IStreamMetadata> itemStream = static_cast<IStreamMetadata*>(stream.GetRefPtr());
    int32_t errorCode = CAMERA_OK;
    if (itemStream) {
        errorCode = itemStream->SetCallback(cameraMetadataCallback_);
    } else {
        MEDIA_ERR_LOG("MetadataOutput::SetCallback() itemStream is nullptr");
    }
    CHECK_RETURN(errorCode == CAMERA_OK);
    MEDIA_ERR_LOG("MetadataOutput::SetCallback(): Failed to register callback, errorCode: %{public}d", errorCode);
    cameraMetadataCallback_ = nullptr;
    appObjectCallback_ = nullptr;
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
    MEDIA_DEBUG_LOG("MetadataOutput::Start is called");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(), CameraErrorCode::SUCCESS,
        "MetadataOutput Failed to Start!, session not commited");
    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(
        stream == nullptr, CameraErrorCode::SUCCESS, "MetadataOutput Failed to Start!, GetStream is nullptr");
    int32_t errCode = static_cast<IStreamMetadata *>(stream.GetRefPtr())->Start();
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to Start MetadataOutput!, errCode: %{public}d", errCode);
    return CameraErrorCode::SUCCESS;
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
    MEDIA_DEBUG_LOG("MetadataOutput::Stop");
    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(stream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "MetadataOutput Failed to Stop!, GetStream is nullptr");
    int32_t errCode = static_cast<IStreamMetadata*>(stream.GetRefPtr())->Stop();
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to Stop MetadataOutput!, errCode: %{public}d", errCode);
    return ServiceToCameraError(errCode);
}

int32_t MetadataOutput::Release()
{
    {
        std::lock_guard<std::mutex> lock(outputCallbackMutex_);
        appObjectCallback_ = nullptr;
        appStateCallback_ = nullptr;
        cameraMetadataCallback_ = nullptr;
    }
    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(stream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "MetadataOutput Failed to Release!, GetStream is nullptr");
    int32_t errCode = static_cast<IStreamMetadata *>(stream.GetRefPtr())->Release();
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to Release MetadataOutput!, errCode: %{public}d", errCode);
    ReleaseSurface();
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

void MetadataOutput::ReleaseSurface()
{
    std::lock_guard<std::mutex> lock(surfaceMutex_);
    if (surface_ != nullptr) {
        SurfaceError ret = surface_->UnregisterConsumerListener();
        CHECK_PRINT_ELOG(ret != SURFACE_ERROR_OK, "Failed to unregister surface consumer listener");
        surface_ = nullptr;
    }
}

sptr<IConsumerSurface> MetadataOutput::GetSurface()
{
    std::lock_guard<std::mutex> lock(surfaceMutex_);
    return surface_;
}

void MetadataOutput::ProcessMetadata(const int32_t streamId,
                                     const std::shared_ptr<OHOS::Camera::CameraMetadata> &result,
                                     std::vector<sptr<MetadataObject>> &metaObjects, bool isNeedMirror, bool isNeedFlip)
{
    bool ret = MetadataCommonUtils::ProcessMetaObjects(streamId, result, metaObjects, isNeedMirror,
        isNeedFlip, RectBoxType::RECT_CAMERA);
    if (ret) {
        reportFaceResults_ = true;
        return;
    }
    reportLastFaceResults_ = false;
    if (reportFaceResults_) {
        reportLastFaceResults_ = true;
        reportFaceResults_ = false;
    }
    MEDIA_ERR_LOG("Camera not ProcessFaceRectangles");
    return;
}

MetadataObjectListener::MetadataObjectListener(sptr<MetadataOutput> metadata) : metadata_(metadata) {}

int32_t MetadataObjectListener::ProcessMetadataBuffer(void *buffer, int64_t timestamp)
{
    return CameraErrorCode::SUCCESS;
}

void MetadataObjectListener::OnBufferAvailable()
{
    MEDIA_INFO_LOG("MetadataOutput::OnBufferAvailable() is Called");
    // metaoutput adapte later
    bool adapterLater = true;
    CHECK_RETURN(adapterLater);
    auto metadataOutput = metadata_.promote();
    CHECK_RETURN_ELOG(metadataOutput == nullptr, "OnBufferAvailable metadataOutput is null");
    auto surface = metadataOutput->GetSurface();
    CHECK_RETURN_ELOG(surface == nullptr, "OnBufferAvailable Metadata surface is null");
    int32_t fence = -1;
    int64_t timestamp;
    OHOS::Rect damage;
    sptr<SurfaceBuffer> buffer = nullptr;
    SurfaceError surfaceRet = surface->AcquireBuffer(buffer, fence, timestamp, damage);
    CHECK_RETURN_ELOG(surfaceRet != SURFACE_ERROR_OK, "OnBufferAvailable Failed to acquire surface buffer");
    int32_t ret = ProcessMetadataBuffer(buffer->GetVirAddr(), timestamp);
    if (ret) {
        std::shared_ptr<MetadataStateCallback> appStateCallback = metadataOutput->GetAppStateCallback();
        CHECK_EXECUTE(appStateCallback, appStateCallback->OnError(ret));
    }
    surface->ReleaseBuffer(buffer, -1);
}

int32_t HStreamMetadataCallbackImpl::OnMetadataResult(const int32_t streamId,
                                                      const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    auto metadataOutput = GetMetadataOutput();
    CHECK_RETURN_RET_ELOG(metadataOutput == nullptr, CAMERA_OK,
        "HStreamMetadataCallbackImpl::OnMetadataResult metadataOutput is nullptr");
    auto session = metadataOutput->GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SESSION_NOT_RUNNING,
        "HStreamMetadataCallbackImpl OnMetadataResult error!, session is nullptr");
    auto inputDevice = session->GetInputDevice();
    bool isNeedMirror = false;
    bool isNeedFlip = false;
    if (inputDevice) {
        auto inputDeviceInfo = inputDevice->GetCameraDeviceInfo();
        isNeedMirror = (inputDeviceInfo->GetPosition() == CAMERA_POSITION_FRONT ||
                        inputDeviceInfo->GetPosition() == CAMERA_POSITION_FOLD_INNER);
        isNeedFlip = inputDeviceInfo->GetUsedAsPosition() == CAMERA_POSITION_FRONT;
    }
    std::vector<sptr<MetadataObject>> metaObjects;
    metadataOutput->ProcessMetadata(streamId, result, metaObjects, isNeedMirror, isNeedFlip);
    auto objectCallback = metadataOutput->GetAppObjectCallback();
    CHECK_RETURN_RET(objectCallback == nullptr, INVALID_ARGUMENT);
    CHECK_EXECUTE((metadataOutput->reportFaceResults_ || metadataOutput->reportLastFaceResults_) && objectCallback,
        objectCallback->OnMetadataObjectsAvailable(metaObjects));
    return SUCCESS;
}

MetadataObjectFactory::MetadataObjectFactory() {}

sptr<MetadataObjectFactory> &MetadataObjectFactory::GetInstance()
{
    if (metaFactoryInstance_ == nullptr) {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        if (metaFactoryInstance_ == nullptr) {
            MEDIA_INFO_LOG("Initializing MetadataObjectFactory instance");
            metaFactoryInstance_ = new MetadataObjectFactory();
        }
    }
    return metaFactoryInstance_;
}

sptr<MetadataObject> MetadataObjectFactory::createMetadataObject(MetadataObjectType type)
{
    MetaObjectParms baseMetaParms = { type_, timestamp_, box_, objectId_, confidence_ };
    sptr<MetadataObject> metadataObject;
    switch (type) {
        case MetadataObjectType::FACE:
            metadataObject = new MetadataFaceObject(baseMetaParms, leftEyeBoundingBox_, rightEyeBoundingBox_, emotion_,
                                                    emotionConfidence_, pitchAngle_, yawAngle_, rollAngle_);
            break;
        case MetadataObjectType::HUMAN_BODY:
            metadataObject = new MetadataHumanBodyObject(baseMetaParms);
            break;
        case MetadataObjectType::CAT_FACE:
            metadataObject = new MetadataCatFaceObject(baseMetaParms, leftEyeBoundingBox_, rightEyeBoundingBox_);
            break;
        case MetadataObjectType::CAT_BODY:
            metadataObject = new MetadataCatBodyObject(baseMetaParms);
            break;
        case MetadataObjectType::DOG_FACE:
            metadataObject = new MetadataDogFaceObject(baseMetaParms, leftEyeBoundingBox_, rightEyeBoundingBox_);
            break;
        case MetadataObjectType::DOG_BODY:
            metadataObject = new MetadataDogBodyObject(baseMetaParms);
            break;
        case MetadataObjectType::SALIENT_DETECTION:
            metadataObject = new MetadataSalientDetectionObject(baseMetaParms);
            break;
        case MetadataObjectType::BAR_CODE_DETECTION:
            metadataObject = new MetadataBarCodeDetectionObject(baseMetaParms);
            break;
        default:
            metadataObject = new MetadataObject(baseMetaParms);
    }
    ResetParameters();
    return metadataObject;
}

void MetadataObjectFactory::ResetParameters()
{
    type_ = MetadataObjectType::INVALID;
    timestamp_ = 0;
    box_ = { 0, 0, 0, 0 };
    objectId_ = 0;
    confidence_ = 0.0f;
    leftEyeBoundingBox_ = { 0, 0, 0, 0 };
    rightEyeBoundingBox_ = { 0, 0, 0, 0 };
    emotion_ = Emotion::NEUTRAL;
    emotionConfidence_ = 0;
    pitchAngle_ = 0;
    yawAngle_ = 0;
    rollAngle_ = 0;
}
}  // namespace CameraStandard
}  // namespace OHOS
