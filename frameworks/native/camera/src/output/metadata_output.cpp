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
#include "foundation/multimedia/camera_framework/interfaces/kits/native/include/camera/camera.h"
#include "input/camera_input.h"
#include "session/capture_session.h"
#include "camera_error_code.h"

namespace OHOS {
namespace CameraStandard {
sptr<MetadataObjectFactory> MetadataObjectFactory::metaFactoryInstance_;
std::mutex MetadataObjectFactory::instanceMutex_;

const std::unordered_map<uint32_t, MetadataObjectType> g_HALResultToFwCameraMetaDetect_ = {
    {OHOS_STATISTICS_DETECT_HUMAN_FACE_INFOS, MetadataObjectType::FACE},
    {OHOS_STATISTICS_DETECT_HUMAN_BODY_INFOS, MetadataObjectType::HUMAN_BODY},
    {OHOS_STATISTICS_DETECT_CAT_FACE_INFOS, MetadataObjectType::CAT_FACE},
    {OHOS_STATISTICS_DETECT_CAT_BODY_INFOS, MetadataObjectType::CAT_BODY},
    {OHOS_STATISTICS_DETECT_DOG_FACE_INFOS, MetadataObjectType::DOG_FACE},
    {OHOS_STATISTICS_DETECT_DOG_BODY_INFOS, MetadataObjectType::DOG_BODY},
    {OHOS_STATISTICS_DETECT_SALIENT_INFOS, MetadataObjectType::SALIENT_DETECTION},
    {OHOS_STATISTICS_DETECT_BAR_CODE_INFOS, MetadataObjectType::BAR_CODE_DETECTION},
    {OHOS_STATISTICS_DETECT_BASE_FACE_INFO, MetadataObjectType::BASE_FACE_DETECTION},
};

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

int32_t MetadataOutput::AddMetadataObjectTypes(std::vector<MetadataObjectType> metadataObjectTypes)
{
    const size_t maxSize4NonSystemApp  = 1;
    if (!CameraSecurity::CheckSystemApp()) {
        MEDIA_DEBUG_LOG("public calling for metadataOutput");
        if (metadataObjectTypes.size() > maxSize4NonSystemApp ||
            std::any_of(metadataObjectTypes.begin(), metadataObjectTypes.end(),
                [](MetadataObjectType type) { return type != MetadataObjectType::FACE; })) {
            return CameraErrorCode::INVALID_ARGUMENT;
        }
    }
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr || !session->IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
                               "MetadataOutput Failed to AddMetadataObjectTypes!, session not commited");

    auto inputDevice = session->GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(inputDevice == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
                               "MetadataOutput Failed to AddMetadataObjectTypes!, inputDevice is null");

    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(cameraObj == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
                               "MetadataOutput Failed to AddMetadataObjectTypes!, cameraObj is null");

    auto outoputCapability = CameraManager::GetInstance()->GetSupportedOutputCapability(cameraObj, session->GetMode());
    CHECK_ERROR_RETURN_RET_LOG(outoputCapability == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
                               "MetadataOutput Failed to AddMetadataObjectTypes!, outoputCapability is null");

    std::vector<MetadataObjectType> supportMetadataType = outoputCapability->GetSupportedMetadataObjectType();
    for (const auto &type : supportMetadataType) {
        MEDIA_DEBUG_LOG("MetadataOutput::AddMetadataObjectTypes, support type: %{public}d", type);
    }
    CHECK_ERROR_RETURN_RET_LOG(!checkValidType(metadataObjectTypes, supportMetadataType),
                               CameraErrorCode::INVALID_ARGUMENT,
                               "MetadataOutput::AddMetadataObjectTypes, unsupported type!");

    auto stream = GetStream();
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
                               "MetadataOutput Failed to AddMetadataObjectTypes!, GetStream is nullptr");
    std::vector<int32_t> numberOfTypes = convert(metadataObjectTypes);
    int32_t errCode = static_cast<IStreamMetadata *>(stream.GetRefPtr())->EnableMetadataType(numberOfTypes);
    CHECK_ERROR_RETURN_RET_LOG(
        errCode != CAMERA_OK, CameraErrorCode::SERVICE_FATL_ERROR,
        "MetadataOutput Failed to AddMetadataObjectTypes!, EnableMetadataType failed ret: %{public}d", errCode);
    return CameraErrorCode::SUCCESS;
}

int32_t MetadataOutput::RemoveMetadataObjectTypes(std::vector<MetadataObjectType> metadataObjectTypes)
{
    const size_t maxSize4NonSystemApp  = 1;
    if (!CameraSecurity::CheckSystemApp()) {
        MEDIA_DEBUG_LOG("public calling for metadataOutput");
        if (metadataObjectTypes.size() > maxSize4NonSystemApp ||
            std::any_of(metadataObjectTypes.begin(), metadataObjectTypes.end(),
                [](MetadataObjectType type) { return type != MetadataObjectType::FACE; })) {
            return CameraErrorCode::INVALID_ARGUMENT;
        }
    }
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr || !session->IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
                               "MetadataOutput Failed to RemoveMetadataObjectTypes!, session not commited");

    auto stream = GetStream();
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
                               "MetadataOutput Failed to AddMetadataObjectTypes!, GetStream is nullptr");

    std::vector<int32_t> numberOfTypes = convert(metadataObjectTypes);
    int32_t errCode = static_cast<IStreamMetadata *>(stream.GetRefPtr())->DisableMetadataType(numberOfTypes);
    CHECK_ERROR_RETURN_RET_LOG(
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
    auto itemStream = static_cast<IStreamMetadata *>(GetStream().GetRefPtr());
    int32_t errorCode = CAMERA_OK;
    if (itemStream) {
        errorCode = itemStream->SetCallback(cameraMetadataCallback_);
    } else {
        MEDIA_ERR_LOG("MetadataOutput::SetCallback() itemStream is nullptr");
    }
    if (errorCode != CAMERA_OK) {
        MEDIA_ERR_LOG("MetadataOutput::SetCallback(): Failed to register callback, errorCode: %{public}d", errorCode);
        cameraMetadataCallback_ = nullptr;
        appObjectCallback_ = nullptr;
    }
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
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr || !session->IsSessionCommited(), CameraErrorCode::SESSION_NOT_CONFIG,
                               "MetadataOutput Failed to Start!, session not commited");
    auto stream = GetStream();
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
                               "MetadataOutput Failed to Start!, GetStream is nullptr");
    int32_t errCode = static_cast<IStreamMetadata *>(stream.GetRefPtr())->Start();
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
    MEDIA_DEBUG_LOG("MetadataOutput::Stop");
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
    int32_t errCode = static_cast<IStreamMetadata *>(stream.GetRefPtr())->Release();
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

void MetadataOutput::ProcessMetadata(const int32_t streamId,
                                     const std::shared_ptr<OHOS::Camera::CameraMetadata> &result,
                                     std::vector<sptr<MetadataObject>> &metaObjects, bool isNeedMirror, bool isNeedFlip)
{
    CHECK_ERROR_RETURN(result == nullptr);
    // camera_metadata_item_t metadataItem;
    common_metadata_header_t *metadata = result->get();
    std::vector<camera_metadata_item_t> metadataResults;
    std::vector<uint32_t> metadataTypes;
    GetMetadataResults(metadata, metadataResults, metadataTypes);
    if (metadataResults.size() == 0) {
        reportLastFaceResults_ = false;
        if (reportFaceResults_) {
            reportLastFaceResults_ = true;
            reportFaceResults_ = false;
        }
        metaObjects.clear();
        MEDIA_ERR_LOG("Camera not ProcessFaceRectangles");
        return;
    }
    int32_t ret = ProcessMetaObjects(streamId, metaObjects, metadataResults, metadataTypes, isNeedMirror, isNeedFlip);
    reportFaceResults_ = true;
    CHECK_ERROR_RETURN_LOG(ret != CameraErrorCode::SUCCESS, "MetadataOutput::ProcessFaceRectangles() is failed.");
    return;
}

int32_t MetadataOutput::ProcessMetaObjects(const int32_t streamId, std::vector<sptr<MetadataObject>>& metaObjects,
                                           const std::vector<camera_metadata_item_t>& metadataItem,
                                           const std::vector<uint32_t>& metadataTypes,
                                           bool isNeedMirror, bool isNeedFlip)
{
    for (size_t i = 0; i < metadataItem.size(); ++i) {
        auto itr = g_HALResultToFwCameraMetaDetect_.find(metadataTypes[i]);
        if (itr != g_HALResultToFwCameraMetaDetect_.end()) {
            GenerateObjects(metadataItem[i], itr->second, metaObjects, isNeedMirror, isNeedFlip);
        } else {
            MEDIA_ERR_LOG("MetadataOutput::ProcessMetaObjects() unsupported type: %{public}d", metadataTypes[i]);
        }
    }
    return CameraErrorCode::SUCCESS;
}

void MetadataOutput::GenerateObjects(const camera_metadata_item_t &metadataItem, MetadataObjectType type,
                                     std::vector<sptr<MetadataObject>> &metaObjects, bool isNeedMirror, bool isNeedFlip)
{
    int32_t index = 0;
    int32_t countOfObject = 0;
    auto iteratorOfLengthMap = mapLengthOfType.find(type);
    if (iteratorOfLengthMap != mapLengthOfType.end()) {
        countOfObject = metadataItem.count / iteratorOfLengthMap->second;
    }
    for (int32_t itr = 0; itr < countOfObject; ++itr) {
        sptr<MetadataObjectFactory> objectFactoryPtr = MetadataObjectFactory::GetInstance();
        MetadataObjectType typeFromHal = static_cast<MetadataObjectType>(metadataItem.data.i32[index]);
        index++;
        ProcessBaseInfo(objectFactoryPtr, metadataItem, index, typeFromHal, isNeedMirror, isNeedFlip);
        ProcessExternInfo(objectFactoryPtr, metadataItem, index, typeFromHal, isNeedMirror, isNeedFlip);
        metaObjects.push_back(objectFactoryPtr->createMetadataObject(type));
    }
}

void MetadataOutput::GetMetadataResults(const common_metadata_header_t *metadata,
    std::vector<camera_metadata_item_t>& metadataResults, std::vector<uint32_t>& metadataTypes)
{
    for (auto itr : typesOfMetadata_) {
        camera_metadata_item_t item;
        int ret = Camera::FindCameraMetadataItem(metadata, itr, &item);
        if (ret == CAM_META_SUCCESS) {
            metadataResults.emplace_back(std::move(item));
            metadataTypes.emplace_back(itr);
        }
    }
}

Rect MetadataOutput::ProcessRectBox(int32_t offsetTopLeftX, int32_t offsetTopLeftY,
    int32_t offsetBottomRightX, int32_t offsetBottomRightY, bool isNeedMirror, bool isNeedFlip)
{
    constexpr int32_t scale = 1000000;
    double topLeftX = 0;
    double topLeftY = 0;
    double width = 0;
    double height = 0;
    if (isNeedMirror) {
        topLeftX = scale - offsetBottomRightY;
        topLeftY = scale - offsetBottomRightX;
        width = offsetBottomRightY - offsetTopLeftY;
        height = offsetBottomRightX - offsetTopLeftX;
    } else if (isNeedFlip) {
        topLeftX = offsetTopLeftY;
        topLeftY = offsetTopLeftX;
        width = offsetBottomRightY - offsetTopLeftY;
        height = offsetBottomRightX - offsetTopLeftX;       
    }
    } else {
        topLeftX = scale - offsetBottomRightY;
        topLeftY = offsetTopLeftX;
        width = offsetBottomRightY - offsetTopLeftY;
        height = offsetBottomRightX - offsetTopLeftX;
    }
    topLeftX = topLeftX < 0 ? 0 : topLeftX;
    topLeftX = topLeftX > scale ? scale : topLeftX;
    topLeftY = topLeftY < 0 ? 0 : topLeftY;
    topLeftY = topLeftY > scale ? scale : topLeftY;

    return (Rect){ topLeftX / scale, topLeftY / scale, width / scale, height / scale};
}

void MetadataOutput::ProcessBaseInfo(sptr<MetadataObjectFactory> factoryPtr, const camera_metadata_item_t &metadataItem,
                                     int32_t &index, MetadataObjectType typeFromHal, bool isNeedMirror, bool isNeedFlip)
{
    const int32_t rectLength = 4;
    const int32_t offsetOne = 1;
    const int32_t offsetTwo = 2;
    const int32_t offsetThree = 3;
    factoryPtr->SetType(typeFromHal)
        ->SetObjectId(metadataItem.data.i32[index]);
    index++;
    factoryPtr->SetTimestamp(metadataItem.data.i32[index]);
    index++;
    factoryPtr->SetBox(ProcessRectBox(metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
                                      metadataItem.data.i32[index + offsetTwo],
                                      metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip));
    index += rectLength;
    factoryPtr->SetConfidence(metadataItem.data.i32[index]);
    index++;
    int32_t externalLength = metadataItem.data.i32[index];
    index++;
    MEDIA_DEBUG_LOG("MetadataOutput::GenerateObjects, type: %{public}d, externalLength: %{public}d", typeFromHal,
                    externalLength);
}

void MetadataOutput::ProcessExternInfo(sptr<MetadataObjectFactory> factoryPtr,
                                       const camera_metadata_item_t &metadataItem, int32_t &index,
                                       MetadataObjectType typeFromHal, bool isNeedMirror, bool isNeedFlip)
{
    switch (typeFromHal) {
        case MetadataObjectType::FACE:
            ProcessHumanFaceDetectInfo(factoryPtr, metadataItem, index, isNeedMirror, isNeedFlip);
            break;
        case MetadataObjectType::CAT_FACE:
            ProcessCatFaceDetectInfo(factoryPtr, metadataItem, index, isNeedMirror, isNeedFlip);
            break;
        case MetadataObjectType::DOG_FACE:
            ProcessDogFaceDetectInfo(factoryPtr, metadataItem, index, isNeedMirror, isNeedFlip);
            break;
        default:
            break;
    }
}

void MetadataOutput::ProcessHumanFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
                                                const camera_metadata_item_t &metadataItem, int32_t &index,
                                                bool isNeedMirror, bool isNeedFlip)
{
    int32_t version = metadataItem.data.i32[index++];
    MEDIA_DEBUG_LOG("isNeedMirror: %{public}d, isNeedFlip: %{public}d, version: %{public}d",
        isNeedMirror, isNeedFlip, version);
    const int32_t rectLength = 4;
    const int32_t offsetOne = 1;
    const int32_t offsetTwo = 2;
    const int32_t offsetThree = 3;
    factoryPtr->SetLeftEyeBoundingBox(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip));
    index += rectLength;
    factoryPtr->SetRightEyeBoundingBoxd(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip));
    index += rectLength;
    factoryPtr->SetEmotion(static_cast<Emotion>(metadataItem.data.i32[index]));
    index++;
    factoryPtr->SetEmotionConfidence(static_cast<Emotion>(metadataItem.data.i32[index]));
    index++;
    factoryPtr->SetPitchAngle(metadataItem.data.i32[index]);
    index++;
    factoryPtr->SetYawAngle(metadataItem.data.i32[index]);
    index++;
    factoryPtr->SetRollAngle(metadataItem.data.i32[index]);
    index++;
}

void MetadataOutput::ProcessCatFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
                                              const camera_metadata_item_t &metadataItem, int32_t &index,
                                              bool isNeedMirror, bool isNeedFlip)
{
    int32_t version = metadataItem.data.i32[index++];
    MEDIA_DEBUG_LOG("isNeedMirror: %{public}d, isNeedFlip: %{public}d, version: %{public}d",
        isNeedMirror, isNeedFlip, version);
    const int32_t rectLength = 4;
    const int32_t offsetOne = 1;
    const int32_t offsetTwo = 2;
    const int32_t offsetThree = 3;
    factoryPtr->SetLeftEyeBoundingBox(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip));
    index += rectLength;
    factoryPtr->SetRightEyeBoundingBoxd(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip));
    index += rectLength;
}

void MetadataOutput::ProcessDogFaceDetectInfo(sptr<MetadataObjectFactory> factoryPtr,
                                              const camera_metadata_item_t &metadataItem, int32_t &index,
                                              bool isNeedMirror, bool isNeedFlip)
{
    int32_t version = metadataItem.data.i32[index++];
    MEDIA_DEBUG_LOG("isNeedMirror: %{public}d, isNeedFlip: %{public}d, version: %{public}d",
        isNeedMirror, isNeedFlip, version);
    const int32_t rectLength = 4;
    const int32_t offsetOne = 1;
    const int32_t offsetTwo = 2;
    const int32_t offsetThree = 3;
    factoryPtr->SetLeftEyeBoundingBox(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip));
    index += rectLength;
    factoryPtr->SetRightEyeBoundingBoxd(ProcessRectBox(
        metadataItem.data.i32[index], metadataItem.data.i32[index + offsetOne],
        metadataItem.data.i32[index + offsetTwo],
        metadataItem.data.i32[index + offsetThree], isNeedMirror, isNeedFlip));
    index += rectLength;
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

int32_t HStreamMetadataCallbackImpl::OnMetadataResult(const int32_t streamId,
                                                      const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    auto metadataOutput = GetMetadataOutput();
    CHECK_ERROR_RETURN_RET_LOG(metadataOutput == nullptr, CAMERA_OK,
                               "HStreamMetadataCallbackImpl::OnMetadataResult metadataOutput is nullptr");
    auto session = metadataOutput->GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr, SESSION_NOT_RUNNING,
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
    CHECK_ERROR_RETURN_RET(objectCallback == nullptr, INVALID_ARGUMENT);
    if ((metadataOutput->reportFaceResults_ || metadataOutput->reportLastFaceResults_) && objectCallback) {
        objectCallback->OnMetadataObjectsAvailable(metaObjects);
    }
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
