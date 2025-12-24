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

#include "hstream_metadata.h"

#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_util.h"
#include "hstream_common.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "camera_report_uitls.h"
#include <cstdint>
#include <iomanip>
#include <unordered_set>
#include "dp_utils.h"
#include "securec.h"

namespace OHOS {
namespace CameraStandard {
namespace {
constexpr uint32_t NS_PER_US = 1000;
constexpr uint32_t MS_PER_S = 1000000;
constexpr int32_t CINEMATIC_DEFAULT_FPS = 30;
static const std::map<uint32_t, uint32_t> g_typeLengthMap = {
    { OHOS_STATISTICS_DETECT_HUMAN_FACE_INFOS, 24 },
    { OHOS_STATISTICS_DETECT_HUMAN_BODY_INFOS, 10 },
    { OHOS_STATISTICS_DETECT_CAT_FACE_INFOS, 19 },
    { OHOS_STATISTICS_DETECT_CAT_BODY_INFOS, 10 },
    { OHOS_STATISTICS_DETECT_DOG_FACE_INFOS, 19 },
    { OHOS_STATISTICS_DETECT_DOG_BODY_INFOS, 10 },
    { OHOS_STATISTICS_DETECT_SALIENT_INFOS, 10 },
    { OHOS_STATISTICS_DETECT_BAR_CODE_INFOS, 10 },
    { OHOS_STATISTICS_DETECT_BASE_FACE_INFO, 10 },
    { OHOS_STATISTICS_DETECT_HUMAN_HEAD_INFOS, 10 },
};
}
constexpr int32_t DEFAULT_ITEMS = 1;
constexpr int32_t DEFAULT_DATA_LENGTH = 10;

using namespace OHOS::HDI::Camera::V1_0;
HStreamMetadata::HStreamMetadata(sptr<OHOS::IBufferProducer> producer,
    int32_t format, std::vector<int32_t> metadataTypes)
    : HStreamCommon(StreamType::METADATA, producer, format, producer->GetDefaultWidth(), producer->GetDefaultHeight()),
    metadataObjectTypes_(metadataTypes), majorVer_(0)
{}

HStreamMetadata::~HStreamMetadata()
{}

int32_t HStreamMetadata::LinkInput(wptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    CHECK_RETURN_RET_ELOG(streamOperator == nullptr || cameraAbility == nullptr, CAMERA_INVALID_ARG,
        "HStreamMetadata::LinkInput streamOperator is null");
    SetStreamOperator(streamOperator);
    std::lock_guard<std::mutex> lock(cameraAbilityLock_);
    cameraAbility_ = cameraAbility;
    return CAMERA_OK;
}

void HStreamMetadata::SetStreamInfo(StreamInfo_V1_5 &streamInfo)
{
    HStreamCommon::SetStreamInfo(streamInfo);
    streamInfo.v1_0.intent_ = ANALYZE;
}

int32_t HStreamMetadata::Start()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(metadataTypeMutex_);
    isStarted_ = true;
    return EnableOrDisableMetadataType(metadataObjectTypes_, true);
}

int32_t HStreamMetadata::Stop()
{
    std::lock_guard<std::mutex> lock(metadataTypeMutex_);
    isStarted_ = false;
    return EnableOrDisableMetadataType(metadataObjectTypes_, false);
}

int32_t HStreamMetadata::Release()
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamMetadataCallback_ = nullptr;
    return ReleaseStream(false);
}

int32_t HStreamMetadata::ReleaseStream(bool isDelay)
{
    return HStreamCommon::ReleaseStream(isDelay);
}

void HStreamMetadata::DumpStreamInfo(CameraInfoDumper& infoDumper)
{
    infoDumper.Title("metadata stream");
    HStreamCommon::DumpStreamInfo(infoDumper);
}

int32_t HStreamMetadata::OperatePermissionCheck(uint32_t interfaceCode)
{
    switch (static_cast<IStreamMetadataIpcCode>(interfaceCode)) {
        case IStreamMetadataIpcCode::COMMAND_START: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            CHECK_RETURN_RET_ELOG(callerToken_ != callerToken, CAMERA_OPERATION_NOT_ALLOWED,
                "HStreamMetadata::OperatePermissionCheck fail, callerToken not legal");
            break;
        }
        case IStreamMetadataIpcCode::COMMAND_ENABLE_METADATA_TYPE:
        case IStreamMetadataIpcCode::COMMAND_DISABLE_METADATA_TYPE: {
            CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "HStreamMetadata::CheckSystemApp fail");
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HStreamMetadata::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_DEBUG_LOG("start, code:%{public}u", code);
    DisableJeMalloc();
    return OperatePermissionCheck(code);
}
int32_t HStreamMetadata::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_DEBUG_LOG("leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}

int32_t HStreamMetadata::EnableMetadataType(const std::vector<int32_t>& metadataTypes)
{
    int32_t rc = EnableOrDisableMetadataType(metadataTypes, true);
    CHECK_RETURN_RET_ELOG(rc != CAMERA_OK, rc, "HStreamMetadata::EnableMetadataType failed!");
    std::lock_guard<std::mutex> lock(metadataTypeMutex_);
    for (auto& element : metadataTypes) {
        metadataObjectTypes_.emplace_back(element);
    }
    return rc;
}
int32_t HStreamMetadata::DisableMetadataType(const std::vector<int32_t>& metadataTypes)
{
    int32_t rc = EnableOrDisableMetadataType(metadataTypes, false);
    CHECK_RETURN_RET_ELOG(rc != CAMERA_OK, rc, "HStreamMetadata::DisableMetadataType failed!");
    std::lock_guard<std::mutex> lock(metadataTypeMutex_);
    removeMetadataType(metadataTypes, metadataObjectTypes_);
    return rc;
}

int32_t HStreamMetadata::AddMetadataType(const std::vector<int32_t>& metadataTypes)
{
    MEDIA_DEBUG_LOG("HStreamMetadata::AddMetadataType is called");
    std::lock_guard<std::mutex> lock(metadataTypeMutex_);
    for (auto& element : metadataTypes) {
        metadataObjectTypes_.emplace_back(element);
    }
    return CAMERA_OK;
}

int32_t HStreamMetadata::RemoveMetadataType(const std::vector<int32_t>& metadataTypes)
{
    MEDIA_DEBUG_LOG("HStreamMetadata::RemoveMetadataType is called");
    std::lock_guard<std::mutex> lock(metadataTypeMutex_);
    removeMetadataType(metadataTypes, metadataObjectTypes_);
    return CAMERA_OK;
}

int32_t HStreamMetadata::OnMetaResult(int32_t streamId, std::shared_ptr<OHOS::Camera::CameraMetadata> result)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (result == nullptr) {
        result = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    }
    if (streamMetadataCallback_ != nullptr) {
        streamMetadataCallback_->OnMetadataResult(streamId, result);
    }
    return CAMERA_OK;
}

int32_t HStreamMetadata::SetCallback(const sptr<IStreamMetadataCallback>& callback)
{
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetCallback input is null");
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamMetadataCallback_ = callback;
    return CAMERA_OK;
}

int32_t HStreamMetadata::UnSetCallback()
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamMetadataCallback_ = nullptr;
    return CAMERA_OK;
}

int32_t HStreamMetadata::EnableOrDisableMetadataType(const std::vector<int32_t>& metadataTypes, const bool enable)
{
    MEDIA_DEBUG_LOG("HStreamMetadata::EnableOrDisableMetadataType enable: %{public}d, metadataTypes size: %{public}zu",
        enable, metadataTypes.size());
    auto streamOperator = GetStreamOperator();
    CHECK_RETURN_RET_ELOG(streamOperator == nullptr, CAMERA_INVALID_STATE,
        "HStreamMetadata::EnableOrDisableMetadataType streamOperator is nullptr");
    streamOperator->GetVersion(majorVer_, minorVer_);
    CHECK_RETURN_RET_DLOG(GetVersionId(majorVer_, minorVer_) < HDI_VERSION_ID_1_3, CAMERA_OK,
        "EnableOrDisableMetadataType version: %{public}d.%{public}d", majorVer_, minorVer_);
    int32_t ret = PrepareCaptureId();
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret,
        "HStreamMetadata::EnableOrDisableMetadataType Failed to allocate a captureId");
    sptr<OHOS::HDI::Camera::V1_3::IStreamOperator> streamOperatorV1_3 =
        OHOS::HDI::Camera::V1_3::IStreamOperator::CastFrom(streamOperator);
    CHECK_RETURN_RET_ELOG(streamOperatorV1_3 == nullptr, CAMERA_UNKNOWN_ERROR,
        "HStreamMetadata::EnableOrDisableMetadataType streamOperatorV1_3 castFrom failed!");
    OHOS::HDI::Camera::V1_2::CamRetCode rc;
    std::vector<uint8_t> typeTagToHal;
    for (auto& type : metadataTypes) {
        auto itr = g_FwkToHALResultCameraMetaDetect_.find(static_cast<MetadataObjectType>(type));
        if (itr != g_FwkToHALResultCameraMetaDetect_.end()) {
            typeTagToHal.emplace_back(itr->second);
            MEDIA_DEBUG_LOG("EnableOrDisableMetadataType type: %{public}d", itr->second);
        }
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata4Types =
        std::make_shared<OHOS::Camera::CameraMetadata>(DEFAULT_ITEMS, DEFAULT_DATA_LENGTH);
    uint32_t count = typeTagToHal.size();
    uint8_t* typesToEnable = typeTagToHal.data();
    bool status = metadata4Types->addEntry(OHOS_CONTROL_STATISTICS_DETECT_SETTING, typesToEnable, count);
    CHECK_RETURN_RET_ELOG(!status, CAMERA_UNKNOWN_ERROR, "set_camera_metadata failed!");
    std::vector<uint8_t> settings;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(metadata4Types, settings);
    if (enable) {
        rc = (OHOS::HDI::Camera::V1_2::CamRetCode)(streamOperatorV1_3->
            EnableResult(-1, settings));
    } else {
        rc = (OHOS::HDI::Camera::V1_2::CamRetCode)(streamOperatorV1_3->
            DisableResult(-1, settings));
    }
    ret = CAMERA_OK;
    CHECK_RETURN_RET_ELOG(rc != HDI::Camera::V1_2::NO_ERROR, HdiToServiceErrorV1_2(rc),
        "HStreamCapture::ConfirmCapture failed with error Code: %{public}d", rc);
    return ret;
}

void HStreamMetadata::removeMetadataType(const std::vector<int32_t>& metaRes, std::vector<int32_t>& metaTarget)
{
    std::unordered_set<int32_t> set(metaRes.begin(), metaRes.end());
    metaTarget.erase(std::remove_if(metaTarget.begin(), metaTarget.end(),
                                    [&set](const int32_t &element) { return set.find(element) != set.end(); }),
                     metaTarget.end());
}

std::vector<int32_t> HStreamMetadata::GetMetadataObjectTypes()
{
    return metadataObjectTypes_;
}

int32_t HStreamMetadata::EnableDetectedObjectLifecycleReport(bool isEnabled, int64_t timestamp)
{
    MEDIA_DEBUG_LOG("isEnabled: %{public}d, timestamp: %{public}" PRId64, isEnabled, timestamp);
    std::lock_guard<std::mutex> lock(objectLifecycleMutex_);
    if (isEnabled) {
        prevTs_ = -1;
        lastFrameDuration_ = -1;
        objectLifecycleMap_.clear();
        objectTrackingMap_.clear();
        prevIds_.clear();
        isDetectedObjectLifecycleReportEnabled_.store(isEnabled);
    } else {
        stopTime_ = timestamp / NS_PER_US;
    }
    return CAMERA_OK;
}

void HStreamMetadata::ProcessDetectedObjectLifecycle(const std::vector<uint8_t>& result)
{
    CHECK_RETURN(!isDetectedObjectLifecycleReportEnabled_.load());

    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, cameraResult);
    CHECK_RETURN_ELOG(cameraResult == nullptr, "cameraResult is null");
    common_metadata_header_t *metadata = cameraResult->get();

    // get timestamp of detcted objects
    int64_t timestamp = -1;
    GetFrameTimestamp(metadata, timestamp);
    CHECK_RETURN_ILOG(stopTime_ != -1 && timestamp > stopTime_,
                      "timestamp:%{public}" PRId64 " > stopTime:%{public}" PRId64 ", return", timestamp, stopTime_);
    CHECK_RETURN_ILOG(timestamp < 0, "timestamp: %{public}" PRId64 " is invalid, return", timestamp);

    // get detected objects and update lifecycle
    std::set<int32_t> detectedObjects;
    int32_t trackingObjectId = -1;
    GetDetectedObject(metadata, detectedObjects, trackingObjectId);
    UpdateDetectedObjectLifecycle(timestamp, detectedObjects, trackingObjectId);
}

void HStreamMetadata::GetFrameTimestamp(common_metadata_header_t *metadata, int64_t &timestamp)
{
    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_STATISTICS_TIMESTAMP, &item);
    if (ret == CAM_META_SUCCESS && item.count > 0) {
        timestamp = item.data.i64[0];
    }
    MEDIA_DEBUG_LOG("current frame timestamp: %{public}" PRId64, timestamp);
}

void HStreamMetadata::GetDetectedObject(common_metadata_header_t *metadata, std::set<int32_t> &detectedObjects,
                                        int32_t &trackingObjectId)
{
    camera_metadata_item_t item;
    // get tracking object id
    int ret = OHOS::Camera::FindCameraMetadataItem(metadata, OHOS_CONTROL_FOCUS_TRACKING_OBJECT_ID, &item);
    if (ret == CAM_META_SUCCESS && item.count == 1 && item.data.i32[0] >= 0) {
        detectedObjects.insert(item.data.i32[0]);
        trackingObjectId = item.data.i32[0];
    }
    // get ids of detcted objects
    constexpr int32_t OBJECT_ID_OFFSET = 1;
    for (const auto& pair : g_typeLengthMap) {
        uint32_t tag = pair.first;
        int ret = OHOS::Camera::FindCameraMetadataItem(metadata, tag, &item);
        if (ret == CAM_META_SUCCESS) {
            uint32_t countOfObject = item.count / pair.second;
            for (uint32_t itr = 0; itr < countOfObject; ++itr) {
                uint32_t offset = pair.second * itr;
                int32_t objectId = item.data.i32[offset + OBJECT_ID_OFFSET];
                detectedObjects.insert(objectId);
            }
        }
    }
}

void HStreamMetadata::UpdateDetectedObjectLifecycle(int64_t &timestamp, std::set<int32_t> &detectedObjects,
                                                    int32_t trackingObjectId)
{
    std::lock_guard<std::mutex> lock(objectLifecycleMutex_);
    CHECK_RETURN_ELOG(stopTime_ > 0 && timestamp > stopTime_, "recording is stopped, timestamp: %{public}" PRId64,
                      timestamp);

    if (prevTs_ > 0) {
        CHECK_RETURN_ELOG(timestamp < prevTs_, "timestamp must be non-decreasing");
        lastFrameDuration_ = timestamp - prevTs_;
        for (int32_t objectId : prevIds_) {
            // if object disappeared, update stop timestamp and next tracking objectId
            if (detectedObjects.find(objectId) == detectedObjects.end()) {
                objectLifecycleMap_[objectId].second = timestamp;
                objectTrackingMap_[objectId] = trackingObjectId;
                MEDIA_INFO_LOG("object disappeared, objectId:%{public}d, timestamp:%{public}" PRId64
                               ", next tracking objectId:%{public}d", objectId, timestamp, trackingObjectId);
            }
        }
    }

    for (int32_t objectId : detectedObjects) {
        // if object appeared, init timestamp and next tracking objectId
        auto iter = objectLifecycleMap_.find(objectId);
        if (iter == objectLifecycleMap_.end()) {
            objectLifecycleMap_[objectId] = {timestamp, timestamp};
            objectTrackingMap_[objectId] = -1;
            MEDIA_INFO_LOG("object appeared, objectId:%{public}d, timestamp:%{public}" PRId64, objectId, timestamp);
        }
    }

    prevIds_ = detectedObjects;
    prevTs_ = timestamp;

    if (!detectedObjects.empty()) {
        std::string detectedObjectsStr = Container2String(detectedObjects.begin(), detectedObjects.end());
        MEDIA_DEBUG_LOG("detected objects info: timestamp: %{public}" PRId64 ", list: %{public}s", timestamp,
                    detectedObjectsStr.c_str());
    }
}

void HStreamMetadata::SetFirstFrameTimestamp(int64_t timestamp)
{
    std::lock_guard<std::mutex> lock(objectLifecycleMutex_);
    firstFrameTimestamp_ = timestamp / NS_PER_US;
    MEDIA_DEBUG_LOG("firstFrameTimestamp_: %{public}" PRId64, firstFrameTimestamp_);
}

void HStreamMetadata::FillLifecycleBuffer(std::vector<uint8_t>& lifecycleBuffer, int32_t objectId, int64_t startPts,
                                          int64_t stopPts, int32_t nextTrackingObjectId)
{
    lifecycleBuffer.resize(sizeof(objectId) + sizeof(startPts) + sizeof(stopPts) + sizeof(nextTrackingObjectId));
    auto ret = memcpy_s(lifecycleBuffer.data(), sizeof(objectId), &objectId, sizeof(objectId));
    CHECK_RETURN_ELOG(ret != 0, "memcpy_s failed, ret: %{public}d", ret);
    ret = memcpy_s(lifecycleBuffer.data() + sizeof(objectId), sizeof(startPts), &startPts, sizeof(startPts));
    CHECK_RETURN_ELOG(ret != 0, "memcpy_s failed, ret: %{public}d", ret);
    ret = memcpy_s(lifecycleBuffer.data() + sizeof(objectId) + sizeof(startPts), sizeof(stopPts), &stopPts,
                   sizeof(stopPts));
    CHECK_RETURN_ELOG(ret != 0, "memcpy_s failed, ret: %{public}d", ret);
    ret = memcpy_s(lifecycleBuffer.data() + sizeof(objectId) + sizeof(startPts) + sizeof(stopPts),
                   sizeof(nextTrackingObjectId), &nextTrackingObjectId, sizeof(nextTrackingObjectId));
    CHECK_RETURN_ELOG(ret != 0, "memcpy_s failed, ret: %{public}d", ret);
    MEDIA_INFO_LOG("objectId: %{public}d (%{public}08x), startPts: %{public}" PRId64 " (%{public}016" PRIx64
        "), stopPts: %{public}" PRId64 " (%{public}016" PRIx64 "), nextTrackingObjectId: %{public}d (%{public}08x)",
        objectId, objectId, startPts, startPts, stopPts, stopPts, nextTrackingObjectId, nextTrackingObjectId);
}

int32_t HStreamMetadata::GetDetectedObjectLifecycleBuffer(std::vector<uint8_t>& buffer)
{
    std::lock_guard<std::mutex> lock(objectLifecycleMutex_);
    isDetectedObjectLifecycleReportEnabled_.store(false);

    int64_t tailDuration = MS_PER_S / CINEMATIC_DEFAULT_FPS;
    CHECK_EXECUTE(lastFrameDuration_ > 0, tailDuration = lastFrameDuration_);
    MEDIA_DEBUG_LOG("tailDuration: %{public}" PRId64, tailDuration);
    for (int32_t objectId : prevIds_) {
        objectLifecycleMap_[objectId].second = prevTs_ + tailDuration;
    }

    const int64_t maxPts = stopTime_ - firstFrameTimestamp_ + tailDuration;
    CHECK_RETURN_RET_DLOG(firstFrameTimestamp_ < 0, CAMERA_OK, "firstFrameTimestamp_:%{public}" PRId64 " is invalid",
                          firstFrameTimestamp_);
    for (const auto &entry : objectLifecycleMap_) {
        int32_t objectId = entry.first;
        int64_t startPts = entry.second.first - firstFrameTimestamp_;
        int64_t stopPts = entry.second.second - firstFrameTimestamp_;
        CHECK_EXECUTE(startPts < 0, startPts = 0);
        CHECK_EXECUTE(stopTime_ != -1 && stopPts > maxPts, stopPts = maxPts);
        if (stopPts < startPts) {
            MEDIA_ERR_LOG("invalid object lifecycle, #%{public}d: [%{public}" PRId64 ",%{public}" PRId64 "]", objectId,
                          startPts, stopPts);
            continue;
        }
        int32_t nextTrackingObjectId = -1;
        if (objectTrackingMap_.find(objectId) != objectTrackingMap_.end()) {
            nextTrackingObjectId = objectTrackingMap_[objectId];
        }
        MEDIA_INFO_LOG("ObjectLifecycleMap Info, objectId: %{public}d, startTs: %{public}" PRId64
                       ", endTs: %{public}" PRId64 ", nextTrackingObjectId: %{public}d",
                       entry.first, entry.second.first, entry.second.second, nextTrackingObjectId);
        std::vector<uint8_t> lifecycleBuffer;
        FillLifecycleBuffer(lifecycleBuffer, objectId, startPts, stopPts, nextTrackingObjectId);
        buffer.insert(buffer.end(), lifecycleBuffer.begin(), lifecycleBuffer.end());
    }
    MEDIA_INFO_LOG("GetDetectedObjectLifecycleBuffer count: %{public}zu, res size: %{public}zu",
                    objectLifecycleMap_.size(), buffer.size());
    stopTime_ = -1;
    objectLifecycleMap_.clear();
    objectTrackingMap_.clear();
    prevIds_.clear();
    return CAMERA_OK;
}
} // namespace Standard
} // namespace OHOS
