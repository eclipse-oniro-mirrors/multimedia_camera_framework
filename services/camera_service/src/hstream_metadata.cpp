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

#include "camera_log.h"
#include "camera_service_ipc_interface_code.h"
#include "camera_util.h"
#include "hstream_common.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "camera_report_uitls.h"
#include <cstdint>
#include <unordered_set>

namespace OHOS {
namespace CameraStandard {
constexpr int32_t DEFAULT_ITEMS = 1;
constexpr int32_t DEFAULT_DATA_LENGTH = 10;
static const std::unordered_map<MetadataObjectType, uint8_t> g_FwkToHALResultCameraMetaDetect_ = {
    {MetadataObjectType::FACE, 0},
    {MetadataObjectType::HUMAN_BODY, 1},
    {MetadataObjectType::CAT_FACE, 2},
    {MetadataObjectType::CAT_BODY, 3},
    {MetadataObjectType::DOG_FACE, 4},
    {MetadataObjectType::DOG_BODY, 5},
    {MetadataObjectType::SALIENT_DETECTION, 6},
    {MetadataObjectType::BAR_CODE_DETECTION, 7},
    {MetadataObjectType::BASE_FACE_DETECTION, 8}
};

using namespace OHOS::HDI::Camera::V1_0;
HStreamMetadata::HStreamMetadata(sptr<OHOS::IBufferProducer> producer,
    int32_t format, std::vector<int32_t> metadataTypes)
    : HStreamCommon(StreamType::METADATA, producer, format, producer->GetDefaultWidth(), producer->GetDefaultHeight()),
    metadataObjectTypes_(metadataTypes)
{}

HStreamMetadata::~HStreamMetadata()
{}

int32_t HStreamMetadata::LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    if (streamOperator == nullptr || cameraAbility == nullptr) {
        MEDIA_ERR_LOG("HStreamMetadata::LinkInput streamOperator is null");
        return CAMERA_INVALID_ARG;
    }
    SetStreamOperator(streamOperator);
    std::lock_guard<std::mutex> lock(cameraAbilityLock_);
    cameraAbility_ = cameraAbility;
    return CAMERA_OK;
}

void HStreamMetadata::SetStreamInfo(StreamInfo_V1_1 &streamInfo)
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
    switch (static_cast<StreamMetadataInterfaceCode>(interfaceCode)) {
        case StreamMetadataInterfaceCode::CAMERA_STREAM_META_START: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            if (callerToken_ != callerToken) {
                MEDIA_ERR_LOG("HStreamMetadata::OperatePermissionCheck fail, callerToken_ is : %{public}d, now token "
                              "is %{public}d",
                    callerToken_, callerToken);
                return CAMERA_OPERATION_NOT_ALLOWED;
            }
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

int32_t HStreamMetadata::EnableMetadataType(std::vector<int32_t> metadataTypes)
{
    int32_t rc = EnableOrDisableMetadataType(metadataTypes, true);
    CHECK_ERROR_RETURN_RET_LOG(rc != CAMERA_OK, rc, "HStreamMetadata::EnableMetadataType failed!");
    std::lock_guard<std::mutex> lock(metadataTypeMutex_);
    for (auto& element : metadataTypes) {
        metadataObjectTypes_.emplace_back(element);
    }
    return rc;
}
int32_t HStreamMetadata::DisableMetadataType(std::vector<int32_t> metadataTypes)
{
    int32_t rc = EnableOrDisableMetadataType(metadataTypes, false);
    CHECK_ERROR_RETURN_RET_LOG(rc != CAMERA_OK, rc, "HStreamMetadata::DisableMetadataType failed!");
    std::lock_guard<std::mutex> lock(metadataTypeMutex_);
    removeMetadataType(metadataTypes, metadataObjectTypes_);
    return rc;
}

int32_t HStreamMetadata::OnMetaResult(int32_t streamId, const std::vector<uint8_t>& result)
{
    CHECK_ERROR_RETURN_RET_LOG(result.size() == 0, CAMERA_INVALID_ARG, "onResult get null meta from HAL");
    std::lock_guard<std::mutex> lock(callbackLock_);
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraResult = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, cameraResult);
    if (cameraResult == nullptr) {
        cameraResult = std::make_shared<OHOS::Camera::CameraMetadata>(0, 0);
    }
    if (streamMetadataCallback_ != nullptr) {
        streamMetadataCallback_->OnMetadataResult(streamId, cameraResult);
    }
    return CAMERA_OK;
}

int32_t HStreamMetadata::SetCallback(sptr<IStreamMetadataCallback>& callback)
{
    CHECK_ERROR_RETURN_RET_LOG(callback == nullptr, CAMERA_INVALID_ARG, "HStreamCapture::SetCallback input is null");
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamMetadataCallback_ = callback;
    return CAMERA_OK;
}

int32_t HStreamMetadata::EnableOrDisableMetadataType(const std::vector<int32_t>& metadataTypes, const bool enable)
{
    MEDIA_DEBUG_LOG("HStreamMetadata::EnableOrDisableMetadataType enable: %{public}d, metadataTypes size: %{public}zu",
        enable, metadataTypes.size());
    auto streamOperator = GetStreamOperator();
    CHECK_ERROR_RETURN_RET_LOG(streamOperator == nullptr, CAMERA_INVALID_STATE,
        "HStreamMetadata::EnableMetadataType streamOperator is nullptr");
    streamOperator->GetVersion(majorVer_, minorVer_);
    if (majorVer_ < HDI_VERSION_1 || minorVer_ < HDI_VERSION_3) {
        MEDIA_DEBUG_LOG("EnableOrDisableMetadataType version: %{public}d.%{public}d", majorVer_, minorVer_);
        return CAMERA_OK;
    }
    int32_t ret = PrepareCaptureId();
    CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ret,
        "HStreamMetadata::EnableMetadataType Failed to allocate a captureId");
    sptr<OHOS::HDI::Camera::V1_3::IStreamOperator> streamOperatorV1_3 =
        OHOS::HDI::Camera::V1_3::IStreamOperator::CastFrom(streamOperator);
    CHECK_ERROR_RETURN_RET_LOG(streamOperatorV1_3 == nullptr, CAMERA_UNKNOWN_ERROR,
        "HStreamMetadata::EnableMetadataType streamOperatorV1_3 castFrom failed!");
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
    CHECK_ERROR_RETURN_RET_LOG(!status, CAMERA_UNKNOWN_ERROR, "set_camera_metadata failed!");
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
    CHECK_ERROR_RETURN_RET_LOG(rc != HDI::Camera::V1_2::NO_ERROR, HdiToServiceErrorV1_2(rc),
        "HStreamCapture::ConfirmCapture failed with error Code: %{public}d", rc);
    return ret;
}

void HStreamMetadata::removeMetadataType(std::vector<int32_t>& metaRes, std::vector<int32_t>& metaTarget)
{
    std::unordered_set<int32_t> set(metaRes.begin(), metaRes.end());
    metaTarget.erase(std::remove_if(metaTarget.begin(), metaTarget.end(),
                                    [&set](const int32_t &element) { return set.find(element) != set.end(); }),
                     metaTarget.end());
}
} // namespace Standard
} // namespace OHOS
