/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hstream_depth_data.h"

#include <cstdint>

#include "camera_device_ability_items.h"
#include "camera_log.h"
#include "camera_metadata_operator.h"
#include "camera_service_ipc_interface_code.h"
#include "display_manager.h"
#include "camera_util.h"
#include "hstream_common.h"
#include "ipc_skeleton.h"
#include "istream_depth_data_callback.h"
#include "metadata_utils.h"
#include "camera_report_uitls.h"

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
HStreamDepthData::HStreamDepthData(
    sptr<OHOS::IBufferProducer> producer, int32_t format, int32_t width, int32_t height)
    : HStreamCommon(StreamType::DEPTH, producer, format, width, height)
{
    MEDIA_INFO_LOG("HStreamDepthData::HStreamDepthData construct, format:%{public}d, size:%{public}dx%{public}d, "
        "streamId:%{public}d",
        format, width, height, GetFwkStreamId());
}

HStreamDepthData::~HStreamDepthData()
{
    MEDIA_INFO_LOG("HStreamDepthData::~HStreamDepthData deconstruct, format:%{public}d size:%{public}dx%{public}d "
                   "streamId:%{public}d, hdiStreamId:%{public}d",
        format_, width_, height_, GetFwkStreamId(), GetHdiStreamId());
}

int32_t HStreamDepthData::LinkInput(sptr<OHOS::HDI::Camera::V1_0::IStreamOperator> streamOperator,
    std::shared_ptr<OHOS::Camera::CameraMetadata> cameraAbility)
{
    MEDIA_INFO_LOG("HStreamDepthData::LinkInput streamId:%{public}d", GetFwkStreamId());
    int32_t ret = HStreamCommon::LinkInput(streamOperator, cameraAbility);
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HStreamDepthData::LinkInput err, streamId:%{public}d ,err:%{public}d", GetFwkStreamId(), ret);
        return ret;
    }
    return CAMERA_OK;
}

void HStreamDepthData::SetStreamInfo(StreamInfo_V1_1& streamInfo)
{
    HStreamCommon::SetStreamInfo(streamInfo);
    streamInfo.v1_0.intent_ =
        static_cast<OHOS::HDI::Camera::V1_0::StreamIntent>(OHOS::HDI::Camera::V1_3::StreamType::STREAM_TYPE_DEPTH);
}

int32_t HStreamDepthData::SetDataAccuracy(int32_t accuracy)
{
    MEDIA_INFO_LOG("HStreamDepthData::SetDataAccuracy accuracy: %{public}d", accuracy);
    streamDepthDataAccuracy_ = {accuracy};
    std::vector<uint8_t> ability;
    std::vector<uint8_t> depthSettings;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, ability);
        std::shared_ptr<OHOS::Camera::CameraMetadata> dynamicSetting = nullptr;
        OHOS::Camera::MetadataUtils::ConvertVecToMetadata(ability, dynamicSetting);
        camera_metadata_item_t item;
        CHECK_AND_RETURN_RET_LOG(dynamicSetting != nullptr, CAMERA_INVALID_ARG,
            "HStreamDepthData::SetDataAccuracy dynamicSetting is nullptr.");
        int ret = OHOS::Camera::FindCameraMetadataItem(dynamicSetting->get(), OHOS_CONTROL_DEPTH_DATA_ACCURACY, &item);
        bool status = false;
        if (ret == CAM_META_ITEM_NOT_FOUND) {
            MEDIA_DEBUG_LOG("HStreamDepthData::SetDataAccuracy Failed to find data accuracy");
            status = dynamicSetting->addEntry(
                OHOS_CONTROL_DEPTH_DATA_ACCURACY, streamDepthDataAccuracy_.data(), streamDepthDataAccuracy_.size());
        } else if (ret == CAM_META_SUCCESS) {
            MEDIA_DEBUG_LOG("HStreamDepthData::SetDataAccuracy success to find data accuracy");
            status = dynamicSetting->updateEntry(
                OHOS_CONTROL_DEPTH_DATA_ACCURACY, streamDepthDataAccuracy_.data(), streamDepthDataAccuracy_.size());
        }
        if (!status) {
            MEDIA_ERR_LOG("HStreamDepthData::SetDataAccuracy Failed to set data accuracy");
        }
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(dynamicSetting, depthSettings);
    }

    auto streamOperator = GetStreamOperator();

    CamRetCode rc = HDI::Camera::V1_0::NO_ERROR;
    if (streamOperator != nullptr) {
        std::lock_guard<std::mutex> startStopLock(streamStartStopLock_);
        CaptureInfo captureInfo;
        captureInfo.streamIds_ = {GetHdiStreamId()};
        captureInfo.captureSetting_ = depthSettings;
        captureInfo.enableShutterCallback_ = false;
        int32_t currentCaptureId = GetPreparedCaptureId();
        MEDIA_INFO_LOG("HStreamDepthData::SetDataAccuracy stream:%{public}d, with settingCapture ID:%{public}d",
            GetFwkStreamId(), currentCaptureId);
        rc = (CamRetCode)(streamOperator->Capture(currentCaptureId, captureInfo, true));
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            MEDIA_ERR_LOG("HStreamDepthData::SetDataAccuracy Failed with error Code:%{public}d", rc);
        }
    }
    return rc;
}

int32_t HStreamDepthData::Start()
{
    CAMERA_SYNC_TRACE;
    auto streamOperator = GetStreamOperator();
    if (streamOperator == nullptr) {
        return CAMERA_INVALID_STATE;
    }

    auto preparedCaptureId = GetPreparedCaptureId();
    if (preparedCaptureId != CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamDepthData::Start, Already started with captureID: %{public}d", preparedCaptureId);
        return CAMERA_INVALID_STATE;
    }

    int32_t ret = PrepareCaptureId();
    preparedCaptureId = GetPreparedCaptureId();
    if (ret != CAMERA_OK || preparedCaptureId == CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamDepthData::Start Failed to allocate a captureId");
        return ret;
    }

    std::vector<uint8_t> ability;
    {
        std::lock_guard<std::mutex> lock(cameraAbilityLock_);
        OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraAbility_, ability);
    }

    CaptureInfo captureInfo;
    captureInfo.streamIds_ = { GetHdiStreamId() };
    captureInfo.captureSetting_ = ability;
    captureInfo.enableShutterCallback_ = false;
    MEDIA_INFO_LOG("HStreamDepthData::Start streamId:%{public}d hdiStreamId:%{public}d With capture ID: %{public}d",
        GetFwkStreamId(), GetHdiStreamId(), preparedCaptureId);

    std::lock_guard<std::mutex> startStopLock(streamStartStopLock_);
    HStreamCommon::PrintCaptureDebugLog(cameraAbility_);
    CamRetCode rc = (CamRetCode)(streamOperator->Capture(preparedCaptureId, captureInfo, true));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        ResetCaptureId();
        MEDIA_ERR_LOG("HStreamDepthData::Start Failed with error Code:%{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "HStreamDepthData::Start", rc, true, CameraReportUtils::GetCallerInfo());
        ret = HdiToServiceError(rc);
    } else {
        depthDataStreamStatus_ = DepthDataStreamStatus::STARTED;
    }

    return ret;
}

int32_t HStreamDepthData::Stop()
{
    CAMERA_SYNC_TRACE;
    auto streamOperator = GetStreamOperator();
    if (streamOperator == nullptr) {
        MEDIA_INFO_LOG("HStreamDepthData::Stop streamOperator is null");
        return CAMERA_INVALID_STATE;
    }
    auto preparedCaptureId = GetPreparedCaptureId();
    MEDIA_INFO_LOG("HStreamDepthData::Start streamId:%{public}d hdiStreamId:%{public}d With capture ID: %{public}d",
        GetFwkStreamId(), GetHdiStreamId(), preparedCaptureId);
    if (preparedCaptureId == CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamDepthData::Stop, Stream not started yet");
        return CAMERA_INVALID_STATE;
    }
    int32_t ret = CAMERA_OK;
    {
        std::lock_guard<std::mutex> startStopLock(streamStartStopLock_);
        ret = StopStream();
        if (ret != CAMERA_OK) {
            MEDIA_ERR_LOG("HStreamDepthData::Stop Failed with errorCode:%{public}d, curCaptureID_: %{public}d",
                          ret, preparedCaptureId);
        } else {
            depthDataStreamStatus_ = DepthDataStreamStatus::STOPED;
        }
    }
    return ret;
}

int32_t HStreamDepthData::Release()
{
    return ReleaseStream(false);
}

int32_t HStreamDepthData::ReleaseStream(bool isDelay)
{
    {
        std::lock_guard<std::mutex> lock(callbackLock_);
        streamDepthDataCallback_ = nullptr;
    }
    return HStreamCommon::ReleaseStream(isDelay);
}

int32_t HStreamDepthData::SetCallback(sptr<IStreamDepthDataCallback>& callback)
{
    if (callback == nullptr) {
        MEDIA_ERR_LOG("HStreamDepthData::SetCallback callback is null");
        return CAMERA_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(callbackLock_);
    streamDepthDataCallback_ = callback;
    return CAMERA_OK;
}

int32_t HStreamDepthData::OnDepthDataError(int32_t errorType)
{
    std::lock_guard<std::mutex> lock(callbackLock_);
    if (streamDepthDataCallback_ != nullptr) {
        int32_t depthDataErrorCode;
        if (errorType == BUFFER_LOST) {
            depthDataErrorCode = CAMERA_STREAM_BUFFER_LOST;
        } else {
            depthDataErrorCode = CAMERA_UNKNOWN_ERROR;
        }
        CAMERA_SYSEVENT_FAULT(CreateMsg("Depth OnDepthDataError! errorCode:%d", depthDataErrorCode));
        streamDepthDataCallback_->OnDepthDataError(depthDataErrorCode);
    }
    return CAMERA_OK;
}

void HStreamDepthData::DumpStreamInfo(CameraInfoDumper& infoDumper)
{
    infoDumper.Title("depth stream");
    HStreamCommon::DumpStreamInfo(infoDumper);
}

int32_t HStreamDepthData::OperatePermissionCheck(uint32_t interfaceCode)
{
    switch (static_cast<StreamDepthDataInterfaceCode>(interfaceCode)) {
        case StreamDepthDataInterfaceCode::CAMERA_STREAM_DEPTH_DATA_START: {
            auto callerToken = IPCSkeleton::GetCallingTokenID();
            if (callerToken_ != callerToken) {
                MEDIA_ERR_LOG("HStreamDepthData::OperatePermissionCheck fail, callerToken invalid!");
                return CAMERA_OPERATION_NOT_ALLOWED;
            }
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}
} // namespace CameraStandard
} // namespace OHOS