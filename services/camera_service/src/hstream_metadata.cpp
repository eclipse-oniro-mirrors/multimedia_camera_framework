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

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_0;
HStreamMetadata::HStreamMetadata(sptr<OHOS::IBufferProducer> producer, int32_t format)
    : HStreamCommon(StreamType::METADATA, producer, format, producer->GetDefaultWidth(), producer->GetDefaultHeight())
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
    auto streamOperator = GetStreamOperator();
    if (streamOperator == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    auto preparedCaptureId = GetPreparedCaptureId();
    if (preparedCaptureId != CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamMetadata::Start, Already started with captureID: %{public}d", preparedCaptureId);
        return CAMERA_INVALID_STATE;
    }
    int32_t ret = PrepareCaptureId();
    preparedCaptureId = GetPreparedCaptureId();
    if (ret != CAMERA_OK || preparedCaptureId == CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamMetadata::Start Failed to allocate a captureId");
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
    MEDIA_INFO_LOG("HStreamMetadata::Start Starting with capture ID: %{public}d", preparedCaptureId);
    HStreamCommon::PrintCaptureDebugLog(cameraAbility_);
    CamRetCode rc = (CamRetCode)(streamOperator->Capture(preparedCaptureId, captureInfo, true));
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        ResetCaptureId();
        MEDIA_ERR_LOG("HStreamMetadata::Start Failed with error Code:%{public}d", rc);
        CameraReportUtils::ReportCameraError(
            "HStreamMetadata::SetStreamInfo", rc, true, CameraReportUtils::GetCallerInfo());
        ret = HdiToServiceError(rc);
    }
    return ret;
}

int32_t HStreamMetadata::Stop()
{
    CAMERA_SYNC_TRACE;
    auto streamOperator = GetStreamOperator();
    if (streamOperator == nullptr) {
        return CAMERA_INVALID_STATE;
    }
    auto preparedCaptureId = GetPreparedCaptureId();
    if (preparedCaptureId == CAPTURE_ID_UNSET) {
        MEDIA_ERR_LOG("HStreamMetadata::Stop, Stream not started yet");
        return CAMERA_INVALID_STATE;
    }
    int32_t ret = StopStream();
    if (ret != CAMERA_OK) {
        MEDIA_ERR_LOG("HStreamMetadata::Stop Failed with errorCode:%{public}d, curCaptureID_: %{public}d", ret,
            preparedCaptureId);
    }
    return ret;
}

int32_t HStreamMetadata::Release()
{
    return ReleaseStream(false);
}

int32_t HStreamMetadata::ReleaseStream(bool isDelay)
{
    return HStreamCommon::ReleaseStream(isDelay);
}

void HStreamMetadata::DumpStreamInfo(std::string& dumpString)
{
    dumpString += "metadata stream:\n";
    HStreamCommon::DumpStreamInfo(dumpString);
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
} // namespace Standard
} // namespace OHOS
