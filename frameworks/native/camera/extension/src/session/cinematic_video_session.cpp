/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "session/cinematic_video_session.h"

#include "camera_log.h"
#include "capture_output.h"
#include "capture_session.h"
#include "movie_file_output.h"

namespace OHOS {
namespace CameraStandard {
void CinematicVideoSession::CinematicVideoSessionMetadataResultProcessor::ProcessCallbacks(const uint64_t timestamp,
    const std::shared_ptr<OHOS::Camera::CameraMetadata> &result)
{
    auto session = cinematicVideoSession_.promote();
    CHECK_RETURN_ELOG(session == nullptr, "%{public}s session is null", __FUNCTION__);
    (void)timestamp;
    session->ProcessApertureEffectChange(result);
    session->ProcessAutoFocusUpdates(result);
    session->ProcessLcdFlashStatusUpdates(result);
}

CinematicVideoSession::CinematicVideoSession(sptr<ICaptureSession>& session)
    : CaptureSessionForSys(session)
{
    MEDIA_DEBUG_LOG("CinematicVideoSession::CinematicVideoSession is called");
    metadataResultProcessor_ = std::make_shared<CinematicVideoSessionMetadataResultProcessor>(this);
}

CinematicVideoSession::~CinematicVideoSession()
{
    MEDIA_DEBUG_LOG("CinematicVideoSession::~CinematicVideoSession");
}

int32_t CinematicVideoSession::AddOutput(sptr<CaptureOutput>& output)
{
    MEDIA_INFO_LOG("CinematicVideoSession::AddOutput is called");
    CHECK_RETURN_RET_ELOG(output == nullptr, SERVICE_FATL_ERROR, "output is null");
    int32_t result = CaptureSessionForSys::AddOutput(output);
    CHECK_RETURN_RET_ELOG(result != SUCCESS, result,
        "CinematicVideoSession::AddOutput failed, caused by CaptureSessionForSys::AddOutput");
    // enable focus tracking for metadata stream
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA) {
        MEDIA_INFO_LOG("CinematicVideoSession::AddOutput enable focus tracking for metadata stream");
        auto metaStream = static_cast<IStreamMetadata*>(output->GetStream().GetRefPtr());
        CHECK_RETURN_RET_ELOG(metaStream == nullptr, SERVICE_FATL_ERROR, "metaStream is null");
        metaStream->AddMetadataType({
            OHOS_CAMERA_BASE_TRACKING_REGION,
            OHOS_CAMERA_BASE_TRACKING_MODE,
            OHOS_CAMERA_BASE_TRACKING_OBJECT_ID,
            OHOS_CAMERA_TIMESTAMP
        });
        CHECK_EXECUTE(recorder_, recorder_->SetMetadataStream(metaStream));
        recorder_ = nullptr;
    }
    // expand raw video stream
    CHECK_RETURN_RET(output->GetOutputType() != CAPTURE_OUTPUT_TYPE_MOVIE_FILE, result);
    auto session = GetCaptureSession();
    auto movieFileOutput = static_cast<MovieFileOutput*>(output.GetRefPtr());
    CHECK_RETURN_RET_ELOG(
        session == nullptr || movieFileOutput == nullptr, SERVICE_FATL_ERROR, "session or movieFileOutput is null!");
    sptr<IStreamCommon> stream = movieFileOutput->GetStream();
    CHECK_RETURN_RET_ELOG(stream == nullptr, SERVICE_FATL_ERROR, "stream is null!");
    sptr<ICameraRecorder> recorder = nullptr;
    result = session->CreateRecorder(stream->AsObject(), recorder);
    recorder_ = recorder;
    movieFileOutput->SetRecorder(recorder);
    movieFileOutput->AddRecorderCallback();
    return result;
}

int32_t CinematicVideoSession::RemoveOutput(sptr<CaptureOutput>& output)
{
    MEDIA_INFO_LOG("CinematicVideoSession::RemoveOutput is called");
    int32_t result = CaptureSessionForSys::RemoveOutput(output);
    CHECK_RETURN_RET_ELOG(result != SUCCESS, result,
        "CinematicVideoSession::RemoveOutput failed, caused by CaptureSessionForSys::RemoveOutput");
    // disable focus tracking for metadata stream
    if (output->GetOutputType() == CAPTURE_OUTPUT_TYPE_METADATA) {
        MEDIA_INFO_LOG("CinematicVideoSession::RemoveOutput disable focus tracking for metadata stream");
        auto metaStream = static_cast<IStreamMetadata*>(output->GetStream().GetRefPtr());
        CHECK_RETURN_RET_ELOG(metaStream == nullptr, SERVICE_FATL_ERROR, "metaStream is null");
        metaStream->RemoveMetadataType({
            OHOS_CAMERA_BASE_TRACKING_REGION,
            OHOS_CAMERA_BASE_TRACKING_MODE,
            OHOS_CAMERA_BASE_TRACKING_OBJECT_ID,
            OHOS_CAMERA_TIMESTAMP
        });
    }
    // remove raw video stream
    CHECK_RETURN_RET(output->GetOutputType() != CAPTURE_OUTPUT_TYPE_MOVIE_FILE, result);
    auto session = GetCaptureSession();
    auto movieFileOutput = static_cast<MovieFileOutput*>(output.GetRefPtr());
    CHECK_RETURN_RET_ELOG(
        session == nullptr || movieFileOutput == nullptr, SERVICE_FATL_ERROR, "session or movieFileOutput is null!");
    result = session->RemoveOutput(output->GetStreamType(), movieFileOutput->GetRawVideoStream()->AsObject());
    return result;
}
} // namespace CameraStandard
} // namespace OHOS