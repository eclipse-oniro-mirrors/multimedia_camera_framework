/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "output/movie_file_output.h"
#include "camera_device_utils.h"
#include "camera_log.h"
#include "camera_util.h"
#include "capture_session.h"
#include "display_manager_lite.h"
#include "parameters.h"

namespace OHOS {
namespace CameraStandard {

MovieFileOutput::MovieFileOutput()
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_MOVIE_FILE, StreamType::REPEAT, nullptr, nullptr)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::MovieFileOutput() is called");
}

MovieFileOutput::~MovieFileOutput()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::~MovieFileOutput() is called");
}

int32_t MovieFileOutput::CreateStream()
{
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::Release()
{
    MEDIA_INFO_LOG("MovieFileOutput::Release is called");
    return CameraErrorCode::SUCCESS;
}

void MovieFileOutput::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
}

int32_t MovieFileOutput::SetOutputSettings(const std::shared_ptr<MovieSettings>& movieSettings)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::SetOutputSettings is called");
    return CameraErrorCode::SUCCESS;
}

std::shared_ptr<MovieSettings> MovieFileOutput::GetOutputSettings()
{
    return currentSettings_;
}

sptr<VideoCapability> MovieFileOutput::GetSupportedVideoCapability(int32_t videoCodecType)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoCapability is called");
    return nullptr;
}

int32_t MovieFileOutput::GetSupportedVideoCodecTypes(std::vector<int32_t> &supportedVideoCodecTypes)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoCodecTypes is called");
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::Start()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::Start is called");
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::Pause()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::Pause is called");
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::Resume()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::Resume is called");
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::Stop()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::Stop is called");
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::SetRotation(int32_t rotation)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::SetRotation is called, rotation: %{public}d", rotation);
    return CameraErrorCode::SUCCESS;
}

void MovieFileOutput::SetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    videoFrameRateRange_ = {minFrameRate, maxFrameRate};
}

void MovieFileOutput::SetRawVideoStream(sptr<IStreamCommon> stream)
{
}

sptr<IStreamCommon> MovieFileOutput::GetRawVideoStream()
{
    return nullptr;
}

void MovieFileOutput::SetCallback(std::shared_ptr<IMovieFileOutputStateCallback> callback)
{
    MEDIA_INFO_LOG("MovieFileOutput::SetCallback is called");
}

void MovieFileOutput::AddRecorderCallback()
{
    MEDIA_INFO_LOG("MovieFileOutput::AddRecorderCallback is called");
}

std::shared_ptr<IMovieFileOutputStateCallback> MovieFileOutput::GetApplicationCallback()
{
    return nullptr;
}

void MovieFileOutput::SetRecorder(sptr<ICameraRecorder> recorder)
{
    CHECK_PRINT_ELOG(recorder == nullptr, "MovieFileOutput::SetRecorder failed, recorder is null");
}

bool MovieFileOutput::IsMirrorSupported()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::IsMirrorSupported is called");
    return false;
}

int32_t MovieFileOutput::EnableMirror(bool isEnable)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::EnableMirror is called, isEnable: %{public}d", isEnable);
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoFilters is called");
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::SetVideoFilter(const std::string& filter, const std::string& filterParam)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::SetVideoFilter is called");
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::GetCameraPosition()
{
    return CameraErrorCode::SUCCESS;
}

void MovieFileOutput::SetUserMeta()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::SetUserMeta is called");
}

int32_t MovieFileOutputCallbackImpl::OnRecordingStart()
{
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnRecordingPause()
{
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnRecordingResume()
{
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnRecordingStop()
{
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnPhotoAssetAvailable(const std::string& uri)
{
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnError(const int32_t errorCode)
{
    return CAMERA_OK;
}

} // namespace CameraStandard
} // namespace OHOS
