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

#include "unify_movie_file_output.h"

#include "camera_device.h"
#include "camera_device_utils.h"
#include "camera_log.h"
#include "camera_util.h"
#include "capture_session.h"
#include "media_capability_proxy.h"

namespace OHOS {
namespace CameraStandard {
UnifyMovieFileOutput::UnifyMovieFileOutput(sptr<IMovieFileOutput> movieFileOutputProxy)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_UNIFY_MOVIE_FILE, StreamType::UNIFY_MOVIE, nullptr, nullptr),
      movieFileOutputProxy_(movieFileOutputProxy)
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutput::UnifyMovieFileOutput() is called");
}

UnifyMovieFileOutput::~UnifyMovieFileOutput()
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutput::~UnifyMovieFileOutput() is called");
}

int32_t UnifyMovieFileOutput::Release()
{
    return CameraErrorCode::SUCCESS;
}

void UnifyMovieFileOutput::CameraServerDied(pid_t pid)
{
}

int32_t UnifyMovieFileOutput::CreateStream()
{
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::SetOutputSettings(std::shared_ptr<MovieSettings> movieSettings)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::SetOutputSettings is called");
    return CameraErrorCode::SUCCESS;
}

std::shared_ptr<MovieSettings> UnifyMovieFileOutput::GetOutputSettings()
{
    return nullptr;
}

int32_t UnifyMovieFileOutput::GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoCodecTypes is called");
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::GetSupportedVideoFilters(std::vector<std::string>& supportedVideoFilters)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::GetSupportedVideoFilters is called");
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::AddVideoFilter(const std::string& filter, const std::string& filterParam)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::AddVideoFilter is called");
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::RemoveVideoFilter(const std::string& filter)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::RemoveVideoFilter is called");
    return CameraErrorCode::SUCCESS;
}

bool UnifyMovieFileOutput::IsMirrorSupported()
{
    MEDIA_INFO_LOG("MovieFileOutput::IsMirrorSupported is called");
    return false;
}

int32_t UnifyMovieFileOutput::EnableMirror(bool isEnable)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::EnableMirror is called, isEnable: %{public}d", isEnable);
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::Start()
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Start start");
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::Pause()
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Pause start");
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::Resume()
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Resume start");
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::Stop()
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Stop start");
    return CameraErrorCode::SUCCESS;
}

void UnifyMovieFileOutput::AddUnifyMovieFileOutputStateCallback(
    std::shared_ptr<UnifyMovieFileOutputStateCallback> callback)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::AddUnifyMovieFileOutputStateCallback start");
}

void UnifyMovieFileOutput::RemoveUnifyMovieFileOutputStateCallback(
    std::shared_ptr<UnifyMovieFileOutputStateCallback> callback)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::RemoveUnifyMovieFileOutputStateCallback start");
}

int32_t UnifyMovieFileOutput::IsAutoDeferredVideoEnhancementSupported(bool& isSupported)
{
    MEDIA_INFO_LOG("IsAutoDeferredVideoEnhancementSupported");
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::IsAutoDeferredVideoEnhancementEnabled(bool& isEnabled)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput IsAutoDeferredVideoEnhancementEnabled");
    isEnabled = false;
    return isEnabled;
}

int32_t UnifyMovieFileOutput::EnableAutoDeferredVideoEnhancement(bool enabled)
{
    MEDIA_INFO_LOG("EnableAutoDeferredVideoEnhancement");
    return CameraErrorCode::SUCCESS;
}

bool UnifyMovieFileOutput::IsAutoVideoFrameRateSupported()
{
    return false;
}

int32_t UnifyMovieFileOutput::EnableAutoVideoFrameRate(bool enable)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::EnableAutoVideoFrameRate enable: %{public}d", enable);
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::GetVideoRotation(int32_t& imageRotation)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput GetVideoRotation is called");
    return CameraErrorCode::SUCCESS;
}

sptr<VideoCapability> UnifyMovieFileOutput::GetSupportedVideoCapability(int32_t videoCodecType)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoCapability is called");
    return nullptr;
}

int32_t UnifyMovieFileOutputListenerManager::OnRecordingStart()
{
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnRecordingPause()
{
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnRecordingResume()
{
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnRecordingStop()
{
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnMovieInfoAvailable(int32_t captureId, const std::string& uri)
{
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnError(const int32_t errorCode)
{
    return CAMERA_OK;
}

} // namespace CameraStandard
} // namespace OHOS