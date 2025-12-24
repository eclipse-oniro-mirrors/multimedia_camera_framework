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
    unifyMovieFileOutputListenerManager_->SetUnifyMovieFileOutput(this);
    MEDIA_DEBUG_LOG("UnifyMovieFileOutput::UnifyMovieFileOutput() is called");
}

UnifyMovieFileOutput::~UnifyMovieFileOutput()
{
    MEDIA_DEBUG_LOG("UnifyMovieFileOutput::~UnifyMovieFileOutput() is called");
}

int32_t UnifyMovieFileOutput::Release()
{
    CAMERA_SYNC_TRACE;
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET(proxy, proxy->Release());
    return CameraErrorCode::SERVICE_FATL_ERROR;
}

void UnifyMovieFileOutput::CameraServerDied(pid_t pid)
{
    ClearMovieFileOutputProxy();
}

int32_t UnifyMovieFileOutput::CreateStream()
{
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::SetOutputSettings(std::shared_ptr<MovieSettings> movieSettings)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::SetOutputSettings is called");
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(
        proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::SetOutputSettings proxy is null");
    MEDIA_INFO_LOG("UnifyMovieFileOutput::SetOutputSettings movieSettings has_value: bitrate:%{public}d",
        movieSettings->videoBitrate);
    int32_t errCode = proxy->SetOutputSettings(*movieSettings);
    CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, ServiceToCameraError(errCode),
        "UnifyMovieFileOutput::SetOutputSettings errCode: %{public}d", errCode);
    {
        std::lock_guard<std::mutex> lock(currentMovieFileOutputSettingsMutex_);
        currentMovieFileOutputSettings_ = movieSettings;
    }
    return ServiceToCameraError(errCode);
}

std::shared_ptr<MovieSettings> UnifyMovieFileOutput::GetOutputSettings()
{
    // todo 如果应用未设置该选项，服务侧的默认选项和该值不一致，需要到服务侧获取
    std::lock_guard<std::mutex> lock(currentMovieFileOutputSettingsMutex_);
    return currentMovieFileOutputSettings_;
}

int32_t UnifyMovieFileOutput::GetSupportedVideoCodecTypes(std::vector<int32_t>& supportedVideoCodecTypes)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoCodecTypes is called");
    supportedVideoCodecTypes.clear();
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "MovieFileOutput::GetSupportedVideoCodecTypes failed due to captureSession is nullptr");
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "MovieFileOutput::GetSupportedVideoCodecTypes failed due to inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "MovieFileOutput::GetSupportedVideoCodecTypes failed due to cameraObj is nullptr");
    int32_t retCode = captureSession->GetSupportedVideoCodecTypes(supportedVideoCodecTypes);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, retCode,
        "MovieFileOutput::GetSupportedVideoCodecTypes failed, retCode: %{public}d", retCode);
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::GetSupportedVideoFilters(std::vector<std::string>& supportedVideoFilters)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::GetSupportedVideoFilters is called");
    static const std::string ORIGIN_FILTER = "origin";
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(
        proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::GetSupportedVideoFilters proxy is null");

    supportedVideoFilters.clear();
    int32_t errCode = proxy->GetSupportedVideoFilters(supportedVideoFilters);

    CHECK_RETURN_RET_ELOG(errCode != CamServiceError::CAMERA_OK, ServiceToCameraError(errCode),
        "UnifyMovieFileOutput::GetSupportedVideoFilters errCode: %{public}d", errCode);
    bool isOriginExist = std::any_of(supportedVideoFilters.begin(), supportedVideoFilters.end(),
        [](std::string& filter) { return ORIGIN_FILTER == filter; });

    if (!isOriginExist) {
        supportedVideoFilters.push_back(ORIGIN_FILTER);
    }

    MEDIA_INFO_LOG("UnifyMovieFileOutput::GetSupportedVideoFilters end");
    return ServiceToCameraError(errCode);
}

int32_t UnifyMovieFileOutput::AddVideoFilter(const std::string& filter, const std::string& filterParam)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::AddVideoFilter is called");
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::AddVideoFilter proxy is null");
    auto errCode = proxy->AddVideoFilter(filter, filterParam);
    CHECK_RETURN_RET_ELOG(errCode != CamServiceError::CAMERA_OK, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput::AddVideoFilter errCode: %{public}d", errCode);
    MEDIA_INFO_LOG("UnifyMovieFileOutput::AddVideoFilter end");
    return ServiceToCameraError(errCode);
}

int32_t UnifyMovieFileOutput::RemoveVideoFilter(const std::string& filter)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::RemoveVideoFilter is called");
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(
        proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::RemoveVideoFilter proxy is null");
    auto errCode = proxy->RemoveVideoFilter(filter);
    CHECK_RETURN_RET_ELOG(errCode != CamServiceError::CAMERA_OK, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput::RemoveVideoFilter errCode: %{public}d", errCode);
    MEDIA_INFO_LOG("UnifyMovieFileOutput::RemoveVideoFilter end");
    return ServiceToCameraError(errCode);
}

bool UnifyMovieFileOutput::IsMirrorSupported()
{
    MEDIA_INFO_LOG("MovieFileOutput::IsMirrorSupported is called");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, false, "MovieFileOutput::IsMirrorSupported session is nullptr");
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, false, "MovieFileOutput IsMirrorSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        cameraObj == nullptr, false, "MovieFileOutput IsMirrorSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    CHECK_RETURN_RET_ELOG(metadata == nullptr, false, "MovieFileOutput IsMirrorSupported error!, metadata is nullptr");
    camera_metadata_item_t item;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(
        retCode != CAM_META_SUCCESS, false, "MovieFileOutput Can not find OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED");
    int step = 2;
    const int32_t canMirrorVideoAndPhoto = 2;
    bool isMirrorSupported = false;
    SceneMode currentSceneMode = session->GetMode();
    for (int i = 0; i < static_cast<int>(item.count); i += step) {
        MEDIA_DEBUG_LOG("mode u8[%{public}d]: %{public}d, u8[%{public}d], %{public}d", i, item.data.u8[i], i + 1,
            item.data.u8[i + 1]);
        if (currentSceneMode == static_cast<int>(item.data.u8[i])) {
            isMirrorSupported = (item.data.u8[i + 1] == canMirrorVideoAndPhoto) ? true : false;
        }
    }
    MEDIA_INFO_LOG("MovieFileOutput::IsMirrorSupported isSupport: %{public}d", isMirrorSupported);
    return isMirrorSupported;
}

int32_t UnifyMovieFileOutput::EnableMirror(bool isEnable)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::EnableMirror is called, isEnable: %{public}d", isEnable);
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::EnableMirror proxy is null");
    auto errCode = proxy->EnableMirror(isEnable);
    CHECK_RETURN_RET_ELOG(errCode != CamServiceError::CAMERA_OK, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput::EnableMirror errCode: %{public}d", errCode);
    MEDIA_INFO_LOG("UnifyMovieFileOutput::EnableMirror end");
    return ServiceToCameraError(errCode);
}

int32_t UnifyMovieFileOutput::Start()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Start start");
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::Start proxy is null");
    auto errCode = proxy->Start();
    CHECK_RETURN_RET_ELOG(errCode != CamServiceError::CAMERA_OK, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput::Start errCode: %{public}d", errCode);
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Start end");
    return ServiceToCameraError(errCode);
}

int32_t UnifyMovieFileOutput::Pause()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Pause start");
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::Pause proxy is null");
    auto errCode = proxy->Pause();
    CHECK_RETURN_RET_ELOG(errCode != CamServiceError::CAMERA_OK, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput::Pause errCode: %{public}d", errCode);
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Pause end");
    return ServiceToCameraError(errCode);
}

int32_t UnifyMovieFileOutput::Resume()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Resume start");
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::Resume proxy is null");
    auto errCode = proxy->Resume();
    CHECK_RETURN_RET_ELOG(errCode != CamServiceError::CAMERA_OK, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput::Resume errCode: %{public}d", errCode);
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Resume end");
    return ServiceToCameraError(errCode);
}

int32_t UnifyMovieFileOutput::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Stop start");
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::Stop proxy is null");
    auto errCode = proxy->Stop();
    CHECK_RETURN_RET_ELOG(errCode != CamServiceError::CAMERA_OK, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput::Stop errCode: %{public}d", errCode);
    MEDIA_INFO_LOG("UnifyMovieFileOutput::Stop end");
    return ServiceToCameraError(errCode);
}

void UnifyMovieFileOutput::AddUnifyMovieFileOutputStateCallback(
    std::shared_ptr<UnifyMovieFileOutputStateCallback> callback)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::AddUnifyMovieFileOutputStateCallback start");
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_ELOG(proxy == nullptr, "UnifyMovieFileOutput::AddUnifyMovieFileOutputStateCallback proxy is null");
    bool isSuccess = unifyMovieFileOutputListenerManager_->AddListener(callback);
    CHECK_RETURN(!isSuccess);
    if (unifyMovieFileOutputListenerManager_->GetListenerCount() == 1) {
        sptr<IMovieFileOutputCallback> ipcCallback = unifyMovieFileOutputListenerManager_;
        auto errCode = proxy->SetMovieFileOutputCallback(ipcCallback);
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("UnifyMovieFileOutput::AddUnifyMovieFileOutputStateCallback fail");
            unifyMovieFileOutputListenerManager_->RemoveListener(callback);
        }
    }
}

void UnifyMovieFileOutput::RemoveUnifyMovieFileOutputStateCallback(
    std::shared_ptr<UnifyMovieFileOutputStateCallback> callback)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("UnifyMovieFileOutput::RemoveUnifyMovieFileOutputStateCallback start");
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_ELOG(proxy == nullptr, "UnifyMovieFileOutput::RemoveUnifyMovieFileOutputStateCallback proxy is null");

    unifyMovieFileOutputListenerManager_->RemoveListener(callback);
    if (unifyMovieFileOutputListenerManager_->GetListenerCount() == 0) {
        auto errCode = proxy->UnsetMovieFileOutputCallback();
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "UnifyMovieFileOutput::AddUnifyMovieFileOutputStateCallback fail");
    }
}

int32_t UnifyMovieFileOutput::IsAutoDeferredVideoEnhancementSupported(bool& isSupported)
{
    MEDIA_INFO_LOG("IsAutoDeferredVideoEnhancementSupported");
    sptr<CameraDevice> cameraObj;
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput IsAutoDeferredVideoEnhancementSupported error!, captureSession is nullptr");
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput IsAutoDeferredVideoEnhancementSupported error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput IsAutoDeferredVideoEnhancementSupported error!, cameraObj is nullptr");

    int32_t curMode = captureSession->GetMode();
    isSupported = cameraObj->GetModeVideoDeferredType(curMode) == OHOS_CAMERA_SUPPORTED;
    MEDIA_INFO_LOG(
        "IsAutoDeferredVideoEnhancementSupported curMode:%{public}d, modeSupportType:%{public}d", curMode, isSupported);
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::IsAutoDeferredVideoEnhancementEnabled(bool& isEnabled)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput IsAutoDeferredVideoEnhancementEnabled");
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput IsAutoDeferredVideoEnhancementEnabled error!, captureSession is nullptr");

    isEnabled = captureSession->IsVideoDeferred();
    MEDIA_INFO_LOG("IsAutoDeferredVideoEnhancementEnabled isEnabled:%{public}d", isEnabled);
    return isEnabled;
}

int32_t UnifyMovieFileOutput::EnableAutoDeferredVideoEnhancement(bool enabled)
{
    MEDIA_INFO_LOG("EnableAutoDeferredVideoEnhancement");
    CAMERA_SYNC_TRACE;
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput EnableAutoDeferredVideoEnhancement error!, captureSession is nullptr");

    captureSession->EnableAutoDeferredVideoEnhancement(enabled);
    captureSession->SetUserId();
    return CameraErrorCode::SUCCESS;
}

bool UnifyMovieFileOutput::IsAutoVideoFrameRateSupported()
{
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(
        session == nullptr, false, "UnifyMovieFileOutput IsAutoVideoFrameRateSupported error!, session is nullptr");
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, false,
        "UnifyMovieFileOutput IsAutoVideoFrameRateSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        cameraObj == nullptr, false, "UnifyMovieFileOutput IsAutoVideoFrameRateSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, false);
    camera_metadata_item_t item;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AUTO_VIDEO_FRAME_RATE, &item);
    CHECK_RETURN_RET_ELOG(
        retCode != CAM_META_SUCCESS, false, "UnifyMovieFileOutput Can not find OHOS_ABILITY_AUTO_VIDEO_FRAME_RATE");
    bool isAutoVideoFrameRateSupported = false;
    SceneMode currentSceneMode = session->GetMode();
    for (int i = 0; i < static_cast<int>(item.count); i++) {
        MEDIA_DEBUG_LOG("mode u8[%{public}d]: %{public}d", i, item.data.u8[i]);
        if (currentSceneMode == static_cast<SceneMode>(item.data.u8[i])) {
            isAutoVideoFrameRateSupported = true;
            break;
        }
    }
    MEDIA_DEBUG_LOG("IsAutoVideoFrameRateSupported isSupport: %{public}d", isAutoVideoFrameRateSupported);
    return isAutoVideoFrameRateSupported;
}

int32_t UnifyMovieFileOutput::EnableAutoVideoFrameRate(bool enable)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput::EnableAutoVideoFrameRate enable: %{public}d", enable);
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "UnifyMovieFileOutput IsAutoVideoFrameRateSupported error!, session is nullptr");
    bool isSupportedAutoVideoFps = IsAutoVideoFrameRateSupported();
    CHECK_RETURN_RET_ELOG(!isSupportedAutoVideoFps, CameraErrorCode::INVALID_ARGUMENT,
        "UnifyMovieFileOutput::EnableAutoVideoFrameRate does not supported.");
    session->LockForControl();
    session->EnableAutoFrameRate(enable);
    session->UnlockForControl();
    return CameraErrorCode::SUCCESS;
}

int32_t UnifyMovieFileOutput::GetVideoRotation(int32_t& imageRotation)
{
    MEDIA_INFO_LOG("UnifyMovieFileOutput GetVideoRotation is called");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(
        session == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput GetVideoRotation error!, session is nullptr");
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput GetVideoRotation error!, inputDevice is nullptr");

    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(proxy == nullptr, SERVICE_FATL_ERROR, "UnifyMovieFileOutput::GetVideoRotation proxy is null");
    bool isMirrorEnabled = false;
    int32_t retCode = proxy->IsMirrorEnabled(isMirrorEnabled);
    CHECK_RETURN_RET_ELOG(retCode != CamServiceError::CAMERA_OK, SERVICE_FATL_ERROR,
        "UnifyMovieFileOutput::GetVideoRotation errCode: %{public}d", retCode);

    imageRotation = CameraDeviceUtils::CalculateImageRotation(inputDevice, imageRotation, isMirrorEnabled);
    return CameraErrorCode::SUCCESS;
}

sptr<VideoCapability> UnifyMovieFileOutput::GetSupportedVideoCapability(int32_t videoCodecType)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoCapability is called");
    CHECK_RETURN_RET(videoCapability_ != nullptr && videoCapability_->codecType_ == videoCodecType,
            videoCapability_);
    auto proxy = GetMovieFileOutputProxy();
    CHECK_RETURN_RET_ELOG(proxy == nullptr, nullptr, "UnifyMovieFileOutput::GetVideoRotation proxy is null");
    std::shared_ptr<MediaCapabilityProxy> capabilityOut;
    int32_t retCode = proxy->GetSupportedVideoCapability(videoCodecType, capabilityOut);
    CHECK_RETURN_RET_ELOG(retCode != CamServiceError::CAMERA_OK, nullptr,
        "UnifyMovieFileOutput::GetSupportedVideoCapability errCode: %{public}d", retCode);
    {
        std::lock_guard<std::mutex> lock(videoCapabilityMutex_);
        videoCapability_ = sptr<VideoCapability>::MakeSptr(capabilityOut->GetBFrameSupported());
        videoCapability_->codecType_ = videoCodecType;
    }
    return videoCapability_;
}

int32_t UnifyMovieFileOutputListenerManager::OnRecordingStart()
{
    CAMERA_SYNC_TRACE;
    auto output = GetUnifyMovieFileOutput();
    CHECK_RETURN_RET_ELOG(
        output == nullptr, CAMERA_OK, "UnifyMovieFileOutputListenerManager::OnRecordingStart output is null");
    auto listenMgr = output->GetUnifyMovieFileOutputListenerManager();
    CHECK_RETURN_RET_ELOG(
        listenMgr == nullptr, CAMERA_OK, "UnifyMovieFileOutputListenerManager::OnRecordingStart listenMgr is null");
    listenMgr->TriggerListener([](auto listener) { listener->OnStart(); });
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnRecordingPause()
{
    CAMERA_SYNC_TRACE;
    auto output = GetUnifyMovieFileOutput();
    CHECK_RETURN_RET_ELOG(
        output == nullptr, CAMERA_OK, "UnifyMovieFileOutputListenerManager::OnRecordingPause output is null");
    output->GetUnifyMovieFileOutputListenerManager()->TriggerListener([](auto listener) { listener->OnPause(); });
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnRecordingResume()
{
    CAMERA_SYNC_TRACE;
    auto output = GetUnifyMovieFileOutput();
    CHECK_RETURN_RET_ELOG(
        output == nullptr, CAMERA_OK, "UnifyMovieFileOutputListenerManager::OnRecordingResume output is null");
    output->GetUnifyMovieFileOutputListenerManager()->TriggerListener([](auto listener) { listener->OnResume(); });
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnRecordingStop()
{
    CAMERA_SYNC_TRACE;
    auto output = GetUnifyMovieFileOutput();
    CHECK_RETURN_RET_ELOG(
        output == nullptr, CAMERA_OK, "UnifyMovieFileOutputListenerManager::OnRecordingStop output is null");
    output->GetUnifyMovieFileOutputListenerManager()->TriggerListener([](auto listener) { listener->OnStop(); });
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnMovieInfoAvailable(int32_t captureId, const std::string& uri)
{
    CAMERA_SYNC_TRACE;
    auto output = GetUnifyMovieFileOutput();
    CHECK_RETURN_RET_ELOG(
        output == nullptr, CAMERA_OK, "UnifyMovieFileOutputListenerManager::OnMovieInfoAvailable output is null");
    output->GetUnifyMovieFileOutputListenerManager()->TriggerListener(
        [captureId, uri](auto listener) { listener->OnMovieInfoAvailable(captureId, uri); });
    return CAMERA_OK;
}

int32_t UnifyMovieFileOutputListenerManager::OnError(const int32_t errorCode)
{
    CAMERA_SYNC_TRACE;
    auto output = GetUnifyMovieFileOutput();
    CHECK_RETURN_RET_ELOG(output == nullptr, CAMERA_OK, "UnifyMovieFileOutputListenerManager::OnError output is null");
    output->GetUnifyMovieFileOutputListenerManager()->TriggerListener(
        [errorCode](auto listener) { listener->OnError(errorCode); });
    return CAMERA_OK;
}

} // namespace CameraStandard
} // namespace OHOS