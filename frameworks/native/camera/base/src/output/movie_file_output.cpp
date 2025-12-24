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
#include "output/movie_file_output.h"
#include "camera_log.h"
#include "camera_util.h"
#include "capture_session.h"
#include "display_manager_lite.h"
#include "parameters.h"

namespace OHOS {
namespace CameraStandard {
namespace {
    const float DEFAULT_PHYSICAL_APERTURE = 2.0;
    const float DEFAULT_VIRTUAL_APERTURE = 2.4;
}
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
    {
        std::lock_guard<std::mutex> lock(outputCallbackMutex_);
        svcCallback_ = nullptr;
        appCallback_ = nullptr;
    }
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    CHECK_RETURN_RET_ELOG(recorder_ == nullptr, SERVICE_FATL_ERROR, "failed to release, recorder_ is null");
    int32_t errCode = recorder_->Release();
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "MovieFileOutput Failed to Release!, errCode: %{public}d", errCode);
    recorder_ = nullptr;
    CaptureOutput::Release();
    rawVideoStream_ = nullptr;
    return ServiceToCameraError(errCode);
}

void MovieFileOutput::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    if (appCallback_ != nullptr) {
        MEDIA_DEBUG_LOG("appCallback not nullptr");
        int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
        appCallback_->OnError(serviceErrorType);
    }
}

int32_t MovieFileOutput::SetOutputSettings(const std::shared_ptr<MovieSettings>& movieSettings)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::SetOutputSettings is called");
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    CHECK_RETURN_RET_ELOG(itemStream == nullptr, SERVICE_FATL_ERROR, "itemStream is nullptr");
    int32_t errCode = itemStream->SetOutputSettings(*movieSettings);
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to SetOutputSettings!, errCode: %{public}d", errCode);
    currentSettings_ = movieSettings;
    MEDIA_DEBUG_LOG("SetOutputSettings End");
    return ServiceToCameraError(errCode);
}

std::shared_ptr<MovieSettings> MovieFileOutput::GetOutputSettings()
{
    return currentSettings_;
}

sptr<VideoCapability> MovieFileOutput::GetSupportedVideoCapability(int32_t videoCodecType)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoCapability is called");
    std::lock_guard<std::mutex> lock(videoCapabilityMutex_);
    videoCapability_ = sptr<VideoCapability>::MakeSptr(false);
    return videoCapability_;
}

int32_t MovieFileOutput::GetSupportedVideoCodecTypes(std::vector<int32_t> &supportedVideoCodecTypes)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoCodecTypes is called");
    supportedVideoCodecTypes.clear();
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    CHECK_RETURN_RET_ELOG(itemStream == nullptr, SERVICE_FATL_ERROR, "itemStream is nullptr");
    itemStream->GetSupportedVideoCodecTypes(supportedVideoCodecTypes);
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::Start()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::Start is called");
    CHECK_RETURN_RET_ELOG(recorder_ == nullptr, SERVICE_FATL_ERROR, "failed to Start, recorder_ is null");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR, "session is nullptr");
    recorder_->EnableVirtualAperture(session->IsVirtualApertureEnabled());

    int32_t errCode = recorder_->Prepare();
    CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, errCode, "failed to Prepare recorder!, errCode: %{public}d", errCode);
    // set user meta for stabilization/aperture/xstyle/cinematic
    SetUserMeta();
    errCode = recorder_->Start();
    CHECK_RETURN_RET_ELOG(errCode != CAMERA_OK, errCode,
        "MovieFileOutput Failed to Start!, errCode: %{public}d", errCode);
    session->EnableKeyFrameReport(true);
    MEDIA_DEBUG_LOG("MovieFileOutput::Start end");
    return ServiceToCameraError(errCode);
}

int32_t MovieFileOutput::Pause()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::Pause is called");
    CHECK_RETURN_RET_ELOG(recorder_ == nullptr, SERVICE_FATL_ERROR, "failed to Pause, recorder_ is null");
    int32_t errCode = recorder_->Pause();
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "MovieFileOutput Failed to Pause!, errCode: %{public}d", errCode);
    MEDIA_DEBUG_LOG("MovieFileOutput::Pause end");
    return ServiceToCameraError(errCode);
}

int32_t MovieFileOutput::Resume()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::Resume is called");
    CHECK_RETURN_RET_ELOG(recorder_ == nullptr, SERVICE_FATL_ERROR, "failed to Resume, recorder_ is null");
    int32_t errCode = recorder_->Resume();
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "MovieFileOutput Failed to Resume!, errCode: %{public}d", errCode);
    MEDIA_DEBUG_LOG("MovieFileOutput::Resume end");
    return ServiceToCameraError(errCode);
}

int32_t MovieFileOutput::Stop()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::Stop is called");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR, "MovieFileOutput::Stop session is nullptr");
    session->EnableKeyFrameReport(false);
    CHECK_RETURN_RET_ELOG(recorder_ == nullptr, SERVICE_FATL_ERROR, "failed to Stop, recorder_ is null");
    int32_t errCode = recorder_->Stop();
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "failed to Stop recorder!, errCode: %{public}d", errCode);
    MEDIA_DEBUG_LOG("MovieFileOutput::Stop end");
    return ServiceToCameraError(errCode);
}

int32_t MovieFileOutput::SetRotation(int32_t rotation)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::SetRotation is called, rotation: %{public}d", rotation);
    CHECK_RETURN_RET_ELOG(recorder_ == nullptr, SERVICE_FATL_ERROR, "failed to SetRotation, recorder_ is null");
    int32_t errCode = recorder_->SetRotation(rotation);
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "failed to Prepare recorder!, errCode: %{public}d", errCode);
    return errCode;
}

void MovieFileOutput::SetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    videoFrameRateRange_ = {minFrameRate, maxFrameRate};
}

void MovieFileOutput::SetRawVideoStream(sptr<IStreamCommon> stream)
{
    {
        std::lock_guard<std::mutex> lock(streamMutex_);
        rawVideoStream_ = stream;
    }
    // add StreamBinderDied callback
}

sptr<IStreamCommon> MovieFileOutput::GetRawVideoStream()
{
    std::lock_guard<std::mutex> lock(streamMutex_);
    return rawVideoStream_;
}

void MovieFileOutput::SetCallback(std::shared_ptr<IMovieFileOutputStateCallback> callback)
{
    MEDIA_INFO_LOG("MovieFileOutput::SetCallback is called");
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appCallback_ = callback;
}

void MovieFileOutput::AddRecorderCallback()
{
    MEDIA_INFO_LOG("MovieFileOutput::AddRecorderCallback is called");
    if (appCallback_ != nullptr) {
        if (svcCallback_ == nullptr) {
            svcCallback_ = new (std::nothrow) MovieFileOutputCallbackImpl(this);
            if (svcCallback_ == nullptr) {
                MEDIA_ERR_LOG("new MovieFileOutputCallbackImpl Failed to register callback");
                appCallback_ = nullptr;
                return;
            }
        }
        int32_t errorCode = CAMERA_OK;
        if (recorder_) {
            errorCode = recorder_->SetRecorderCallback(svcCallback_);
        } else {
            MEDIA_ERR_LOG("MovieFileOutput::SetCallback recorder_ is nullptr");
        }

        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("MovieFileOutput::SetCallback: Failed to register callback, errorCode:%{public}d", errorCode);
            svcCallback_ = nullptr;
            appCallback_ = nullptr;
        }
    }
}

std::shared_ptr<IMovieFileOutputStateCallback> MovieFileOutput::GetApplicationCallback()
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appCallback_;
}

void MovieFileOutput::SetRecorder(sptr<ICameraRecorder> recorder)
{
    CHECK_PRINT_ELOG(recorder == nullptr, "MovieFileOutput::SetRecorder failed, recorder is null");
    recorder_ = recorder;
}

bool MovieFileOutput::IsMirrorSupported()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::IsMirrorSupported is called");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, false, "MovieFileOutput::IsMirrorSupported session is nullptr");
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(
        inputDevice == nullptr, false, "MovieFileOutput IsMirrorSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(
        cameraObj == nullptr, false, "MovieFileOutput IsMirrorSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    CHECK_RETURN_RET(metadata == nullptr, false);
    camera_metadata_item_t item;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(
        retCode != CAM_META_SUCCESS, false, "MovieFileOutput Can not find OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED");
    int step = 2;
    const int32_t canMirrorVideoAndPhoto = 2;
    bool isMirrorEnabled = false;
    SceneMode currentSceneMode = session->GetMode();
    for (int i = 0; i < static_cast<int>(item.count); i += step) {
        MEDIA_DEBUG_LOG("mode u8[%{public}d]: %{public}d, u8[%{public}d], %{public}d",
            i, item.data.u8[i], i + 1, item.data.u8[i + 1]);
        if (currentSceneMode == static_cast<int>(item.data.u8[i])) {
            isMirrorEnabled = (item.data.u8[i + 1] == canMirrorVideoAndPhoto) ? true : false;
        }
    }
    MEDIA_DEBUG_LOG("MovieFileOutput::IsMirrorSupported isSupport: %{public}d", isMirrorEnabled);
    return isMirrorEnabled;
}

int32_t MovieFileOutput::EnableMirror(bool isEnable)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::EnableMirror is called, isEnable: %{public}d", isEnable);
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(
        session == nullptr, CameraErrorCode::SESSION_NOT_CONFIG, "Can not enable mirror, session is not config");
    CHECK_RETURN_RET_ELOG(!recorder_ || !IsMirrorSupported(), CameraErrorCode::INVALID_ARGUMENT,
        "MovieFileOutput::enableMirror not supported mirror or stream is null");
    int32_t retCode = recorder_->EnableMirror(isEnable);
    CHECK_RETURN_RET_ELOG(
        retCode != CAMERA_OK, ServiceToCameraError(retCode), "MovieFileOutput::enableMirror failed to set mirror");
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::GetSupportedVideoFilters is called");
    supportedVideoFilters.clear();
    supportedVideoFilters.push_back("origin");
    std::vector<std::string> videoFilters;
    int32_t retCode = recorder_->GetSupportedVideoFilters(videoFilters);
    CHECK_RETURN_RET_ELOG(
        retCode != CAMERA_OK, ServiceToCameraError(retCode), "MovieFileOutput::GetSupportedVideoFilters failed");
    for (const auto& filter : videoFilters) {
        supportedVideoFilters.push_back(filter);
    }
    return CameraErrorCode::SUCCESS;
}

int32_t MovieFileOutput::SetVideoFilter(const std::string& filter, const std::string& filterParam)
{
    MEDIA_DEBUG_LOG("MovieFileOutput::SetVideoFilter is called");
    CHECK_RETURN_RET_ELOG(
        !recorder_, CameraErrorCode::INVALID_ARGUMENT, "MovieFileOutput::SetVideoFilter failed: recorder_ is null");
    int32_t retCode = recorder_->SetVideoFilter(filter, filterParam);
    return retCode;
}

int32_t MovieFileOutput::GetCameraPosition()
{
    int32_t cameraPosition = -1;
    sptr<CaptureSession> session = GetSession();
    CHECK_RETURN_RET_ELOG(!session, cameraPosition, "session is not config");
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(!inputDevice, cameraPosition, "inputDevice is null");
    sptr<CameraDevice> cameraDeviceInfo = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(!cameraDeviceInfo, cameraPosition, "cameraDeviceInfo is null");
    return cameraDeviceInfo->GetPosition();
}

void MovieFileOutput::SetUserMeta()
{
    MEDIA_DEBUG_LOG("MovieFileOutput::SetUserMeta is called");
    sptr<CaptureSession> session = GetSession();
    CHECK_RETURN_ELOG(session == nullptr, "SetUserMeta failed, session is not config");

    // stabilization
    int32_t videoStabilizationMode = session->GetActiveVideoStabilizationMode();
    // aperture
    float physicalAperture = DEFAULT_PHYSICAL_APERTURE;
    float virtualAperture = DEFAULT_VIRTUAL_APERTURE;
    if (session->IsVirtualApertureEnabled()) {
        session->GetVirtualAperture(virtualAperture);
        physicalAperture = 2.0; // deafult physical aperture is 2.0
    } else {
        session->GetPhysicalAperture(physicalAperture);
        virtualAperture = -1.0; // virtual aperture is not enabled by deafult
    }
    // xstyle
    int32_t colorEffect = session->GetColorEffect();
    int32_t cameraPosition = GetCameraPosition();
    int32_t deviceFoldState = static_cast<int32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldStatus());
    std::string deviceModel = system::GetParameter("persist.hiviewdfx.priv.sw.model", "");
    CHECK_RETURN_ELOG(recorder_ == nullptr, "SetUserMeta failed, recorder_ is null");
    recorder_->SetUserMeta("com.openharmony.deviceFoldState", std::to_string(deviceFoldState));
    recorder_->SetUserMeta("com.openharmony.deviceModel", deviceModel);
    recorder_->SetUserMeta("com.openharmony.cameraPosition", std::to_string(cameraPosition));
    recorder_->SetUserMeta("com.openharmony.stabilization", std::to_string(videoStabilizationMode));
    recorder_->SetUserMeta("com.openharmony.aperture",
                           std::to_string(physicalAperture) + "," + std::to_string(virtualAperture));
    recorder_->SetUserMeta("com.openharmony.colorEffect", std::to_string(colorEffect));
    recorder_->SetUserMeta("com.openharmony.cinematic", std::to_string(true));
    MEDIA_INFO_LOG("MovieFileOutput::SetUserMeta vsMode: %{public}d, physicalAperture: %{public}f, virtualAperture: "
                   "%{public}f, colorEffect: %{public}d, deviceFoldState: %{public}d, cameraPosition: %{public}d",
                   videoStabilizationMode, physicalAperture, virtualAperture, colorEffect, deviceFoldState,
                   cameraPosition);
}

int32_t MovieFileOutputCallbackImpl::OnRecordingStart()
{
    CAMERA_SYNC_TRACE;
    auto item = movieFileOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnRecordingStart();
    } else {
        MEDIA_INFO_LOG("Discarding MovieFileOutputCallbackImpl::OnRecordingStart callback");
    }
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnRecordingPause()
{
    CAMERA_SYNC_TRACE;
    auto item = movieFileOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnRecordingPause();
    } else {
        MEDIA_INFO_LOG("Discarding MovieFileOutputCallbackImpl::OnRecordingPause callback");
    }
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnRecordingResume()
{
    CAMERA_SYNC_TRACE;
    auto item = movieFileOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnRecordingResume();
    } else {
        MEDIA_INFO_LOG("Discarding MovieFileOutputCallbackImpl::OnRecordingResume callback");
    }
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnRecordingStop()
{
    CAMERA_SYNC_TRACE;
    auto item = movieFileOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnRecordingStop();
    } else {
        MEDIA_INFO_LOG("Discarding MovieFileOutputCallbackImpl::OnRecordingStop callback");
    }
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnPhotoAssetAvailable(const std::string& uri)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileOutputCallbackImpl::OnPhotoAssetAvailable is called");
    auto item = movieFileOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnPhotoAssetAvailable(uri);
    } else {
        MEDIA_ERR_LOG("Discarding MovieFileOutputCallbackImpl::OnMovieInfoAvailable callback");
    }
    return CAMERA_OK;
}

int32_t MovieFileOutputCallbackImpl::OnError(const int32_t errorCode)
{
    CAMERA_SYNC_TRACE;
    auto item = movieFileOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnError(errorCode);
    } else {
        MEDIA_INFO_LOG("Discarding MovieFileOutputCallbackImpl::OnError callback");
    }
    return CAMERA_OK;
}

} // namespace CameraStandard
} // namespace OHOS