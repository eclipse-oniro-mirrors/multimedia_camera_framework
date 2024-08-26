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

#include "output/video_output.h"

#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "hstream_repeat_callback_stub.h"
#include "input/camera_device.h"
#include "input/camera_input.h"
#include "istream_repeat.h"

namespace OHOS {
namespace CameraStandard {
VideoOutput::VideoOutput(sptr<IBufferProducer> bufferProducer)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_VIDEO, StreamType::REPEAT, bufferProducer, nullptr)
{
    videoFormat_ = 0;
    videoSize_.height = 0;
    videoSize_.width = 0;
}

VideoOutput::~VideoOutput()
{
}

int32_t VideoOutputCallbackImpl::OnFrameStarted()
{
    CAMERA_SYNC_TRACE;
    auto item = videoOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnFrameStarted();
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnFrameStarted callback in video");
    }
    return CAMERA_OK;
}

int32_t VideoOutputCallbackImpl::OnFrameEnded(const int32_t frameCount)
{
    CAMERA_SYNC_TRACE;
    auto item = videoOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnFrameEnded(frameCount);
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnFrameEnded callback in video");
    }
    return CAMERA_OK;
}

int32_t VideoOutputCallbackImpl::OnFrameError(const int32_t errorCode)
{
    auto item = videoOutput_.promote();
    if (item != nullptr && item->GetApplicationCallback() != nullptr) {
        item->GetApplicationCallback()->OnError(errorCode);
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnFrameError callback in video");
    }
    return CAMERA_OK;
}

int32_t VideoOutputCallbackImpl::OnSketchStatusChanged(SketchStatus status)
{
    // Empty implement
    return CAMERA_OK;
}

void VideoOutput::SetCallback(std::shared_ptr<VideoStateCallback> callback)
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    appCallback_ = callback;
    if (appCallback_ != nullptr) {
        if (svcCallback_ == nullptr) {
            svcCallback_ = new (std::nothrow) VideoOutputCallbackImpl(this);
            if (svcCallback_ == nullptr) {
                MEDIA_ERR_LOG("new VideoOutputCallbackImpl Failed to register callback");
                appCallback_ = nullptr;
                return;
            }
        }
        if (GetStream() == nullptr) {
            MEDIA_ERR_LOG("VideoOutput Failed to SetCallback!, GetStream is nullptr");
            return;
        }
        int32_t errorCode = CAMERA_OK;
        auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
        if (itemStream) {
            errorCode = itemStream->SetCallback(svcCallback_);
        } else {
            MEDIA_ERR_LOG("VideoOutput::SetCallback itemStream is nullptr");
        }

        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("VideoOutput::SetCallback: Failed to register callback, errorCode: %{public}d", errorCode);
            svcCallback_ = nullptr;
            appCallback_ = nullptr;
        }
    }
}

int32_t VideoOutput::Start()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Start");
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_CONFIG, "VideoOutput Failed to Start, session not commited");
    CHECK_ERROR_RETURN_RET_LOG(GetStream() == nullptr,
        CameraErrorCode::SERVICE_FATL_ERROR, "VideoOutput Failed to Start!, GetStream is nullptr");
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Start();
        CHECK_ERROR_PRINT_LOG(errCode != CAMERA_OK, "VideoOutput Failed to Start!, errCode: %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("VideoOutput::Start() itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t VideoOutput::Stop()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Stop");
    CHECK_ERROR_RETURN_RET_LOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput Failed to Stop!, GetStream is nullptr");
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Stop();
        CHECK_ERROR_PRINT_LOG(errCode != CAMERA_OK, "VideoOutput Failed to Stop!, errCode: %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("VideoOutput::Stop() itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t VideoOutput::Resume()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Resume");
    CHECK_ERROR_RETURN_RET_LOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput Failed to Resume!, GetStream is nullptr");
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Start();
    } else {
        MEDIA_ERR_LOG("VideoOutput::Resume() itemStream is nullptr");
    }
    return ServiceToCameraError(errCode);
}

int32_t VideoOutput::Pause()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Pause");
    CHECK_ERROR_RETURN_RET_LOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput Failed to Pause!, GetStream is nullptr");
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Stop();
    } else {
        MEDIA_ERR_LOG("VideoOutput::Pause() itemStream is nullptr");
    }
    return errCode;
}

int32_t VideoOutput::CreateStream()
{
    auto stream = GetStream();
    CHECK_ERROR_RETURN_RET_LOG(stream != nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "VideoOutput::CreateStream stream is not null");
    auto producer = GetBufferProducer();
    CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "VideoOutput::CreateStream producer is not null");
    sptr<IStreamRepeat> streamPtr = nullptr;
    auto videoProfile = GetVideoProfile();
    CHECK_ERROR_RETURN_RET_LOG(videoProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput::CreateStream video profile is not null");
    int32_t retCode =
        CameraManager::GetInstance()->CreateVideoOutputStream(streamPtr, *videoProfile, GetBufferProducer());
    CHECK_ERROR_PRINT_LOG(retCode != CameraErrorCode::SUCCESS,
        "VideoOutput::CreateStream fail! error code :%{public}d", retCode);
    SetStream(streamPtr);
    return retCode;
}

int32_t VideoOutput::Release()
{
    {
        std::lock_guard<std::mutex> lock(outputCallbackMutex_);
        svcCallback_ = nullptr;
        appCallback_ = nullptr;
    }
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Release");
    CHECK_ERROR_RETURN_RET_LOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput Failed to Release!, GetStream is nullptr");
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->Release();
    } else {
        MEDIA_ERR_LOG("VideoOutput::Release() itemStream is nullptr");
    }
    CHECK_ERROR_PRINT_LOG(errCode != CAMERA_OK, "Failed to release VideoOutput!, errCode: %{public}d", errCode);
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

std::shared_ptr<VideoStateCallback> VideoOutput::GetApplicationCallback()
{
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    return appCallback_;
}

const std::vector<int32_t>& VideoOutput::GetFrameRateRange()
{
    return videoFrameRateRange_;
}

void VideoOutput::SetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    MEDIA_DEBUG_LOG("VideoOutput::SetFrameRateRange min = %{public}d and max = %{public}d", minFrameRate, maxFrameRate);

    videoFrameRateRange_ = { minFrameRate, maxFrameRate };
}

void VideoOutput::SetOutputFormat(int32_t format)
{
    MEDIA_DEBUG_LOG("VideoOutput::SetOutputFormat set format %{public}d", format);
    videoFormat_ = format;
}

void VideoOutput::SetSize(Size size)
{
    videoSize_ = size;
}
 
int32_t VideoOutput::SetFrameRate(int32_t minFrameRate, int32_t maxFrameRate)
{
    int32_t result = canSetFrameRateRange(minFrameRate, maxFrameRate);
    CHECK_ERROR_RETURN_RET(result != CameraErrorCode::SUCCESS, result);
    CHECK_ERROR_RETURN_RET_LOG(minFrameRate == videoFrameRateRange_[0] && maxFrameRate == videoFrameRateRange_[1],
        CameraErrorCode::INVALID_ARGUMENT, "VideoOutput::SetFrameRate The frame rate does not need to be set.");
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    if (itemStream) {
        int32_t ret = itemStream->SetFrameRate(minFrameRate, maxFrameRate);
        CHECK_ERROR_RETURN_RET_LOG(ret != CAMERA_OK, ServiceToCameraError(ret),
            "VideoOutput::setFrameRate failed to set stream frame rate");
        SetFrameRateRange(minFrameRate, maxFrameRate);
    }
    return CameraErrorCode::SUCCESS;
}

std::vector<std::vector<int32_t>> VideoOutput::GetSupportedFrameRates()
{
    MEDIA_DEBUG_LOG("VideoOutput::GetSupportedFrameRates called.");
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET(session == nullptr, {});
    auto inputDevice = session->GetInputDevice();
    CHECK_ERROR_RETURN_RET(inputDevice == nullptr, {});

    sptr<CameraDevice> camera = inputDevice->GetCameraDeviceInfo();
    sptr<CameraOutputCapability> cameraOutputCapability =
                                 CameraManager::GetInstance()->GetSupportedOutputCapability(camera, SceneMode::VIDEO);
    CHECK_ERROR_RETURN_RET(cameraOutputCapability == nullptr, {});
    std::vector<VideoProfile> supportedProfiles = cameraOutputCapability->GetVideoProfiles();
    supportedProfiles.erase(std::remove_if(
        supportedProfiles.begin(), supportedProfiles.end(),
        [&](Profile& profile) {
            return profile.format_ != videoFormat_ ||
                   profile.GetSize().height != videoSize_.height ||
                   profile.GetSize().width != videoSize_.width;
        }), supportedProfiles.end());
    std::vector<std::vector<int32_t>> supportedFrameRatesRange;
    for (auto item : supportedProfiles) {
        supportedFrameRatesRange.emplace_back(item.GetFrameRates());
    }
    std::set<std::vector<int>> set(supportedFrameRatesRange.begin(), supportedFrameRatesRange.end());
    supportedFrameRatesRange.assign(set.begin(), set.end());
    MEDIA_DEBUG_LOG("VideoOutput::GetSupportedFrameRates frameRateRange size:%{public}zu",
                    supportedFrameRatesRange.size());
    return supportedFrameRatesRange;
}

int32_t VideoOutput::enableMirror(bool enabled)
{
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "Can not enable mirror, session is not config");
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    CHECK_ERROR_RETURN_RET_LOG(!itemStream || !IsMirrorSupported(), CameraErrorCode::INVALID_ARGUMENT,
        "VideoOutput::enableMirror not supported mirror or stream is null");
    int32_t retCode = itemStream->SetMirror(enabled);
    CHECK_ERROR_RETURN_RET_LOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "VideoOutput::enableMirror failed to set mirror");
    return CameraErrorCode::SUCCESS;
}
 
bool VideoOutput::IsMirrorSupported()
{
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr, false, "VideoOutput IsMirrorSupported error!, session is nullptr");
    auto inputDevice = session->GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(inputDevice == nullptr, false,
        "VideoOutput IsMirrorSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(cameraObj == nullptr, false,
        "VideoOutput IsMirrorSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    CHECK_ERROR_RETURN_RET(metadata == nullptr, false);
    camera_metadata_item_t item;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    CHECK_ERROR_RETURN_RET_LOG(retCode != CAM_META_SUCCESS, false,
        "VideoOutput Can not find OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED");
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
    MEDIA_DEBUG_LOG("IsMirrorSupported isSupport: %{public}d", isMirrorEnabled);
    return isMirrorEnabled;
}

std::vector<VideoMetaType> VideoOutput::GetSupportedVideoMetaTypes()
{
    std::vector<VideoMetaType> vecto = {};
    if (IsTagSupported(OHOS_ABILITY_AVAILABLE_EXTENDED_STREAM_INFO_TYPES)) {
        vecto.push_back(VideoMetaType::VIDEO_META_MAKER_INFO);
    }
    return vecto;
}
 
bool VideoOutput::IsTagSupported(camera_device_metadata_tag tag)
{
    camera_metadata_item_t item;
    sptr<CameraDevice> cameraObj;
    auto captureSession = GetSession();
    CHECK_ERROR_RETURN_RET_LOG(captureSession == nullptr, false,
        "VideoOutput isTagEnabled error!, captureSession is nullptr");
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(inputDevice == nullptr, false,
        "VideoOutput isTagEnabled error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(cameraObj == nullptr, false,
        "VideoOutput isTagEnabled error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    CHECK_ERROR_RETURN_RET(metadata == nullptr, false);
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), tag, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, false, "Can not find this tag");
    MEDIA_DEBUG_LOG("This tag is Supported");
    return true;
}
 
void VideoOutput::AttachMetaSurface(sptr<Surface> surface, VideoMetaType videoMetaType)
{
    auto itemStream = static_cast<IStreamRepeat*>(GetStream().GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    if (itemStream) {
        errCode = itemStream->AttachMetaSurface(surface->GetProducer(), videoMetaType);
        if (errCode != CAMERA_OK) {
            MEDIA_ERR_LOG("VideoOutput Failed to Attach Meta Surface!, errCode: %{public}d", errCode);
        }
    } else {
        MEDIA_ERR_LOG("VideoOutput::AttachMetaSurface() itemStream is nullptr");
    }
}

void VideoOutput::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    if (appCallback_ != nullptr) {
        MEDIA_DEBUG_LOG("appCallback not nullptr");
        int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
        appCallback_->OnError(serviceErrorType);
    }
}

int32_t VideoOutput::canSetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "VideoOutput canSetFrameRateRange error!, session is nullptr");
    CHECK_ERROR_RETURN_RET_LOG(!session->CanSetFrameRateRange(minFrameRate, maxFrameRate, this),
        CameraErrorCode::UNRESOLVED_CONFLICTS_BETWEEN_STREAMS,
        "VideoOutput canSetFrameRateRange Can not set frame rate range with wrong state of output");
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<std::vector<int32_t>> supportedFrameRange = GetSupportedFrameRates();
    for (auto item : supportedFrameRange) {
        if (item[minIndex] <= minFrameRate && item[maxIndex] >= maxFrameRate) {
            return CameraErrorCode::SUCCESS;
        }
    }
    MEDIA_WARNING_LOG("Can not set frame rate range with invalid parameters");
    return CameraErrorCode::INVALID_ARGUMENT;
}

int32_t VideoOutput::GetVideoRotation(int32_t imageRotation)
{
    MEDIA_DEBUG_LOG("VideoOutput GetVideoRotation is called");
    int32_t sensorOrientation = 0;
    CameraPosition cameraPosition;
    camera_metadata_item_t item;
    ImageRotation result = ImageRotation::ROTATION_0;
    sptr<CameraDevice> cameraObj;
    auto session = GetSession();
    CHECK_ERROR_RETURN_RET_LOG(session == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput GetVideoRotation error!, session is nullptr");
    auto inputDevice = session->GetInputDevice();
    CHECK_ERROR_RETURN_RET_LOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput GetVideoRotation error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_ERROR_RETURN_RET_LOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput GetVideoRotation error!, cameraObj is nullptr");
    cameraPosition = cameraObj->GetPosition();
    CHECK_ERROR_RETURN_RET_LOG(cameraPosition == CAMERA_POSITION_UNSPECIFIED, SERVICE_FATL_ERROR,
        "VideoOutput GetVideoRotation error!, cameraPosition is unspecified");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetMetadata();
    CHECK_ERROR_RETURN_RET(metadata == nullptr, SERVICE_FATL_ERROR);
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), OHOS_SENSOR_ORIENTATION, &item);
    CHECK_ERROR_RETURN_RET_LOG(ret != CAM_META_SUCCESS, SERVICE_FATL_ERROR,
        "GetVideoRotation Can not find OHOS_SENSOR_ORIENTATION");
    sensorOrientation = item.data.i32[0];
    if (cameraPosition == CAMERA_POSITION_BACK) {
        result = (ImageRotation)((imageRotation + sensorOrientation) % CAPTURE_ROTATION_BASE);
    } else if (cameraPosition == CAMERA_POSITION_FRONT || cameraPosition == CAMERA_POSITION_FOLD_INNER) {
        result = (ImageRotation)((imageRotation - sensorOrientation + CAPTURE_ROTATION_BASE) % CAPTURE_ROTATION_BASE);
    }
    MEDIA_INFO_LOG("VideoOutput GetVideoRotation :result %{public}d, sensorOrientation:%{public}d",
        result, sensorOrientation);
    return result;
}
} // namespace CameraStandard
} // namespace OHOS
