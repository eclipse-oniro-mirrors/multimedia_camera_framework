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
#include "input/camera_device.h"
#include "istream_repeat.h"

namespace OHOS {
namespace CameraStandard {
constexpr int32_t FRAMERATE_120 = 120;
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
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto item = videoOutput_.promote();
    std::shared_ptr<VideoStateCallback> appCallback =nullptr;
    if (item != nullptr) {
        appCallback = item->GetApplicationCallback();
    }
    if (appCallback != nullptr) {
        appCallback->OnFrameStarted();
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnFrameStarted callback in video");
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t VideoOutputCallbackImpl::OnFrameEnded(const int32_t frameCount)
{
    // LCOV_EXCL_START
    CAMERA_SYNC_TRACE;
    auto item = videoOutput_.promote();
    std::shared_ptr<VideoStateCallback> appCallback =nullptr;
    if (item != nullptr) {
        appCallback = item->GetApplicationCallback();
    }
    if (appCallback != nullptr) {
        appCallback->OnFrameEnded(frameCount);
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnFrameEnded callback in video");
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t VideoOutputCallbackImpl::OnFrameError(const int32_t errorCode)
{
    // LCOV_EXCL_START
    auto item = videoOutput_.promote();
    std::shared_ptr<VideoStateCallback> appCallback =nullptr;
    if (item != nullptr) {
        appCallback = item->GetApplicationCallback();
    }
    if (appCallback != nullptr) {
        appCallback->OnError(errorCode);
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnFrameError callback in video");
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

int32_t VideoOutputCallbackImpl::OnSketchStatusChanged(SketchStatus status)
{
    // Empty implement
    return CAMERA_OK;
}

int32_t VideoOutputCallbackImpl::OnDeferredVideoEnhancementInfo(const CaptureEndedInfoExt &captureEndedInfo)
{
    // LCOV_EXCL_START
    MEDIA_INFO_LOG("VideoOutputCallbackImpl::OnDeferredVideoEnhancementInfo callback in video");
    auto item = videoOutput_.promote();
    std::shared_ptr<VideoStateCallback> appCallback =nullptr;
    if (item != nullptr) {
        appCallback = item->GetApplicationCallback();
    }
    if (appCallback != nullptr) {
        appCallback->OnDeferredVideoEnhancementInfo(captureEndedInfo);
    } else {
        MEDIA_INFO_LOG("Discarding VideoOutputCallbackImpl::OnDeferredVideoEnhancementInfo callback in video");
    }
    return CAMERA_OK;
    // LCOV_EXCL_STOP
}

void VideoOutput::SetCallback(std::shared_ptr<VideoStateCallback> callback)
{
    // LCOV_EXCL_START
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
        CHECK_RETURN_ELOG(GetStream() == nullptr, "VideoOutput Failed to SetCallback!, GetStream is nullptr");
        int32_t errorCode = CAMERA_OK;
        auto stream = GetStream();
        sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
        CHECK_PRINT_ELOG(itemStream == nullptr, "VideoOutput::SetCallback itemStream is nullptr");
        if (itemStream) {
            errorCode = itemStream->SetCallback(svcCallback_);
        }

        CHECK_RETURN(errorCode == CAMERA_OK);
        MEDIA_ERR_LOG("VideoOutput::SetCallback: Failed to register callback, errorCode: %{public}d", errorCode);
        svcCallback_ = nullptr;
        appCallback_ = nullptr;
    }
    // LCOV_EXCL_STOP
}

int32_t VideoOutput::Start()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Start");
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(),
        CameraErrorCode::SESSION_NOT_CONFIG, "VideoOutput Failed to Start, session not commited");
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr,
        CameraErrorCode::SERVICE_FATL_ERROR, "VideoOutput Failed to Start!, GetStream is nullptr");
    if (!GetFrameRateRange().empty() && GetFrameRateRange()[0] >= FRAMERATE_120) {
        MEDIA_INFO_LOG("EnableFaceDetection is call");
        session->EnableFaceDetection(false);
    }
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_RETURN_RET_ELOG(itemStream == nullptr, ServiceToCameraError(errCode),
        "VideoOutput::Start() itemStream is nullptr");
    if (itemStream) {
        errCode = itemStream->Start();
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "VideoOutput Failed to Start!, errCode: %{public}d", errCode);
        isVideoStarted_ = true;
    }
    return ServiceToCameraError(errCode);
    // LCOV_EXCL_STOP
}

int32_t VideoOutput::Stop()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Stop");
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput Failed to Stop!, GetStream is nullptr");
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_PRINT_ELOG(itemStream == nullptr, "VideoOutput::Stop() itemStream is nullptr");
    if (itemStream) {
        errCode = itemStream->Stop();
        CHECK_PRINT_ELOG(errCode != CAMERA_OK, "VideoOutput Failed to Stop!, errCode: %{public}d", errCode);
        isVideoStarted_ = false;
    }
    // LCOV_EXCL_START
    if (!GetFrameRateRange().empty() && GetFrameRateRange()[0] >= FRAMERATE_120) {
        auto session = GetSession();
        CHECK_RETURN_RET_ELOG(session == nullptr || !session->IsSessionCommited(),
            CameraErrorCode::SESSION_NOT_CONFIG, "VideoOutput Failed to Start, session not commited");
        MEDIA_INFO_LOG("EnableFaceDetection is call");
        session->EnableFaceDetection(true);
    }
    // LCOV_EXCL_STOP
    return ServiceToCameraError(errCode);
}

int32_t VideoOutput::Resume()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Resume");
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput Failed to Resume!, GetStream is nullptr");
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_RETURN_RET_ELOG(itemStream == nullptr, ServiceToCameraError(errCode),
        "VideoOutput::Resume() itemStream is nullptr");
    if (itemStream) {
        errCode = itemStream->Start();
        isVideoStarted_ = true;
    }
    return ServiceToCameraError(errCode);
}

int32_t VideoOutput::Pause()
{
    std::lock_guard<std::mutex> lock(asyncOpMutex_);
    MEDIA_DEBUG_LOG("Enter Into VideoOutput::Pause");
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput Failed to Pause!, GetStream is nullptr");
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_RETURN_RET_ELOG(itemStream == nullptr, errCode,
        "VideoOutput::Pause() itemStream is nullptr");
    if (itemStream) {
        errCode = itemStream->Stop();
        isVideoStarted_ = false;
    }
    return errCode;
}

int32_t VideoOutput::CreateStream()
{
    auto stream = GetStream();
    CHECK_RETURN_RET_ELOG(stream != nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "VideoOutput::CreateStream stream is not null");
    // LCOV_EXCL_START
    auto producer = GetBufferProducer();
    CHECK_RETURN_RET_ELOG(producer == nullptr, CameraErrorCode::OPERATION_NOT_ALLOWED,
        "VideoOutput::CreateStream producer is not null");
    sptr<IStreamRepeat> streamPtr = nullptr;
    auto videoProfile = GetVideoProfile();
    CHECK_RETURN_RET_ELOG(videoProfile == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput::CreateStream video profile is not null");
    int32_t retCode =
        CameraManager::GetInstance()->CreateVideoOutputStream(streamPtr, *videoProfile, GetBufferProducer());
    CHECK_PRINT_ELOG(retCode != CameraErrorCode::SUCCESS,
        "VideoOutput::CreateStream fail! error code :%{public}d", retCode);
    SetStream(streamPtr);
    return retCode;
    // LCOV_EXCL_STOP
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
    CHECK_RETURN_RET_ELOG(GetStream() == nullptr, CameraErrorCode::SERVICE_FATL_ERROR,
        "VideoOutput Failed to Release!, GetStream is nullptr");
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    CHECK_PRINT_ELOG(itemStream == nullptr, "VideoOutput::Release() itemStream is nullptr");
    if (itemStream) {
        errCode = itemStream->Release();
    }
    CHECK_PRINT_ELOG(errCode != CAMERA_OK, "Failed to release VideoOutput!, errCode: %{public}d", errCode);
    CaptureOutput::Release();
    isVideoStarted_ = false;
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
    CHECK_RETURN(minFrameRate > maxFrameRate);
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
    CHECK_RETURN_RET(result != CameraErrorCode::SUCCESS, result);
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(minFrameRate == videoFrameRateRange_[0] && maxFrameRate == videoFrameRateRange_[1],
        CameraErrorCode::INVALID_ARGUMENT, "VideoOutput::SetFrameRate The frame rate does not need to be set.");
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    if (itemStream) {
        int32_t ret = itemStream->SetFrameRate(minFrameRate, maxFrameRate);
        CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ServiceToCameraError(ret),
            "VideoOutput::setFrameRate failed to set stream frame rate");
        SetFrameRateRange(minFrameRate, maxFrameRate);
    }
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

std::vector<std::vector<int32_t>> VideoOutput::GetSupportedFrameRates()
{
    MEDIA_DEBUG_LOG("VideoOutput::GetSupportedFrameRates called.");
    auto session = GetSession();
    CHECK_RETURN_RET(session == nullptr, {});
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET(inputDevice == nullptr, {});

    sptr<CameraDevice> camera = inputDevice->GetCameraDeviceInfo();
    sptr<CameraOutputCapability> cameraOutputCapability =
                                 CameraManager::GetInstance()->GetSupportedOutputCapability(camera, SceneMode::VIDEO);
    CHECK_RETURN_RET(cameraOutputCapability == nullptr, {});
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
    // LCOV_EXCL_STOP
}

int32_t VideoOutput::enableMirror(bool enabled)
{
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "Can not enable mirror, session is not config");
    // LCOV_EXCL_START
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    CHECK_RETURN_RET_ELOG(!itemStream || !IsMirrorSupported(), CameraErrorCode::INVALID_ARGUMENT,
        "VideoOutput::enableMirror not supported mirror or stream is null");
    int32_t retCode = itemStream->SetMirror(enabled);
    CHECK_RETURN_RET_ELOG(retCode != CAMERA_OK, ServiceToCameraError(retCode),
        "VideoOutput::enableMirror failed to set mirror");
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

bool VideoOutput::IsMirrorSupported()
{
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, false, "VideoOutput IsMirrorSupported error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, false,
        "VideoOutput IsMirrorSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, false,
        "VideoOutput IsMirrorSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, false);
    camera_metadata_item_t item;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &item);
    CHECK_RETURN_RET_ELOG(retCode != CAM_META_SUCCESS, false,
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
    // LCOV_EXCL_STOP
}

std::vector<VideoMetaType> VideoOutput::GetSupportedVideoMetaTypes()
{
    std::vector<VideoMetaType> vecto = {};
    CHECK_EXECUTE(IsTagSupported(OHOS_ABILITY_AVAILABLE_EXTENDED_STREAM_INFO_TYPES),
        vecto.push_back(VideoMetaType::VIDEO_META_MAKER_INFO));
    return vecto;
}

bool VideoOutput::IsTagSupported(camera_device_metadata_tag tag)
{
    camera_metadata_item_t item;
    sptr<CameraDevice> cameraObj;
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, false,
        "VideoOutput isTagEnabled error!, captureSession is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, false,
        "VideoOutput isTagEnabled error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, false,
        "VideoOutput isTagEnabled error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, false);
    int32_t ret = Camera::FindCameraMetadataItem(metadata->get(), tag, &item);
    CHECK_RETURN_RET_ELOG(ret != CAM_META_SUCCESS, false, "Can not find this tag");
    MEDIA_DEBUG_LOG("This tag is Supported");
    return true;
    // LCOV_EXCL_STOP
}

void VideoOutput::AttachMetaSurface(sptr<Surface> surface, VideoMetaType videoMetaType)
{
    auto stream = GetStream();
    sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
    int32_t errCode = CAMERA_UNKNOWN_ERROR;
    // LCOV_EXCL_START
    if (itemStream) {
        errCode = itemStream->AttachMetaSurface(surface->GetProducer(), videoMetaType);
        CHECK_PRINT_ELOG(errCode != CAMERA_OK,
            "VideoOutput Failed to Attach Meta Surface!, errCode: %{public}d", errCode);
    } else {
        MEDIA_ERR_LOG("VideoOutput::AttachMetaSurface() itemStream is nullptr");
    }
    // LCOV_EXCL_STOP
}

void VideoOutput::CameraServerDied(pid_t pid)
{
    MEDIA_ERR_LOG("camera server has died, pid:%{public}d!", pid);
    std::lock_guard<std::mutex> lock(outputCallbackMutex_);
    if (appCallback_ != nullptr) {
        // LCOV_EXCL_START
        MEDIA_DEBUG_LOG("appCallback not nullptr");
        int32_t serviceErrorType = ServiceToCameraError(CAMERA_INVALID_STATE);
        appCallback_->OnError(serviceErrorType);
        // LCOV_EXCL_STOP
    }
}

int32_t VideoOutput::canSetFrameRateRange(int32_t minFrameRate, int32_t maxFrameRate)
{
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "VideoOutput canSetFrameRateRange error!, session is nullptr");
    // LCOV_EXCL_START
    CHECK_RETURN_RET_ELOG(!session->CanSetFrameRateRange(minFrameRate, maxFrameRate, this),
        CameraErrorCode::UNRESOLVED_CONFLICTS_BETWEEN_STREAMS,
        "VideoOutput canSetFrameRateRange Can not set frame rate range with wrong state of output");
    int32_t minIndex = 0;
    int32_t maxIndex = 1;
    std::vector<std::vector<int32_t>> supportedFrameRange = GetSupportedFrameRates();
    for (auto item : supportedFrameRange) {
        CHECK_RETURN_RET(item[minIndex] <= minFrameRate && item[maxIndex] >= maxFrameRate,
            CameraErrorCode::SUCCESS);
    }
    MEDIA_WARNING_LOG("VideoOutput canSetFrameRateRange Can not set frame rate range with invalid parameters");
    return CameraErrorCode::INVALID_ARGUMENT;
    // LCOV_EXCL_STOP
}

int32_t VideoOutput::GetVideoRotation(int32_t imageRotation)
{
    MEDIA_DEBUG_LOG("VideoOutput GetVideoRotation is called");
    int32_t sensorOrientation = 0;
    CameraPosition cameraPosition;
    ImageRotation result = ImageRotation::ROTATION_0;
    sptr<CameraDevice> cameraObj;
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput GetVideoRotation error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput GetVideoRotation error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput GetVideoRotation error!, cameraObj is nullptr");
    cameraPosition = cameraObj->GetPosition();
    CHECK_RETURN_RET_ELOG(cameraPosition == CAMERA_POSITION_UNSPECIFIED, SERVICE_FATL_ERROR,
        "VideoOutput GetVideoRotation error!, cameraPosition is unspecified");
    sensorOrientation = static_cast<int32_t>(cameraObj->GetCameraOrientation());
    imageRotation = (imageRotation + ROTATION_45_DEGREES) / ROTATION_90_DEGREES * ROTATION_90_DEGREES;
    if (cameraPosition == CAMERA_POSITION_BACK) {
        result = (ImageRotation)((imageRotation + sensorOrientation) % CAPTURE_ROTATION_BASE);
    } else if (cameraPosition == CAMERA_POSITION_FRONT || CAMERA_POSITION_FOLD_INNER) {
        result = (ImageRotation)((sensorOrientation - imageRotation + CAPTURE_ROTATION_BASE) % CAPTURE_ROTATION_BASE);
    }
    bool isMirrorEnabled = false;
    if (result != ImageRotation::ROTATION_0 && result != ImageRotation::ROTATION_180 && IsMirrorSupported()) {
        auto stream = GetStream();
        sptr<IStreamRepeat> itemStream = static_cast<IStreamRepeat*>(stream.GetRefPtr());
        if (itemStream != nullptr) {
            int32_t ret = itemStream->GetMirror(isMirrorEnabled);
            CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ServiceToCameraError(ret), "VideoOutput::getMirror failed");
            result = (isMirrorEnabled == false) ? result :
                (ImageRotation)((result + ImageRotation::ROTATION_180) % CAPTURE_ROTATION_BASE);
        }
    }
    MEDIA_INFO_LOG("VideoOutput GetVideoRotation :result %{public}d, sensorOrientation:%{public}d, "
        "isMirrorEnabled%{public}d", result, sensorOrientation, isMirrorEnabled);
    return result;
    // LCOV_EXCL_STOP
}

int32_t VideoOutput::IsAutoDeferredVideoEnhancementSupported()
{
    MEDIA_INFO_LOG("IsAutoDeferredVideoEnhancementSupported");
    sptr<CameraDevice> cameraObj;
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput IsAutoDeferredVideoEnhancementSupported error!, captureSession is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput IsAutoDeferredVideoEnhancementSupported error!, inputDevice is nullptr");
    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput IsAutoDeferredVideoEnhancementSupported error!, cameraObj is nullptr");

    int32_t curMode = captureSession->GetMode();
    int32_t isSupported  = cameraObj->modeVideoDeferredType_[curMode];
    MEDIA_INFO_LOG("IsAutoDeferredVideoEnhancementSupported curMode:%{public}d, modeSupportType:%{public}d",
        curMode, isSupported);
    return isSupported;
    // LCOV_EXCL_STOP
}

int32_t VideoOutput::IsAutoDeferredVideoEnhancementEnabled()
{
    MEDIA_INFO_LOG("VideoOutput IsAutoDeferredVideoEnhancementEnabled");
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput IsAutoDeferredVideoEnhancementEnabled error!, captureSession is nullptr");

    // LCOV_EXCL_START
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput IsAutoDeferredVideoEnhancementEnabled error!, inputDevice is nullptr");

    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput IsAutoDeferredVideoEnhancementEnabled error!, cameraObj is nullptr");

    int32_t curMode = captureSession->GetMode();
    bool isEnabled = captureSession->IsVideoDeferred();
    MEDIA_INFO_LOG("IsAutoDeferredVideoEnhancementEnabled curMode:%{public}d, isEnabled:%{public}d",
        curMode, isEnabled);
    return isEnabled;
    // LCOV_EXCL_STOP
}

int32_t VideoOutput::EnableAutoDeferredVideoEnhancement(bool enabled)
{
    MEDIA_INFO_LOG("EnableAutoDeferredVideoEnhancement");
    CAMERA_SYNC_TRACE;
    sptr<CameraDevice> cameraObj;
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput EnableAutoDeferredVideoEnhancement error!, captureSession is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput EnableAutoDeferredVideoEnhancement error!, inputDevice is nullptr");

    cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput EnableAutoDeferredVideoEnhancement error!, cameraObj is nullptr");
    captureSession->EnableAutoDeferredVideoEnhancement(enabled);
    captureSession->SetUserId();
    return SUCCESS;
    // LCOV_EXCL_STOP
}

bool VideoOutput::IsVideoStarted()
{
    return isVideoStarted_;
}

int32_t VideoOutput::GetSupportedRotations(std::vector<int32_t> &supportedRotations)
{
    MEDIA_DEBUG_LOG("VideoOutput::GetSupportedRotations is called");
    supportedRotations.clear();
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput::GetSupportedRotations failed due to captureSession is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput::GetSupportedRotations failed due to inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput::GetSupportedRotations failed due to cameraObj is nullptr");
    int32_t retCode = captureSession->GetSupportedVideoRotations(supportedRotations);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, SERVICE_FATL_ERROR,
        "VideoOutput::GetSupportedRotations failed, GetSupportedVideoRotations retCode: %{public}d", retCode);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t VideoOutput::IsRotationSupported(bool &isSupported)
{
    MEDIA_DEBUG_LOG("VideoOutput::IsRotationSupported is called");
    isSupported = false;
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput::IsRotationSupported failed due to captureSession is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput::IsRotationSupported failed due to inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput::IsRotationSupported failed due to cameraObj is nullptr");
    int32_t retCode = captureSession->IsVideoRotationSupported(isSupported);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, SERVICE_FATL_ERROR,
        "VideoOutput::IsRotationSupported failed, IsVideoRotationSupported retCode: %{public}d", retCode);
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}

int32_t VideoOutput::SetRotation(int32_t rotation)
{
    MEDIA_DEBUG_LOG("VideoOutput::SetRotation is called, rotation: %{public}d", rotation);
    auto captureSession = GetSession();
    CHECK_RETURN_RET_ELOG(captureSession == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput::SetRotation failed, captureSession is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = captureSession->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput::SetRotation failed, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, SERVICE_FATL_ERROR,
        "VideoOutput::SetRotation failed, cameraObj is nullptr");
    captureSession->LockForControl();
    int32_t retCode = captureSession->SetVideoRotation(rotation);
    CHECK_RETURN_RET_ELOG(retCode != CameraErrorCode::SUCCESS, SERVICE_FATL_ERROR,
        "VideoOutput::SetRotation failed, SetVideoRotation retCode: %{public}d", retCode);
    captureSession->UnlockForControl();
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}
 
bool VideoOutput::IsAutoVideoFrameRateSupported()
{
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, false,
        "VideoOutput IsAutoVideoFrameRateSupported error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, false,
        "VideoOutput IsAutoVideoFrameRateSupported error!, inputDevice is nullptr");
    sptr<CameraDevice> cameraObj = inputDevice->GetCameraDeviceInfo();
    CHECK_RETURN_RET_ELOG(cameraObj == nullptr, false,
        "VideoOutput IsAutoVideoFrameRateSupported error!, cameraObj is nullptr");
    std::shared_ptr<Camera::CameraMetadata> metadata = cameraObj->GetCachedMetadata();
    CHECK_RETURN_RET(metadata == nullptr, false);
    camera_metadata_item_t item;
    int32_t retCode = Camera::FindCameraMetadataItem(metadata->get(), OHOS_ABILITY_AUTO_VIDEO_FRAME_RATE, &item);
    CHECK_RETURN_RET_ELOG(retCode != CAM_META_SUCCESS, false,
        "VideoOutput Can not find OHOS_ABILITY_AUTO_VIDEO_FRAME_RATE");
    bool isAutoVideoFrameRateSupported = false;
    SceneMode currentSceneMode = session->GetMode();
    for (int i = 0; i < static_cast<int>(item.count); i++) {
        MEDIA_DEBUG_LOG("mode u8[%{public}d]: %{public}d", i, item.data.u8[i]);
        if (currentSceneMode == static_cast<SceneMode>(item.data.u8[i])) {
            isAutoVideoFrameRateSupported = true;
        }
    }
    MEDIA_DEBUG_LOG("IsAutoVideoFrameRateSupported isSupport: %{public}d", isAutoVideoFrameRateSupported);
    return isAutoVideoFrameRateSupported;
    // LCOV_EXCL_STOP
}
 
int32_t VideoOutput::EnableAutoVideoFrameRate(bool enable)
{
    MEDIA_INFO_LOG("VideoOutput::EnableAutoVideoFrameRate enable: %{public}d", enable);
    auto session = GetSession();
    CHECK_RETURN_RET_ELOG(session == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "VideoOutput IsAutoVideoFrameRateSupported error!, session is nullptr");
    // LCOV_EXCL_START
    auto inputDevice = session->GetInputDevice();
    CHECK_RETURN_RET_ELOG(inputDevice == nullptr, CameraErrorCode::SESSION_NOT_CONFIG,
        "VideoOutput IsAutoVideoFrameRateSupported error!, inputDevice is nullptr");
    bool isSupportedAutoVideoFps = IsAutoVideoFrameRateSupported();
    CHECK_RETURN_RET_ELOG(!isSupportedAutoVideoFps, CameraErrorCode::INVALID_ARGUMENT,
        "VideoOutput::EnableAutoVideoFrameRate does not supported.");
    session->LockForControl();
    session->EnableAutoFrameRate(enable);
    session->UnlockForControl();
    return CameraErrorCode::SUCCESS;
    // LCOV_EXCL_STOP
}
} // namespace CameraStandard
} // namespace OHOS
