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

#include "hcamera_movie_file_output.h"

#include "camera/v1_5/types.h"
#include "camera_log.h"
#include "camera_util.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"
#include "av_codec_proxy.h"

namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr int64_t SEC_TO_NS = 1000000000;
}
int32_t HCameraMovieFileOutput::OperatePermissionCheck(uint32_t interfaceCode)
{
    switch (static_cast<IMovieFileOutputIpcCode>(interfaceCode)) {
        case IMovieFileOutputIpcCode::COMMAND_START:                            // fall-through
        case IMovieFileOutputIpcCode::COMMAND_STOP:                             // fall-through
        case IMovieFileOutputIpcCode::COMMAND_PAUSE:                            // fall-through
        case IMovieFileOutputIpcCode::COMMAND_RESUME:                           // fall-through
        case IMovieFileOutputIpcCode::COMMAND_SET_OUTPUT_SETTINGS:              // fall-through
        case IMovieFileOutputIpcCode::COMMAND_GET_SUPPORTED_VIDEO_FILTERS:      // fall-through
        case IMovieFileOutputIpcCode::COMMAND_SET_MOVIE_FILE_OUTPUT_CALLBACK:   // fall-through
        case IMovieFileOutputIpcCode::COMMAND_UNSET_MOVIE_FILE_OUTPUT_CALLBACK: // fall-through
        case IMovieFileOutputIpcCode::COMMAND_ADD_VIDEO_FILTER:                 // fall-through
        case IMovieFileOutputIpcCode::COMMAND_REMOVE_VIDEO_FILTER:              // fall-through
        case IMovieFileOutputIpcCode::COMMAND_ENABLE_MIRROR:                    // fall-through
        case IMovieFileOutputIpcCode::COMMAND_IS_MIRROR_ENABLED:                // fall-through
        case IMovieFileOutputIpcCode::COMMAND_RELEASE: {
            auto callerTokenId = IPCSkeleton::GetCallingTokenID();
            CHECK_RETURN_RET_ELOG(appTokenId_ != callerTokenId, CAMERA_OPERATION_NOT_ALLOWED,
                "MovieFileRecorder::OperatePermissionCheck fail, callerToken not legal");
            break;
        }
        default:
            break;
    }
    return CAMERA_OK;
}

void HCameraMovieFileOutput::InitCallerInfo()
{
    MEDIA_INFO_LOG("HCameraMovieFileOutput::InitCallerInfo is called");
    // set caller info
    appTokenId_ = IPCSkeleton::GetCallingTokenID();
    appFullTokenId_ = IPCSkeleton::GetCallingFullTokenID();
    appUid_ = IPCSkeleton::GetCallingUid();
    appPid_ = IPCSkeleton::GetCallingPid();
    // set first caller tokenId, the audio server will check it later when creating audio process
    SetFirstCallerTokenID(appTokenId_);
    bundleName_ = GetClientBundle(appUid_);
    MEDIA_INFO_LOG(
        "HCameraMovieFileOutput::InitCallerInfo, appUid: %{public}d, appPid: %{public}d, bundleName_: %{public}s",
        appUid_, appPid_, bundleName_.c_str());
}

HCameraMovieFileOutput::HCameraMovieFileOutput(
    int32_t format, int32_t width, int32_t height, MovieFileOutputFrameRateRange& frameRateRange)
    : format_(format), width_(width), height_(height), frameRateRange_(frameRateRange)
{
    InitCallerInfo();
    movieFileProxy_.Set(MovieFileProxy::CreateMovieFileProxy());
}

int32_t HCameraMovieFileOutput::InitConfig(int32_t opMode)
{
    auto movieFileProxy = movieFileProxy_.Get();
    CHECK_RETURN_RET_ELOG(movieFileProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "movieFileProxy is null");
    using HDI::Camera::V1_5::OperationMode;
    std::vector<OperationMode> supportedModes = { OperationMode::VIDEO, OperationMode::VIDEO_MACRO,
        OperationMode::HIGH_FRAME_RATE, OperationMode::PROFESSIONAL_VIDEO, OperationMode::APERTURE_VIDEO };

    if (std::find(supportedModes.begin(), supportedModes.end(), opMode) != supportedModes.end()) {
        bool isHdr = false;
        if (format_ == OHOS_CAMERA_FORMAT_YCBCR_P010 || format_ == OHOS_CAMERA_FORMAT_YCRCB_P010) {
            isHdr = true;
        }
        int32_t frameRate = frameRateRange_.maxFrameRate;
        int32_t videoBitrate = currentMovieSettings_.videoBitrate;
        movieFileProxy->CreateMovieControllerVideo(width_, height_, isHdr, frameRate, videoBitrate);
        auto videoProducer = movieFileProxy->GetVideoProducer();
        // 如果在Addoutput之前还没有设置OutputSetting，则 videoProducer 为空，设置OutputSetting时进行延迟配流。
        sptr<HStreamRepeat> videoStreamRepeat =
            new HStreamRepeat(videoProducer, format_, width_, height_, RepeatStreamType::VIDEO);
        videoStreamRepeat->SetFrameRate(frameRateRange_.minFrameRate, frameRateRange_.maxFrameRate);
        auto metaSurfaceProducer = movieFileProxy->GetMetaProducer();
        videoStreamRepeat->SetMetaSurface(metaSurfaceProducer, 0);
        videoStreamRepeat_.Set(videoStreamRepeat);
    } else {
        return CamServiceError::CAMERA_UNKNOWN_ERROR;
    }
    return CamServiceError::CAMERA_OK;
}

std::vector<sptr<HStreamRepeat>> HCameraMovieFileOutput::GetStreams()
{
    std::vector<sptr<HStreamRepeat>> streams {};
    streams.emplace_back(videoStreamRepeat_.Get());
    return streams;
}

int32_t HCameraMovieFileOutput::Start()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraMovieFileOutput::Start enter");
    auto movieFileProxy = movieFileProxy_.Get();
    CHECK_RETURN_RET_ELOG(movieFileProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "movieFileProxy is null");
    auto videoStreamRepeat = videoStreamRepeat_.Get();
    CHECK_RETURN_RET_ELOG(!videoStreamRepeat, CamServiceError::CAMERA_DEVICE_FATAL_ERROR,
        "HCameraMovieFileOutput::Start videoStreamRepeat is nullptr");
    int32_t retCode = movieFileProxy->MuxMovieFileStart(0, currentMovieSettings_, cameraPosition_);
    CHECK_RETURN_RET_ELOG(
        retCode != CamServiceError::CAMERA_OK, retCode, "HCameraMovieFileOutput::Start MuxMovieFileStart failed");
    videoStreamRepeat->SetCallback(movieFileProxy->GetVideoStreamCallback());
    retCode = videoStreamRepeat->Start();
    CHECK_RETURN_RET_ELOG(
        retCode != CamServiceError::CAMERA_OK, retCode, "HCameraMovieFileOutput::Start video stream start failed");

    auto callback = GetMovieFileOutputCallback();
    if (callback) {
        callback->OnRecordingStart();
    }
    MEDIA_INFO_LOG("HCameraMovieFileOutput::Start end");
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::Stop()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraMovieFileOutput::Stop enter");
    int64_t currentTime = -1;
    GetCurrentTime(currentTime);
    auto movieFileProxy = movieFileProxy_.Get();
    CHECK_RETURN_RET_ELOG(movieFileProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "movieFileProxy is null");
    auto videoStreamRepeat = videoStreamRepeat_.Get();
    CHECK_RETURN_RET_ELOG(!videoStreamRepeat, CamServiceError::CAMERA_DEVICE_FATAL_ERROR,
        "HCameraMovieFileOutput::Stop videoStreamRepeat is nullptr");
    bool isWakeUp = movieFileProxy->WaitFirstFrame();
    if (!isWakeUp) {
        MEDIA_ERR_LOG("HCameraMovieFileOutput::Stop get first frame timeout");
    }
    int32_t captureId = videoStreamRepeat->GetPreparedCaptureId();
    videoStreamRepeat->Stop();
    auto uri = movieFileProxy->MuxMovieFileStop(currentTime);
    auto callback = GetMovieFileOutputCallback();
    if (callback) {
        callback->OnRecordingStop();
        if (!uri.empty() && isWakeUp) { // 如果没有首帧画面，录制的视频在图库中将是无效视频，不进行数据回调
            callback->OnMovieInfoAvailable(captureId, uri);
        } else {
            MEDIA_ERR_LOG("HCameraMovieFileOutput::Stop uri is empty");
        }
    }
    MEDIA_INFO_LOG("HCameraMovieFileOutput::Stop end");
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::Pause()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("HCameraMovieFileOutput::Pause enter");
    int64_t currentTime = -1;
    GetCurrentTime(currentTime);
    auto movieFileProxy = movieFileProxy_.Get();
    CHECK_RETURN_RET_ELOG(movieFileProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "movieFileProxy is null");
    auto videoStreamRepeat = videoStreamRepeat_.Get();
    CHECK_RETURN_RET_ELOG(!videoStreamRepeat, CamServiceError::CAMERA_DEVICE_FATAL_ERROR,
        "HCameraMovieFileOutput::Pause videoStreamRepeat is nullptr");
    bool isTimeout = movieFileProxy->WaitFirstFrame();
    if (!isTimeout) {
        MEDIA_ERR_LOG("HCameraMovieFileOutput::Pause get first frame timeout");
    }
    videoStreamRepeat->Stop();
    movieFileProxy->MuxMovieFilePause(currentTime);
    auto callback = GetMovieFileOutputCallback();
    if (callback) {
        callback->OnRecordingPause();
    }
    MEDIA_INFO_LOG("HCameraMovieFileOutput::Pause end");
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::Resume()
{
    CAMERA_SYNC_TRACE;
    auto movieFileProxy = movieFileProxy_.Get();
    CHECK_RETURN_RET_ELOG(movieFileProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "movieFileProxy is null");
    auto videoStreamRepeat = videoStreamRepeat_.Get();
    CHECK_RETURN_RET_ELOG(!videoStreamRepeat, CamServiceError::CAMERA_DEVICE_FATAL_ERROR,
        "HCameraMovieFileOutput::Resume videoStreamRepeat is nullptr");
    movieFileProxy->MuxMovieFileResume();
    videoStreamRepeat->Start();
    auto callback = GetMovieFileOutputCallback();
    if (callback) {
        callback->OnRecordingResume();
    }
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::SetOutputSettings(const MovieSettings& movieSettings)
{
    constexpr int32_t VIDEO_BITRATE_MAX = 800000000;
    constexpr int32_t VIDEO_BITRATE_DEFAULT = 30000000;
    currentMovieSettings_ = movieSettings;
    MEDIA_INFO_LOG(
        "HCameraMovieFileOutput::SetOutputSettings currentMovieSettings_ has_value, bitrate:%{public}d",
        currentMovieSettings_.videoBitrate);

    if (currentMovieSettings_.videoBitrate < 0) {
        currentMovieSettings_.videoBitrate = VIDEO_BITRATE_DEFAULT;
    } else if (currentMovieSettings_.videoBitrate > VIDEO_BITRATE_MAX) {
        currentMovieSettings_.videoBitrate = VIDEO_BITRATE_MAX;
    }

    auto movieFileProxy = movieFileProxy_.Get();
    CHECK_RETURN_RET_ELOG(movieFileProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "movieFileProxy is null");

    movieFileProxy->ChangeCodecSettings(currentMovieSettings_.videoCodecType, currentMovieSettings_.rotation,
        currentMovieSettings_.isBFrameEnabled, currentMovieSettings_.videoBitrate);
    auto videoProducer = movieFileProxy->GetVideoProducer();

    // 如果在 Addoutput 之后调用此接口，则 videoStreamRepeat 通过延迟配流的方式进行添加surface
    auto videoStreamRepeat = videoStreamRepeat_.Get();
    if (videoStreamRepeat) {
        videoStreamRepeat->AddDeferredSurface(videoProducer);
    }
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::GetSupportedVideoFilters(std::vector<std::string>& supportedVideoFilters)
{
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::SetMovieFileOutputCallback(const sptr<IMovieFileOutputCallback>& callbackFunc)
{
    MEDIA_INFO_LOG("HCameraMovieFileOutput::SetMovieFileOutputCallback enter");
    std::lock_guard<std::mutex> lock(movieFileOutputCallbackMtx_);
    movieFileOutputCallback_ = callbackFunc;
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::UnsetMovieFileOutputCallback()
{
    MEDIA_INFO_LOG("HCameraMovieFileOutput::UnsetMovieFileOutputCallback enter");
    std::lock_guard<std::mutex> lock(movieFileOutputCallbackMtx_);
    movieFileOutputCallback_ = nullptr;
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::AddVideoFilter(const std::string& filter, const std::string& filterParam)
{
    auto movieFileProxy = movieFileProxy_.Get();
    CHECK_RETURN_RET_ELOG(movieFileProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "movieFileProxy is null");
    movieFileProxy->AddVideoFilter(filter, filterParam);
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::RemoveVideoFilter(const std::string& filter)
{
    auto movieFileProxy = movieFileProxy_.Get();
    CHECK_RETURN_RET_ELOG(movieFileProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "movieFileProxy is null");
    movieFileProxy->RemoveVideoFilter(filter);
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::EnableMirror(bool isEnable)
{
    auto videoStreamRepeat = videoStreamRepeat_.Get();
    CHECK_RETURN_RET_ELOG(!videoStreamRepeat, CamServiceError::CAMERA_DEVICE_FATAL_ERROR,
        "HCameraMovieFileOutput::EnableMirror videoStreamRepeat is nullptr");
    return videoStreamRepeat->SetMirror(isEnable);
}

int32_t HCameraMovieFileOutput::IsMirrorEnabled(bool& isEnable)
{
    auto videoStreamRepeat = videoStreamRepeat_.Get();
    CHECK_RETURN_RET_ELOG(!videoStreamRepeat, CamServiceError::CAMERA_DEVICE_FATAL_ERROR,
        "HCameraMovieFileOutput::IsMirrorEnabled videoStreamRepeat is nullptr");
    return videoStreamRepeat->GetMirror(isEnable);
}

int32_t HCameraMovieFileOutput::Release()
{
    auto videoStreamRepeat = videoStreamRepeat_.Get();
    if (videoStreamRepeat) {
        videoStreamRepeat->Release();
        videoStreamRepeat_.Set(nullptr);
    }
    auto movieFileProxy = movieFileProxy_.Get();
    if (movieFileProxy) {
        movieFileProxy->ReleaseConsumer();
        movieFileProxy->ReleaseController();
    }
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::GetSupportedVideoCapability(int32_t videoCodecType,
    std::shared_ptr<MediaCapabilityProxy>& mediaCapability)
{
    auto avCodecProxy = AVCodecProxy::CreateAVCodecProxy();
    CHECK_RETURN_RET_ELOG(avCodecProxy == nullptr, CAMERA_DEVICE_FATAL_ERROR, "avCodecProxy is null");
    bool isBFrameSupported = avCodecProxy->IsBframeSupported(videoCodecType);
    mediaCapability = std::make_shared<MediaCapabilityProxy>();
    mediaCapability->SetBFrameSupported(isBFrameSupported);
    return CamServiceError::CAMERA_OK;
}

int32_t HCameraMovieFileOutput::CallbackEnter([[maybe_unused]] uint32_t code)
{
    return OperatePermissionCheck(code);
}

int32_t HCameraMovieFileOutput::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    return CamServiceError::CAMERA_OK;
}

void HCameraMovieFileOutput::SetCameraPosition(int32_t position)
{
    MEDIA_INFO_LOG("HCameraMovieFileOutput::SetCameraPosition %{public}d", position);
    cameraPosition_ = position;
}

void HCameraMovieFileOutput::GetCurrentTime(int64_t &currentTime)
{
    struct timespec timestamp = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    currentTime = static_cast<int64_t>(timestamp.tv_sec) * SEC_TO_NS + static_cast<int64_t>(timestamp.tv_nsec);
}

} // namespace CameraStandard
} // namespace OHOS
