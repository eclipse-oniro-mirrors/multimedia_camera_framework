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
#include "movie_file_recorder.h"

#include <fcntl.h>
#include <memory>

#include "camera_log.h"
#include "camera_util.h"
#include "camera_xml_parser.h"
#include "hstream_metadata.h"
#include "image_effect_proxy.h"
#include "image_source.h"
#include "ipc_skeleton.h"
#include "recorder_engine_interface.h"
#include "token_setproc.h"

namespace OHOS {
namespace CameraStandard {
namespace {
// rotation
std::atomic<int32_t> g_motionRotationCoef{0};
}

class RecorderProxy : public RecorderIntf {
public:
    explicit RecorderProxy(wptr<MovieFileRecorder> recorder)
    {
        recorder_ = recorder;
    }

    int32_t GetMuxerRotation() override
    {
        if (auto recorder = recorder_.promote()) {
            return recorder->GetMuxerRotation();
        }
        return 90;
    }

    void SetFirstFrameTimestamp(int64_t firstTimestamp) override
    {
        if (auto recorder = recorder_.promote()) {
            recorder->SetFirstFrameTimestamp(firstTimestamp);
        }
    }

    void EnableDetectedObjectLifecycleReport(bool isEnable, int64_t timestamp) override
    {
        if (auto recorder = recorder_.promote()) {
            recorder->EnableDetectedObjectLifecycleReport(isEnable, timestamp);
        }
    }

    bool IsMovieStreamHdr() override
    {
        if (auto recorder = recorder_.promote()) {
            return recorder->IsMovieStreamHdr();
        }
        return false;
    }
private:
    wptr<MovieFileRecorder> recorder_;
};

MovieFileRecorder::MovieFileRecorder()
{
    MEDIA_DEBUG_LOG("MovieFileRecorder ctor is called");
    RegisterSensorRotationCallback();
    recorderEngineProxy_.Set(RecorderEngineProxy::CreateRecorderEngineProxy());
}

MovieFileRecorder::~MovieFileRecorder()
{
    MEDIA_INFO_LOG("MovieFileRecorder dtor is called");
    UnregisterSensorRotationCallback();
    Release();
    recorderProxy_ = nullptr;
    recorderEngineProxy_.Set(nullptr);
}

int32_t MovieFileRecorder::Init()
{
    MEDIA_INFO_LOG("MovieFileRecorder::Init is called");
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    recorderProxy_ = sptr<RecorderProxy>::MakeSptr(this);
    engine->CreateRecorderEngine(recorderProxy_);
    return engine->Init();
}

int32_t MovieFileRecorder::Prepare()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("MovieFileRecorder::Prepare is called");
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    return engine->Prepare();
};

int32_t MovieFileRecorder::Start()
{
    MEDIA_INFO_LOG("MovieFileRecorder::Start is called");
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    int32_t ret = engine->StartRecording();
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, CAMERA_INVALID_STATE, "StartRecording failed");

    auto appCallback = appCallback_.Get();
    CHECK_EXECUTE(appCallback, appCallback->OnRecordingStart());

    ret = StartStreams();
    if (ret == CAMERA_OK) {
        engine->SetIsWaitForMeta(true);
    } else {
        MEDIA_ERR_LOG("StartStreams failed");
        engine->SetIsWaitForMeta(false);
        engine->SetIsStreamStarted(false);
    }
    engine->SetIsWaitForMuxerDone(true);
    return CAMERA_OK;
}

int32_t MovieFileRecorder::Pause()
{
    MEDIA_INFO_LOG("MovieFileRecorder::Pause is called");
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    int32_t ret = engine->PauseRecording();
    auto appCallback = appCallback_.Get();
    CHECK_EXECUTE(appCallback, appCallback->OnRecordingPause());
    return ret;
}

int32_t MovieFileRecorder::Resume()
{
    MEDIA_INFO_LOG("MovieFileRecorder::Resume is called");
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    int32_t ret = engine->ResumeRecording();
    auto appCallback = appCallback_.Get();
    CHECK_EXECUTE(appCallback, appCallback->OnRecordingResume());
    return ret;
}

int32_t MovieFileRecorder::Stop()
{
    return Stop(true);
}

int32_t MovieFileRecorder::Stop(bool needWait)
{
    MEDIA_INFO_LOG("MovieFileRecorder::Stop is called, need wait: %{public}d", needWait);
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    int32_t ret = CAMERA_INVALID_STATE;
    if (engine->IsNeedWaitForMuxerDone()) {
        engine->SetIsNeedStopCallback(true);
        engine->SetIsNeedWaitForRawMuxerDone(true);
    }

    CHECK_EXECUTE(!needWait, engine->SetIsStreamStarted(false));

    // stop recorder first, then stop stream, so the stop condition will be notified continously,
    // otherwise the recorder will wait for stop until timeout
    ret = engine->StopRecording();
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "StopRecording failed");

    if (engine->IsNeedStopCallback()) {
        MEDIA_DEBUG_LOG("MovieFileRecorder::Stop execute app callback");
        auto appCallback = appCallback_.Get();
        if (appCallback == nullptr) {
            MEDIA_ERR_LOG("execute app callback failed, appCallback is nullptr");
        } else {
            int32_t ret = appCallback->OnRecordingStop();
            MEDIA_DEBUG_LOG("appCallback->OnRecordingStop ret: %{public}d", ret);
            ret = appCallback->OnPhotoAssetAvailable(engine->GetMovieFileUri());
            MEDIA_DEBUG_LOG("appCallback->OnPhotoAssetAvailable ret: %{public}d", ret);
        }
        engine->SetIsNeedStopCallback(false);
    }

    ret = StopStreams();
    engine->WaitForRawMuxerDone();
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "StopStreams failed");
    return CAMERA_OK;
}

int32_t MovieFileRecorder::Reset()
{
    MEDIA_INFO_LOG("MovieFileRecorder::Reset is called");
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    int32_t ret = engine->StopRecording();
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, CAMERA_INVALID_STATE, "Reset failed");

    MEDIA_INFO_LOG("MovieFileRecorder::Reset start stop stream");
    ret = StopStreams();
    return ret;
}

int32_t MovieFileRecorder::Release()
{
    MEDIA_INFO_LOG("MovieFileRecorder::Release is called");
    int32_t ret = CAMERA_OK;

    // stop first to release filters
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    engine->SetIsStreamStarted(false);
    ret = Stop();
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "StopRecording failed");

    ret = ReleaseStreams();
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "Release stream failed");

    movieStream_.Set(nullptr);
    rawStream_.Set(nullptr);
    metadataStream_.Set(nullptr);
    return CAMERA_OK;
}

int32_t MovieFileRecorder::StartStreams()
{
    MEDIA_DEBUG_LOG("MovieFileRecorder::StartStreams is called.");
    int32_t ret = CAMERA_OK;
    auto movieStream = movieStream_.Get();
    CHECK_RETURN_RET_ELOG(movieStream == nullptr, CAMERA_INVALID_STATE, "movieStream is null");
    ret = movieStream->Start();
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "movieStream start failed");
    auto rawStream = rawStream_.Get();
    CHECK_RETURN_RET_ELOG(rawStream == nullptr, CAMERA_INVALID_STATE, "rawStream is null");
    ret = rawStream->Start();
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "rawStream start failed");
    return CAMERA_OK;
}

int32_t MovieFileRecorder::StopStreams()
{
    MEDIA_INFO_LOG("MovieFileRecorder::StopStreams is called.");
    int32_t ret = CAMERA_OK;
    // stop movie stream
    auto movieStream = movieStream_.Get();
    CHECK_RETURN_RET_ELOG(movieStream == nullptr, CAMERA_INVALID_STATE, "movieStream is null");
    ret = movieStream->Stop();
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "movieStream stop failed");
    // stop raw stream
    auto rawStream = rawStream_.Get();
    CHECK_RETURN_RET_ELOG(rawStream == nullptr, CAMERA_INVALID_STATE, "rawStream is null");
    ret = rawStream->Stop();
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "rawStream stop failed");
    MEDIA_INFO_LOG("MovieFileRecorder::StopStreams exit.");
    return CAMERA_OK;
}

int32_t MovieFileRecorder::ReleaseStreams()
{
    MEDIA_DEBUG_LOG("MovieFileRecorder::ReleaseStreams is called.");
    int32_t ret = CAMERA_OK;
    // release movie stream
    auto movieStream = movieStream_.Get();
    CHECK_RETURN_RET_ELOG(movieStream == nullptr, CAMERA_INVALID_STATE, "movieStream is null");
    ret = movieStream->Release();
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "movieStream release failed");
    // release raw stream
    auto rawStream = rawStream_.Get();
    CHECK_RETURN_RET_ELOG(rawStream == nullptr, CAMERA_INVALID_STATE, "rawStream is null");
    ret = rawStream->Release();
    CHECK_PRINT_ELOG(ret != CAMERA_OK, "rawStream release failed");
    return CAMERA_OK;
}

sptr<Surface> MovieFileRecorder::GetRawSurface()
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, nullptr, "engine is null");
    return engine->GetRawSurface();
}

sptr<Surface> MovieFileRecorder::GetMetaSurface()
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, nullptr, "engine is null");
    return engine->GetMetaSurface();
}

sptr<Surface> MovieFileRecorder::GetMovieDebugSurface()
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, nullptr, "engine is null");
    return engine->GetMovieDebugSurface();
}

sptr<Surface> MovieFileRecorder::GetRawDebugSurface()
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, nullptr, "engine is null");
    return engine->GetRawDebugSurface();
}

sptr<Surface> MovieFileRecorder::GetDepthSurface()
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, nullptr, "engine is null");
    return engine->GetDepthSurface();
}

sptr<Surface> MovieFileRecorder::GetPreySurface()
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, nullptr, "engine is null");
    return engine->GetPreySurface();
}

sptr<Surface> MovieFileRecorder::GetImageEffectSurface()
{
    CAMERA_SYNC_TRACE;
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, nullptr, "engine is null");
    return engine->GetImageEffectSurface();
}

void MovieFileRecorder::SetMovieFrameSize(int32_t width, int32_t height)
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_ELOG(engine == nullptr, "engine is null");
    engine->SetMovieFrameSize(width, height);
}

void MovieFileRecorder::SetRawFrameSize(int32_t width, int32_t height)
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_ELOG(engine == nullptr, "engine is null");
    engine->SetRawFrameSize(width, height);
}

void MovieFileRecorder::SetMovieStream(sptr<HStreamRepeat> stream)
{
    movieStream_.Set(stream);
}

void MovieFileRecorder::SetRawStream(sptr<HStreamRepeat> stream)
{
    rawStream_.Set(stream);
}

int32_t MovieFileRecorder::SetMetadataStream(const sptr<IStreamMetadata>& stream)
{
    metadataStream_.Set(static_cast<HStreamMetadata*>(stream.GetRefPtr()));
    return CAMERA_OK;
}

int32_t MovieFileRecorder::GetDetectedObjectLifecycleBuffer(std::vector<uint8_t>& buffer)
{
    auto metadataStream = metadataStream_.Get();
    CHECK_RETURN_RET_ELOG(metadataStream == nullptr, CAMERA_OK, "metadataStream is null");
    metadataStream->GetDetectedObjectLifecycleBuffer(buffer);
    return CAMERA_OK;
}

int32_t MovieFileRecorder::SetRotation(int32_t rotation)
{
    MEDIA_INFO_LOG("MovieFileRecorder::SetRotation, rotation: %{public}d", rotation);
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    return engine->SetRotation(rotation);
}

int32_t MovieFileRecorder::SetOutputSettings(const MovieSettings& movieSettings)
{
    // 首次打开电影模式时调用
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    movieSettings_.videoCodecType = static_cast<EngineVideoCodecType>(
        static_cast<int32_t>(movieSettings.videoCodecType));
    movieSettings_.rotation = movieSettings.rotation;
    movieSettings_.isHasLocation = movieSettings.isHasLocation;
    movieSettings_.location = {
        movieSettings.location.latitude,
        movieSettings.location.longitude,
        movieSettings.location.altitude};
    movieSettings_.isBFrameEnabled = movieSettings.isBFrameEnabled;
    movieSettings_.videoBitrate = movieSettings.videoBitrate;
    return engine->SetOutputSettings(movieSettings_);
}

int32_t MovieFileRecorder::SetRecorderCallback(const sptr<ICameraRecorderCallback>& callback)
{
    MEDIA_INFO_LOG("MovieFileRecorder::SetRecorderCallback in");
    appCallback_.Set(callback);
    return CAMERA_OK;
}

int32_t MovieFileRecorder::GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters)
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    return engine->GetSupportedVideoFilters(supportedVideoFilters);
}

int32_t MovieFileRecorder::SetVideoFilter(const std::string& filter, const std::string& filterParam)
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    return engine->SetVideoFilter(filter, filterParam);
}

int32_t MovieFileRecorder::EnableMirror(bool isEnable)
{
    MEDIA_INFO_LOG("MovieFileRecorder::EnableMirror is called, isEnable: %{public}d", isEnable);
    int32_t ret = CAMERA_INVALID_STATE;
    auto movieStream = movieStream_.Get();
    CHECK_RETURN_RET_ELOG(movieStream == nullptr, ret, "movieStream is null");
    auto rawStream = rawStream_.Get();
    CHECK_RETURN_RET_ELOG(rawStream == nullptr, ret, "rawStream is null");

    ret = movieStream->SetMirror(isEnable);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "movieStream SetMirror failed");

    ret = rawStream->SetMirror(isEnable);
    CHECK_RETURN_RET_ELOG(ret != CAMERA_OK, ret, "rawStream SetMirror failed");

    isMirrorEnabled_ = isEnable;

    return CAMERA_OK;
}

int32_t MovieFileRecorder::SetUserMeta(const std::string& key, const std::string& val)
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    return engine->SetUserMeta(key, val);
}

int32_t MovieFileRecorder::SetUserMeta(const std::string& key, const std::vector<uint8_t>& val)
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    return engine->SetUserMeta(key, val);
}

int32_t MovieFileRecorder::UpdatePhotoProxy(const std::string& videoId, int32_t videoEnhancementType)
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    return engine->UpdatePhotoProxy(videoId, videoEnhancementType);
}

int32_t MovieFileRecorder::EnableVirtualAperture(bool isVirtualApertureEnabled)
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    return engine->EnableVirtualAperture(isVirtualApertureEnabled);
}

int32_t MovieFileRecorder::OperatePermissionCheck(uint32_t interfaceCode)
{
    CHECK_RETURN_RET_ELOG(!CheckSystemApp(), CAMERA_NO_PERMISSION,
                          "MovieFileRecorder check system permission failed, interface code:%{public}u", interfaceCode);
    return CAMERA_OK;
}

int32_t MovieFileRecorder::CallbackEnter([[maybe_unused]] uint32_t code)
{
    MEDIA_INFO_LOG("start, code:%{public}u", code);
    DisableJeMalloc();
    return OperatePermissionCheck(code);
}

int32_t MovieFileRecorder::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    MEDIA_INFO_LOG("leave, code:%{public}u, result:%{public}d", code, result);
    return CAMERA_OK;
}

void MovieFileRecorder::RegisterSensorRotationCallback()
{
    MEDIA_INFO_LOG("RegisterSensorRotationCallback is called");
    CHECK_RETURN_ELOG(!OHOS::Rosen::LoadMotionSensor(), "RegisterSensorRotationCallback LoadMotionSensor fail");
    CHECK_RETURN_ELOG(!OHOS::Rosen::SubscribeCallback(OHOS::Rosen::MOTION_TYPE_ROTATION, SensorRotationCallbackImpl),
        "RegisterSensorRotationCallback SubscribeCallback fail");
}

void MovieFileRecorder::UnregisterSensorRotationCallback()
{
    MEDIA_INFO_LOG("UnRegisterSensorRotationCallback is called");
    CHECK_RETURN_ELOG(!UnsubscribeCallback(OHOS::Rosen::MOTION_TYPE_ROTATION, SensorRotationCallbackImpl),
        "UnregisterSensorRotationCallback UnsubscribeCallback fail");
}

void MovieFileRecorder::SensorRotationCallbackImpl(const OHOS::Rosen::MotionSensorEvent &motionData)
{
    std::ostringstream oss;
    oss << "type=" << motionData.type << ",";
    oss << "status=" << motionData.status << ",";
    MEDIA_DEBUG_LOG("SensorRotationCallbackImpl %{public}s", oss.str().c_str());
    CHECK_EXECUTE(motionData.status >= 0, g_motionRotationCoef = motionData.status);
}

int32_t MovieFileRecorder::GetMuxerRotation()
{
    // formula: muxerRotation = (sensorOrientation + sign * motionRotation) % 360
    MEDIA_INFO_LOG("GetMuxerRotation is called");
    auto movieStream = movieStream_.Get();
    CHECK_RETURN_RET(movieStream == nullptr, CAMERA_OK);
    // get device rotation
    constexpr int32_t motionRotationBase = 90;
    int32_t motionRotation = (360 - g_motionRotationCoef * motionRotationBase) % 360;
    return movieStream->GetMuxerRotation(motionRotation);
}

void MovieFileRecorder::SetFirstFrameTimestamp(int64_t firstTimestamp)
{
    auto metadataStream = metadataStream_.Get();
    CHECK_EXECUTE(metadataStream, metadataStream->SetFirstFrameTimestamp(firstTimestamp));
}

void MovieFileRecorder::EnableDetectedObjectLifecycleReport(bool isEnable, int64_t timestamp)
{
    auto metadataStream = metadataStream_.Get();
    CHECK_EXECUTE(metadataStream, metadataStream->EnableDetectedObjectLifecycleReport(isEnable, timestamp));
}

bool MovieFileRecorder::IsMovieStreamHdr()
{
    MEDIA_INFO_LOG("IsMovieStreamHdr is called");
    auto movieStream = movieStream_.Get();
    CHECK_RETURN_RET(movieStream == nullptr, false);
    ColorSpace colorSpace = movieStream->GetColorSpace();
    bool isMovieHdr = IsHdr(colorSpace);
    MEDIA_INFO_LOG("IsMovieStreamHdr, isMovieHdr: %{public}d, colorSpace: %{public}d", isMovieHdr, colorSpace);
    return isMovieHdr;
}

bool MovieFileRecorder::IsHdr(ColorSpace colorSpace)
{
    std::vector<ColorSpace> hdrColorSpaces = {BT2020_HLG, BT2020_PQ, BT2020_HLG_LIMIT,
                                             BT2020_PQ_LIMIT};
    auto it = std::find(hdrColorSpaces.begin(), hdrColorSpaces.end(), colorSpace);
    return it != hdrColorSpaces.end();
}

int32_t MovieFileRecorder::GetFirstFrameTimestamp(int64_t& firstFrameTimestamp)
{
    auto engine = recorderEngineProxy_.Get();
    CHECK_RETURN_RET_ELOG(engine == nullptr, CAMERA_UNKNOWN_ERROR, "engine is null");
    engine->GetFirstFrameTimestamp(firstFrameTimestamp);
    return CAMERA_OK;
}
}
}