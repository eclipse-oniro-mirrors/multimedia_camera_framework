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

#include "recorder_engine_proxy.h"
#include "camera_log.h"
#include "recorder_engine_interface.h"

namespace OHOS::CameraStandard {

RecorderEngineProxy::RecorderEngineProxy(
    std::shared_ptr<Dynamiclib> mediaStreamLib, std::shared_ptr<RecorderEngineIntf> recorderEngineIntf)
    : mediaStreamLib_(mediaStreamLib), recorderEngineIntf_(recorderEngineIntf)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy ctor is called");
}

RecorderEngineProxy::~RecorderEngineProxy()
{
    MEDIA_INFO_LOG("RecorderEngineProxy dtor is called");
}

using CreateRecorderEngineIntf = RecorderEngineIntf*(*)();

std::shared_ptr<RecorderEngineProxy> RecorderEngineProxy::CreateRecorderEngineProxy()
{
    MEDIA_DEBUG_LOG("CreateRecorderEngineProxy start");
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_STREAM_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "get dynamiclib fail");
    CreateRecorderEngineIntf createRecorderEngineIntf
        = (CreateRecorderEngineIntf)dynamiclib->GetFunction("createRecorderEngineIntf");
    CHECK_RETURN_RET_ELOG(createRecorderEngineIntf == nullptr, nullptr, "createRecorderEngineIntf fail");
    RecorderEngineIntf* recorderEngineIntf = createRecorderEngineIntf();
    CHECK_RETURN_RET_ELOG(recorderEngineIntf == nullptr, nullptr, "get recorderEngineIntf fail");
    return std::make_shared<RecorderEngineProxy>(dynamiclib, std::shared_ptr<RecorderEngineIntf>(recorderEngineIntf));
}

void RecorderEngineProxy::FreeMediaStreamDynamiclib()
{
    constexpr uint32_t delayMs = 60 * 1000; // 60 second
    CameraDynamicLoader::FreeDynamicLibDelayed(MEDIA_STREAM_SO, delayMs);
}

void RecorderEngineProxy::CreateRecorderEngine(wptr<RecorderIntf> recorder)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::CreateRecorderEngine is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->CreateRecorderEngine(recorder);
}

int32_t RecorderEngineProxy::Prepare()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::Prepare is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->Prepare();
}

int32_t RecorderEngineProxy::StartRecording()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::StartRecording is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->StartRecording();
}

int32_t RecorderEngineProxy::PauseRecording()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::PauseRecording is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->PauseRecording();
}

int32_t RecorderEngineProxy::ResumeRecording()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::ResumeRecording is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->ResumeRecording();
}

int32_t RecorderEngineProxy::StopRecording()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::StopRecording is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->StopRecording();
}

int32_t RecorderEngineProxy::SetRotation(int32_t rotation)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetRotation is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->SetRotation(rotation);
}

int32_t RecorderEngineProxy::SetOutputSettings(const EngineMovieSettings& movieSettings)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetOutputSettings is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->SetOutputSettings(movieSettings);
}

int32_t RecorderEngineProxy::Init()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::Init is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->Init();
}

int32_t RecorderEngineProxy::GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetSupportedVideoFilters is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->GetSupportedVideoFilters(supportedVideoFilters);
}

int32_t RecorderEngineProxy::SetVideoFilter(const std::string& filter, const std::string& filterParam)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetVideoFilter is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->SetVideoFilter(filter, filterParam);
}

int32_t RecorderEngineProxy::SetUserMeta(const std::string& key, const std::string& val)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetUserMeta is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->SetUserMeta(key, val);
}

int32_t RecorderEngineProxy::SetUserMeta(const std::string& key, const std::vector<uint8_t>& val)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetUserMeta is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->SetUserMeta(key, val);
}

void RecorderEngineProxy::GetFirstFrameTimestamp(int64_t& firstFrameTimestamp)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetFirstFrameTimestamp is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->GetFirstFrameTimestamp(firstFrameTimestamp);
}

void RecorderEngineProxy::SetIsWaitForMeta(bool isWait)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetIsWaitForMeta is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->SetIsWaitForMeta(isWait);
}

void RecorderEngineProxy::SetIsWaitForMuxerDone(bool isWait)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetIsWaitForMuxerDone is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->SetIsWaitForMuxerDone(isWait);
}

void RecorderEngineProxy::SetIsStreamStarted(bool isStarted)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetIsStreamStarted is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->SetIsStreamStarted(isStarted);
}

int32_t RecorderEngineProxy::UpdatePhotoProxy(const std::string& videoId, int32_t videoEnhancementType)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::UpdatePhotoProxy is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->UpdatePhotoProxy(videoId, videoEnhancementType);
}

bool RecorderEngineProxy::IsNeedWaitForMuxerDone()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::IsNeedWaitForMuxerDone is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, false, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->IsNeedWaitForMuxerDone();
}

sptr<Surface> RecorderEngineProxy::GetRawSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetRawSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, nullptr, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->GetRawSurface();
}

sptr<Surface> RecorderEngineProxy::GetDepthSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetDepthSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, nullptr, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->GetDepthSurface();
}

sptr<Surface> RecorderEngineProxy::GetPreySurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetPreySurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, nullptr, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->GetPreySurface();
}

sptr<Surface> RecorderEngineProxy::GetMetaSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetMetaSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, nullptr, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->GetMetaSurface();
}

sptr<Surface> RecorderEngineProxy::GetMovieDebugSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetMovieDebugSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, nullptr, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->GetMovieDebugSurface();
}

sptr<Surface> RecorderEngineProxy::GetRawDebugSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetRawDebugSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, nullptr, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->GetRawDebugSurface();
}

sptr<Surface> RecorderEngineProxy::GetImageEffectSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetImageEffectSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, nullptr, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->GetImageEffectSurface();
}

void RecorderEngineProxy::WaitForRawMuxerDone()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::WaitForRawMuxerDone is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->WaitForRawMuxerDone();
}

void RecorderEngineProxy::SetMovieFrameSize(int32_t width, int32_t height)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetMovieFrameSize is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->SetMovieFrameSize(width, height);
}

void RecorderEngineProxy::SetRawFrameSize(int32_t width, int32_t height)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetRawFrameSize is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->SetRawFrameSize(width, height);
}

int32_t RecorderEngineProxy::EnableVirtualAperture(bool isVirtualApertureEnabled)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::EnableVirtualAperture is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, MEDIA_ERR, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->EnableVirtualAperture(isVirtualApertureEnabled);
}

std::string RecorderEngineProxy::GetMovieFileUri()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::GetMovieFileUri is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, "", "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->GetMovieFileUri();
}

bool RecorderEngineProxy::IsNeedStopCallback()
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::IsNeedStopCallback is called");
    CHECK_RETURN_RET_ELOG(recorderEngineIntf_ == nullptr, false, "recorderEngineIntf_ is nullptr");
    return recorderEngineIntf_->IsNeedStopCallback();
}

void RecorderEngineProxy::SetIsNeedStopCallback(bool isNeed)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetIsNeedStopCallback is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->SetIsNeedStopCallback(isNeed);
}

void RecorderEngineProxy::SetIsNeedWaitForRawMuxerDone(bool isNeed)
{
    MEDIA_DEBUG_LOG("RecorderEngineProxy::SetIsNeedWaitForRawMuxerDone is called");
    CHECK_RETURN_ELOG(recorderEngineIntf_ == nullptr, "recorderEngineIntf_ is nullptr");
    recorderEngineIntf_->SetIsNeedWaitForRawMuxerDone(isNeed);
}
}  // namespace OHOS::CameraStandard