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

#include "recorder_engine_adapter.h"
#include "camera_log.h"
#include <memory>

namespace OHOS::CameraStandard {
RecorderEngineAdapter::RecorderEngineAdapter()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter ctor is called");
}

RecorderEngineAdapter::~RecorderEngineAdapter()
{
    MEDIA_INFO_LOG("RecorderEngineAdapter dtor is called");
}

void RecorderEngineAdapter::CreateRecorderEngine(wptr<RecorderIntf> recorder)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::CreateRecorderEngine is called");
    recorderEngine_ = sptr<RecorderEngine>::MakeSptr(recorder);
}

int32_t RecorderEngineAdapter::Prepare()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::Prepare is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->Prepare();
}

int32_t RecorderEngineAdapter::StartRecording()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::StartRecording is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->StartRecording() == Status::OK ? MEDIA_OK : MEDIA_ERR;
}

int32_t RecorderEngineAdapter::PauseRecording()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::PauseRecording is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->PauseRecording() == Status::OK ? MEDIA_OK : MEDIA_ERR;
}

int32_t RecorderEngineAdapter::ResumeRecording()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::ResumeRecording is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->ResumeRecording() == Status::OK ? MEDIA_OK : MEDIA_ERR;
}

int32_t RecorderEngineAdapter::StopRecording()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::StopRecording is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->StopRecording() == Status::OK ? MEDIA_OK : MEDIA_ERR;
}

int32_t RecorderEngineAdapter::SetRotation(int32_t rotation)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetRotation is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    recorderEngine_->SetRotation(rotation);
    return MEDIA_OK;
}

int32_t RecorderEngineAdapter::SetOutputSettings(const EngineMovieSettings& movieSettings)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetOutputSettings is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->SetOutputSettings(movieSettings);
}

int32_t RecorderEngineAdapter::Init()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::Init is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->Init();
}

int32_t RecorderEngineAdapter::GetSupportedVideoFilters(std::vector<std::string> &supportedVideoFilters)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetSupportedVideoFilters is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->GetSupportedVideoFilters(supportedVideoFilters);
}

int32_t RecorderEngineAdapter::SetVideoFilter(const std::string& filter, const std::string& filterParam)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetVideoFilter is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->SetVideoFilter(filter, filterParam);
}

int32_t RecorderEngineAdapter::SetUserMeta(const std::string& key, const std::string& val)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetUserMeta is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->SetUserMeta(key, val);
}

int32_t RecorderEngineAdapter::SetUserMeta(const std::string& key, const std::vector<uint8_t>& val)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetUserMeta is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is null");
    return recorderEngine_->SetUserMeta(key, val);
}

void RecorderEngineAdapter::GetFirstFrameTimestamp(int64_t& firstFrameTimestamp)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetFirstFrameTimestamp is called");
    CHECK_RETURN_ELOG(recorderEngine_ == nullptr, "recorderEngine_ is null");
    recorderEngine_->GetFirstFrameTimestamp(firstFrameTimestamp);
}

void RecorderEngineAdapter::SetIsWaitForMeta(bool isWait)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetIsWaitForMeta is called");
    CHECK_RETURN_ELOG(recorderEngine_ == nullptr, "recorderEngine_ is nullptr");
    recorderEngine_->SetIsWaitForMeta(isWait);
}

void RecorderEngineAdapter::SetIsWaitForMuxerDone(bool isWait)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetIsWaitForMuxerDone is called");
    CHECK_RETURN_ELOG(recorderEngine_ == nullptr, "recorderEngine_ is nullptr");
    recorderEngine_->SetIsWaitForMuxerDone(isWait);
}

void RecorderEngineAdapter::SetIsStreamStarted(bool isStarted)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetIsStreamStarted is called");
    CHECK_RETURN_ELOG(recorderEngine_ == nullptr, "recorderEngine_ is nullptr");
    recorderEngine_->SetIsStreamStarted(isStarted);
}

int32_t RecorderEngineAdapter::UpdatePhotoProxy(const std::string& videoId, int32_t videoEnhancementType)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::UpdatePhotoProxy is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is nullptr");
    return recorderEngine_->UpdatePhotoProxy(videoId, videoEnhancementType);
}

bool RecorderEngineAdapter::IsNeedWaitForMuxerDone()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::IsNeedWaitForMuxerDone is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, false, "recorderEngine_ is nullptr");
    return recorderEngine_->IsNeedWaitForMuxerDone();
}

sptr<Surface> RecorderEngineAdapter::GetRawSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetRawSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, nullptr, "recorderEngine_ is nullptr");
    return recorderEngine_->GetRawSurface();
}

sptr<Surface> RecorderEngineAdapter::GetDepthSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetDepthSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, nullptr, "recorderEngine_ is nullptr");
    return recorderEngine_->GetDepthSurface();
}

sptr<Surface> RecorderEngineAdapter::GetPreySurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetPreySurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, nullptr, "recorderEngine_ is nullptr");
    return recorderEngine_->GetPreySurface();
}

sptr<Surface> RecorderEngineAdapter::GetMetaSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetMetaSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, nullptr, "recorderEngine_ is nullptr");
    return recorderEngine_->GetMetaSurface();
}

sptr<Surface> RecorderEngineAdapter::GetMovieDebugSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetMovieDebugSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, nullptr, "recorderEngine_ is nullptr");
    return recorderEngine_->GetMovieDebugSurface();
}

sptr<Surface> RecorderEngineAdapter::GetRawDebugSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetRawDebugSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, nullptr, "recorderEngine_ is nullptr");
    return recorderEngine_->GetRawDebugSurface();
}

sptr<Surface> RecorderEngineAdapter::GetImageEffectSurface()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetImageEffectSurface is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, nullptr, "recorderEngine_ is nullptr");
    return recorderEngine_->GetImageEffectSurface();
}

void RecorderEngineAdapter::WaitForRawMuxerDone()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::WaitForRawMuxerDone is called");
    CHECK_RETURN_ELOG(recorderEngine_ == nullptr, "recorderEngine_ is nullptr");
    recorderEngine_->WaitForRawMuxerDone();
}

void RecorderEngineAdapter::SetMovieFrameSize(int32_t width, int32_t height)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetMovieFrameSize is called");
    CHECK_RETURN_ELOG(recorderEngine_ == nullptr, "recorderEngine_ is nullptr");
    recorderEngine_->SetMovieFrameSize(width, height);
}

void RecorderEngineAdapter::SetRawFrameSize(int32_t width, int32_t height)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetRawFrameSize is called");
    CHECK_RETURN_ELOG(recorderEngine_ == nullptr, "recorderEngine_ is nullptr");
    recorderEngine_->SetRawFrameSize(width, height);
}

int32_t RecorderEngineAdapter::EnableVirtualAperture(bool isVirtualApertureEnabled)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::EnableVirtualAperture is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, MEDIA_ERR, "recorderEngine_ is nullptr");
    return recorderEngine_->EnableVirtualAperture(isVirtualApertureEnabled);
}

std::string RecorderEngineAdapter::GetMovieFileUri()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::GetMovieFileUri is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, "", "recorderEngine_ is nullptr");
    return recorderEngine_->GetMovieFileUri();
}

bool RecorderEngineAdapter::IsNeedStopCallback()
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::IsNeedStopCallback is called");
    CHECK_RETURN_RET_ELOG(recorderEngine_ == nullptr, false, "recorderEngine_ is nullptr");
    return recorderEngine_->IsNeedStopCallback();
}

void RecorderEngineAdapter::SetIsNeedStopCallback(bool isNeed)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetIsNeedStopCallback is called");
    CHECK_RETURN_ELOG(recorderEngine_ == nullptr, "recorderEngine_ is nullptr");
    recorderEngine_->SetIsNeedStopCallback(isNeed);
}

void RecorderEngineAdapter::SetIsNeedWaitForRawMuxerDone(bool isNeed)
{
    MEDIA_DEBUG_LOG("RecorderEngineAdapter::SetIsNeedWaitForRawMuxerDone is called");
    CHECK_RETURN_ELOG(recorderEngine_ == nullptr, "recorderEngine_ is nullptr");
    recorderEngine_->SetIsNeedWaitForRawMuxerDone(isNeed);
}

extern "C" RecorderEngineIntf *createRecorderEngineIntf()
{
    return new RecorderEngineAdapter();
}
}  // namespace OHOS::CameraStandard