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

#include "output/capture_output.h"
#include <memory>
#include <mutex>

#include "camera_error_code.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "capture_session.h"

namespace OHOS {
namespace CameraStandard {
static const char* g_captureOutputTypeString[CAPTURE_OUTPUT_TYPE_MAX] = {"Preview", "Photo", "Video", "Metadata"};

CaptureOutput::CaptureOutput(CaptureOutputType outputType, StreamType streamType, sptr<IBufferProducer> bufferProducer,
    sptr<IStreamCommon> stream)
    : outputType_(outputType), streamType_(streamType), stream_(stream), bufferProducer_(bufferProducer)
{}

void CaptureOutput::RegisterStreamBinderDied()
{
    auto stream = GetStream();
    if (stream == nullptr) {
        return;
    }
    sptr<IRemoteObject> object = stream->AsObject();
    if (object == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) CameraDeathRecipient(0);
        CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new CameraDeathRecipient.");
        deathRecipient_->SetNotifyCb([this](pid_t pid) { OnCameraServerDied(pid); });
    }

    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_ERR_LOG("failed to add deathRecipient");
        return;
    }
}

sptr<IBufferProducer> CaptureOutput::GetBufferProducer()
{
    std::lock_guard<std::mutex> lock(bufferProducerMutex_);
    return bufferProducer_;
}

void CaptureOutput::UnregisterStreamBinderDied()
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    if (deathRecipient_ == nullptr) {
        return;
    }
    auto stream = GetStream();
    if (stream != nullptr) {
        stream->AsObject()->RemoveDeathRecipient(deathRecipient_);
        deathRecipient_ = nullptr;
    }
}

void CaptureOutput::OnCameraServerDied(pid_t pid)
{
    CameraServerDied(pid);
    UnregisterStreamBinderDied();
}

CaptureOutput::~CaptureOutput()
{
    UnregisterStreamBinderDied();
}

CaptureOutputType CaptureOutput::GetOutputType()
{
    return outputType_;
}

const char* CaptureOutput::GetOutputTypeString()
{
    return g_captureOutputTypeString[outputType_];
}

StreamType CaptureOutput::GetStreamType()
{
    return streamType_;
}

bool CaptureOutput::IsStreamCreated()
{
    std::lock_guard<std::mutex> lock(streamMutex_);
    return stream_ != nullptr;
}

sptr<IStreamCommon> CaptureOutput::GetStream()
{
    std::lock_guard<std::mutex> lock(streamMutex_);
    return stream_;
}

void CaptureOutput::SetStream(sptr<IStreamCommon> stream)
{
    {
        std::lock_guard<std::mutex> lock(streamMutex_);
        stream_ = stream;
    }
    RegisterStreamBinderDied();
}

sptr<CaptureSession> CaptureOutput::GetSession()
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    return session_.promote();
}

void CaptureOutput::SetSession(wptr<CaptureSession> captureSession)
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    session_ = captureSession;
}

int32_t CaptureOutput::Release()
{
    {
        UnregisterStreamBinderDied();
        std::lock_guard<std::mutex> lock(streamMutex_);
        stream_ = nullptr;
    }
    SetSession(nullptr);
    return 0;
}

void CaptureOutput::SetPhotoProfile(Profile& profile)
{
    std::lock_guard<std::mutex> lock(photoProfileMutex_);
    photoProfile_ = std::make_shared<Profile>(profile);
}

std::shared_ptr<Profile> CaptureOutput::GetPhotoProfile()
{
    std::lock_guard<std::mutex> lock(photoProfileMutex_);
    return photoProfile_;
}

void CaptureOutput::SetPreviewProfile(Profile& profile)
{
    std::lock_guard<std::mutex> lock(previewProfileMutex_);
    previewProfile_ = std::make_shared<Profile>(profile);
}

std::shared_ptr<Profile> CaptureOutput::GetPreviewProfile()
{
    std::lock_guard<std::mutex> lock(previewProfileMutex_);
    return previewProfile_;
}

void CaptureOutput::SetVideoProfile(VideoProfile& videoProfile)
{
    std::lock_guard<std::mutex> lock(videoProfileMutex_);
    videoProfile_ = std::make_shared<VideoProfile>(videoProfile);
}

std::shared_ptr<VideoProfile> CaptureOutput::GetVideoProfile()
{
    std::lock_guard<std::mutex> lock(videoProfileMutex_);
    return videoProfile_;
}

void CaptureOutput::ClearProfiles()
{
    {
        std::lock_guard<std::mutex> lock(previewProfileMutex_);
        previewProfile_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(photoProfileMutex_);
        photoProfile_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(videoProfileMutex_);
        videoProfile_ = nullptr;
    }
}

void CaptureOutput::AddTag(Tag tag)
{
    std::lock_guard<std::mutex> lock(tagsMutex_);
    tags_.insert(tag);
}

void CaptureOutput::RemoveTag(Tag tag)
{
    std::lock_guard<std::mutex> lock(tagsMutex_);
    tags_.erase(tag);
}

bool CaptureOutput::IsTagSetted(Tag tag)
{
    std::lock_guard<std::mutex> lock(tagsMutex_);
    return tags_.find(tag) != tags_.end();
}

} // CameraStandard
} // OHOS
