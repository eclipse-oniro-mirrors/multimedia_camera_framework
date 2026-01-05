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

CaptureOutput::CaptureOutput(CaptureOutputType outputType, StreamType streamType, sptr<IStreamCommon> stream)
    : outputType_(outputType), streamType_(streamType), stream_(stream)
{}

void CaptureOutput::RegisterStreamBinderDied()
{
    auto stream = GetStream();
    CHECK_RETURN(stream == nullptr);
    sptr<IRemoteObject> object = stream->AsObject();
    CHECK_RETURN(object == nullptr);
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) CameraDeathRecipient(0);
        CHECK_RETURN_ELOG(deathRecipient_ == nullptr, "failed to new CameraDeathRecipient.");
        auto thisPtr = wptr<CaptureOutput>(this);
        deathRecipient_->SetNotifyCb([thisPtr](pid_t pid) {
            auto ptr = thisPtr.promote();
            CHECK_RETURN(ptr == nullptr);
            ptr->OnCameraServerDied(pid);
        });
    }

    bool result = object->AddDeathRecipient(deathRecipient_);
    CHECK_RETURN_ELOG(!result, "failed to add deathRecipient");
}

sptr<IBufferProducer> CaptureOutput::GetBufferProducer()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(bufferProducerMutex_);
    return bufferProducer_;
    // LCOV_EXCL_STOP
}

std::string CaptureOutput::GetPhotoSurfaceId()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(bufferProducerMutex_);
    return surfaceId_;
    // LCOV_EXCL_STOP
}

void CaptureOutput::UnregisterStreamBinderDied()
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    CHECK_RETURN(deathRecipient_ == nullptr);
    auto stream = GetStream();
    if (stream != nullptr) {
        stream->AsObject()->RemoveDeathRecipient(deathRecipient_);
        deathRecipient_ = nullptr;
    }
}

void CaptureOutput::OnCameraServerDied(pid_t pid)
{
    // LCOV_EXCL_START
    CameraServerDied(pid);
    UnregisterStreamBinderDied();
    // LCOV_EXCL_STOP
}

CaptureOutput::~CaptureOutput()
{
    UnregisterStreamBinderDied();
}

CaptureOutputType CaptureOutput::GetOutputType()
{
    return outputType_;
}

bool CaptureOutput::IsVideoProfileType()
{
    // LCOV_EXCL_START
#ifdef CAMERA_MOVIE_FILE
    return outputType_ == CAPTURE_OUTPUT_TYPE_VIDEO || outputType_ == CAPTURE_OUTPUT_TYPE_MOVIE_FILE ||
           outputType_ == CAPTURE_OUTPUT_TYPE_UNIFY_MOVIE_FILE;
#else
    return outputType_ == CAPTURE_OUTPUT_TYPE_VIDEO;
#endif
    // LCOV_EXCL_STOP
}

const char* CaptureOutput::GetOutputTypeString()
{
    // LCOV_EXCL_START
    return g_captureOutputTypeString[outputType_];
    // LCOV_EXCL_STOP
}

StreamType CaptureOutput::GetStreamType()
{
    return streamType_;
}

bool CaptureOutput::IsStreamCreated()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(streamMutex_);
    return stream_ != nullptr;
    // LCOV_EXCL_STOP
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

void CaptureOutput::SetDepthProfile(DepthProfile& depthProfile)
{
    std::lock_guard<std::mutex> lock(depthProfileMutex_);
    // LCOV_EXCL_START
    depthProfile_ = std::make_shared<DepthProfile>(depthProfile);
    // LCOV_EXCL_STOP
}

std::shared_ptr<DepthProfile> CaptureOutput::GetDepthProfile()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(depthProfileMutex_);
    return depthProfile_;
    // LCOV_EXCL_STOP
}

void CaptureOutput::ClearProfiles()
{
    // LCOV_EXCL_START
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
    // LCOV_EXCL_STOP
}

void CaptureOutput::AddTag(Tag tag)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(tagsMutex_);
    tags_.insert(tag);
    // LCOV_EXCL_STOP
}

void CaptureOutput::RemoveTag(Tag tag)
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> lock(tagsMutex_);
    tags_.erase(tag);
    // LCOV_EXCL_STOP
}

bool CaptureOutput::IsTagSetted(Tag tag)
{
    std::lock_guard<std::mutex> lock(tagsMutex_);
    return tags_.find(tag) != tags_.end();
}

bool CaptureOutput::IsHasEnableOfflinePhoto()
{
    // LCOV_EXCL_START
    return mIsHasEnableOfflinePhoto_;
    // LCOV_EXCL_STOP
}

#ifdef CAMERA_MOVIE_FILE
bool CaptureOutput::IsMultiStreamOutput()
{
    return outputType_ == CaptureOutputType::CAPTURE_OUTPUT_TYPE_UNIFY_MOVIE_FILE;
}
#endif

} // CameraStandard
} // OHOS
