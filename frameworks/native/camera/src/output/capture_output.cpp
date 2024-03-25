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

#include "camera_log.h"
#include "capture_session.h"

namespace OHOS {
namespace CameraStandard {
static const char* g_captureOutputTypeString[CAPTURE_OUTPUT_TYPE_MAX] = {"Preview", "Photo", "Video", "Metadata"};

CaptureOutput::CaptureOutput(CaptureOutputType outputType, StreamType streamType,
    sptr<IStreamCommon> stream) : outputType_(outputType), streamType_(streamType), stream_(stream)
{
    sptr<IRemoteObject> object = stream_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) CameraDeathRecipient(pid);
    CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb(std::bind(&CaptureOutput::CameraServerDied, this, std::placeholders::_1));
    if (object) {
        bool result = object->AddDeathRecipient(deathRecipient_);
        if (!result) {
            MEDIA_ERR_LOG("failed to add deathRecipient");
            return;
        }
    }
}

CaptureOutput::~CaptureOutput()
{
    if (GetStream() != nullptr) {
        (void)GetStream()->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
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

sptr<IStreamCommon> CaptureOutput::GetStream()
{
    std::lock_guard<std::mutex> lock(streamMutex_);
    return stream_;
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
        std::lock_guard<std::mutex> lock(streamMutex_);
        stream_ = nullptr;
    }
    SetSession(nullptr);
    return 0;
}

int32_t CaptureOutput::SetPhotoProfile(Profile &profile)
{
    photoProfile_ = profile;
    return 0;
}

Profile CaptureOutput::GetPhotoProfile()
{
    return photoProfile_;
}

int32_t CaptureOutput::SetPreviewProfile(Profile &profile)
{
    previewProfile_ = profile;
    return 0;
}

Profile CaptureOutput::GetPreviewProfile()
{
    return previewProfile_;
}

int32_t CaptureOutput::SetVideoProfile(VideoProfile &videoProfile)
{
    videoProfile_ = videoProfile;
    return 0;
}

VideoProfile CaptureOutput::GetVideoProfile()
{
    return videoProfile_;
}
} // CameraStandard
} // OHOS
