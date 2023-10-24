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

#include "camera_log.h"
#include "output/capture_output.h"

namespace OHOS {
namespace CameraStandard {
CaptureOutput::CaptureOutput(CaptureOutputType outputType, StreamType streamType,
    sptr<IStreamCommon> stream) : outputType_(outputType), streamType_(streamType), stream_(stream)
{
    session_ = nullptr;
    sptr<IRemoteObject> object = stream_->AsObject();
    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) CameraDeathRecipient(pid);
    CHECK_AND_RETURN_LOG(deathRecipient_ != nullptr, "failed to new CameraDeathRecipient.");

    deathRecipient_->SetNotifyCb(std::bind(&CaptureOutput::CameraServerDied, this, std::placeholders::_1));
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_ERR_LOG("failed to add deathRecipient");
        return;
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
    return stream_;
}

sptr<CaptureSession> CaptureOutput::GetSession()
{
    return session_.promote();
}

int32_t CaptureOutput::Release()
{
    stream_ = nullptr;
    session_ = nullptr;
    return 0;
}

void CaptureOutput::SetSession(sptr<CaptureSession> captureSession)
{
    session_ = captureSession;
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
} // CameraStandard
} // OHOS
