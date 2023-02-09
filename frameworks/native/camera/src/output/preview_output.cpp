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

#include "output/preview_output.h"
#include "camera_util.h"
#include "hstream_repeat_callback_stub.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
PreviewOutput::PreviewOutput(sptr<IStreamRepeat> &streamRepeat)
    : CaptureOutput(CAPTURE_OUTPUT_TYPE_PREVIEW, StreamType::REPEAT, streamRepeat) {
}

int32_t PreviewOutput::Release()
{
    int32_t errCode = static_cast<IStreamRepeat *>(GetStream().GetRefPtr())->Release();
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("Failed to release PreviewOutput!, errCode: %{public}d", errCode);
    }
    CaptureOutput::Release();
    return ServiceToCameraError(errCode);
}

class HStreamRepeatCallbackImpl : public HStreamRepeatCallbackStub {
public:
    sptr<PreviewOutput> previewOutput_ = nullptr;
    HStreamRepeatCallbackImpl() : previewOutput_(nullptr) {
    }

    explicit HStreamRepeatCallbackImpl(const sptr<PreviewOutput>& previewOutput) : previewOutput_(previewOutput) {
    }

    ~HStreamRepeatCallbackImpl()
    {
        previewOutput_ = nullptr;
    }

    int32_t OnFrameStarted() override
    {
        CAMERA_SYNC_TRACE;
        if (previewOutput_ != nullptr && previewOutput_->GetApplicationCallback() != nullptr) {
            previewOutput_->GetApplicationCallback()->OnFrameStarted();
        } else {
            MEDIA_INFO_LOG("Discarding HStreamRepeatCallbackImpl::OnFrameStarted callback in preview");
        }
        return CAMERA_OK;
    }

    int32_t OnFrameEnded(int32_t frameCount) override
    {
        CAMERA_SYNC_TRACE;
        if (previewOutput_ != nullptr && previewOutput_->GetApplicationCallback() != nullptr) {
            previewOutput_->GetApplicationCallback()->OnFrameEnded(frameCount);
        } else {
            MEDIA_INFO_LOG("Discarding HStreamRepeatCallbackImpl::OnFrameEnded callback in preview");
        }
        return CAMERA_OK;
    }

    int32_t OnFrameError(int32_t errorCode) override
    {
        if (previewOutput_ != nullptr && previewOutput_->GetApplicationCallback() != nullptr) {
            previewOutput_->GetApplicationCallback()->OnError(errorCode);
        } else {
            MEDIA_INFO_LOG("Discarding HStreamRepeatCallbackImpl::OnFrameError callback in preview");
        }
        return CAMERA_OK;
    }
};

void PreviewOutput::AddDeferredSurface(sptr<Surface> surface)
{
    if (surface == nullptr) {
        MEDIA_ERR_LOG("PreviewOutput::AddDeferredSurface surface is null");
        return;
    }
    static_cast<IStreamRepeat *>(GetStream().GetRefPtr())->AddDeferredSurface(surface->GetProducer());
}

int32_t PreviewOutput::Start()
{
    CaptureSession* captureSession = GetSession();
    if (captureSession == nullptr || !captureSession->IsSessionCommited()) {
        MEDIA_ERR_LOG("PreviewOutput Failed to Start!, session not config");
        return CameraErrorCode::SESSION_NOT_CONFIG;
    }
    int32_t errCode = static_cast<IStreamRepeat *>(GetStream().GetRefPtr())->Start();
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("PreviewOutput Failed to Start!, errCode: %{public}d", errCode);
    }
    return ServiceToCameraError(errCode);
}

int32_t PreviewOutput::Stop()
{
    int32_t errCode = static_cast<IStreamRepeat *>(GetStream().GetRefPtr())->Stop();
    if (errCode != CAMERA_OK) {
        MEDIA_ERR_LOG("PreviewOutput Failed to Stop!, errCode: %{public}d", errCode);
    }
    return ServiceToCameraError(errCode);
}

void PreviewOutput::SetCallback(std::shared_ptr<PreviewStateCallback> callback)
{
    int32_t errorCode = CAMERA_OK;

    appCallback_ = callback;
    if (appCallback_ != nullptr) {
        if (svcCallback_ == nullptr) {
            svcCallback_ = new(std::nothrow) HStreamRepeatCallbackImpl(this);
            if (svcCallback_ == nullptr) {
                MEDIA_ERR_LOG("PreviewOutput::SetCallback: new HStreamRepeatCallbackImpl Failed to register callback");
                appCallback_ = nullptr;
                return;
            }
        }
        errorCode = static_cast<IStreamRepeat *>(GetStream().GetRefPtr())->SetCallback(svcCallback_);
        if (errorCode != CAMERA_OK) {
            MEDIA_ERR_LOG("PreviewOutput::SetCallback: Failed to register callback, errorCode: %{public}d", errorCode);
            svcCallback_ = nullptr;
            appCallback_ = nullptr;
        }
    }
    return;
}

std::shared_ptr<PreviewStateCallback> PreviewOutput::GetApplicationCallback()
{
    return appCallback_;
}
} // CameraStandard
} // OHOS

