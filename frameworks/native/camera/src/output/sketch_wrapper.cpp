/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "sketch_wrapper.h"

#include "camera_log.h"
#include "camera_util.h"
#include "image_source.h"

namespace OHOS {
namespace CameraStandard {
namespace {
std::shared_ptr<OHOS::Media::PixelMap> CreatePixelMapFromBuffer(const OHOS::sptr<OHOS::SurfaceBuffer>& buffer)
{
    Media::SourceOptions srcOpt;
    srcOpt = { .pixelFormat = Media::PixelFormat::NV21,
        .size = { .width = buffer->GetWidth(), .height = buffer->GetHeight() } };
    uint32_t errorCode = Media::SUCCESS;
    auto imageSource = Media::ImageSource::CreateImageSource(
        static_cast<uint8_t*>(buffer->GetVirAddr()), buffer->GetSize(), srcOpt, errorCode);
    if (errorCode != Media::SUCCESS || imageSource == nullptr) {
        MEDIA_ERR_LOG("CreatePixelMapFromBuffer CreateImageSource fail");
        return nullptr;
    }
    Media::DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = Media::PixelFormat::RGBA_8888;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != Media::SUCCESS || pixelMap == nullptr) {
        MEDIA_ERR_LOG("CreatePixelMapFromBuffer CreatePixelMap fail");
        return nullptr;
    }
    return pixelMap;
}
} // namespace

void SketchWrapper::SketchBufferAvaliableListener::OnSurfaceBufferAvaliable()
{
    MEDIA_DEBUG_LOG("Enter Into SketchWrapper OnSurfaceBufferAvaliable");
    auto sketchWrapper = sketchWrapper_.lock();
    if (sketchWrapper == nullptr) {
        MEDIA_WARNING_LOG("sketchWrapper is null");
        return;
    }

    if (sketchWrapper->sketchImgReceiver_ == nullptr) {
        MEDIA_WARNING_LOG("sketchWrapper sketchImgReceiver_ is null");
        return;
    }

    auto buffer = sketchWrapper->sketchImgReceiver_->ReadNextImage();
    auto appCallback = sketchWrapper->holder_->GetApplicationCallback();
    if (appCallback == nullptr) {
        sketchWrapper->sketchImgReceiver_->ReleaseBuffer(buffer);
        MEDIA_ERR_LOG("OnSurfaceBufferAvaliable appCallback is null");
        return;
    }

    auto session = sketchWrapper->holder_->GetSession();
    float referenceFovValue = -1.0f;
    float sketchEnableRatio = -1.0f;
    if (session != nullptr) {
        int32_t currentMode = session->GetMode();
        referenceFovValue = sketchWrapper->holder_->GetSketchReferenceFovRatio(currentMode);
        if (referenceFovValue > 0) {
            sketchEnableRatio = sketchWrapper->holder_->GetSketchEnableRatio(currentMode);
        }
    }
    if (referenceFovValue <= 0 || sketchEnableRatio <= 0) {
        sketchWrapper->sketchImgReceiver_->ReleaseBuffer(buffer);
        SketchData sketchData { .ratio = referenceFovValue, .pixelMap = nullptr };
        appCallback->OnSketchAvailable(sketchData);
        return;
    }

    MEDIA_DEBUG_LOG("sketch Width:%{public}d, sketch height: %{public}d, bufSize: %{public}d", buffer->GetWidth(),
        buffer->GetHeight(), buffer->GetSize());

    auto pixelMap = CreatePixelMapFromBuffer(buffer);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("OnSurfaceBufferAvaliable CreatePixelMap fail");
        sketchWrapper->sketchImgReceiver_->ReleaseBuffer(buffer);
        return;
    }

    SketchData sketchData { .ratio = referenceFovValue, .pixelMap = std::move(pixelMap) };
    appCallback->OnSketchAvailable(sketchData);
    sketchWrapper->sketchImgReceiver_->ReleaseBuffer(buffer);
}

SketchWrapper::SketchWrapper(PreviewOutput* holder) : holder_(holder) {}

int32_t SketchWrapper::Init(std::shared_ptr<SketchBufferAvaliableListener>& listener, const Size size)
{
    sketchImgReceiver_ = Media::ImageReceiver::CreateImageReceiver(
        size.width, size.height, static_cast<int32_t>(Media::ImageFormat::YUV420_888), 1);
    sptr<Surface> surface = sketchImgReceiver_->GetReceiverSurface();
    sketchSurfaceBufferAvaliableListener_ = listener;
    sketchImgReceiver_->RegisterBufferAvaliableListener(sketchSurfaceBufferAvaliableListener_);
    sptr<IStreamCommon> hostStream = holder_->GetStream();
    IStreamRepeat* repeatStream = static_cast<IStreamRepeat*>(hostStream.GetRefPtr());
    return repeatStream->ForkSketchStreamRepeat(surface->GetProducer(), size.width, size.height, sketchStream_);
}

SketchWrapper::~SketchWrapper()
{
    if (sketchStream_ != nullptr) {
        sketchStream_->Release();
    }
    if (sketchImgReceiver_ != nullptr) {
        sketchImgReceiver_->RegisterBufferAvaliableListener(nullptr);
    }
}

int32_t SketchWrapper::SketchWrapper::StartSketchStream()
{
    if (sketchStream_ != nullptr) {
        MEDIA_INFO_LOG("Enter Into SketchWrapper::SketchWrapper::StartSketchStream");
        holder_->UpdateSketchStaticInfo();
        return sketchStream_->Start();
    }
    return CAMERA_UNKNOWN_ERROR;
}

int32_t SketchWrapper::SketchWrapper::StopSketchStream()
{
    if (sketchStream_ != nullptr) {
        MEDIA_INFO_LOG("Enter Into SketchWrapper::SketchWrapper::StopSketchStream");
        return sketchStream_->Stop();
    }
    return CAMERA_UNKNOWN_ERROR;
}
} // namespace CameraStandard
} // namespace OHOS