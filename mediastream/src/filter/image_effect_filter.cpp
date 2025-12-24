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

#include "image_effect_filter.h"

#include "camera_log.h"
#include "any.h"
#include "image_effect_proxy.h"
#include "media_core.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
ImageEffectFilter::ImageEffectFilter(std::string name, CFilterType type)
    : CFilter(name, type)
{
    MEDIA_INFO_LOG("entered.");
}

ImageEffectFilter::~ImageEffectFilter()
{
    MEDIA_INFO_LOG("entered.");
}

void ImageEffectFilter::OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
{
    MEDIA_ERR_LOG("ImageEffectFilter error happened. ErrorType: %{public}d, errorCode: %{public}d",
        static_cast<int32_t>(errorType), errorCode);
    if (eventReceiver_ != nullptr) {
        eventReceiver_->OnEvent({"image_effect_filter", FilterEventType::EVENT_ERROR, MSERR_VID_ENC_FAILED});
    }
}

void ImageEffectFilter::Init(const std::shared_ptr<CEventReceiver> &receiver,
    const std::shared_ptr<CFilterCallback> &callback)
{
    MEDIA_INFO_LOG("Init");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
    auto imageEffectProxy = imageEffectProxy_.Get();
    if (imageEffectProxy == nullptr) {
        imageEffectProxy = ImageEffectProxy::CreateImageEffectProxy();
        imageEffectProxy_.Set(imageEffectProxy);
        if (imageEffectProxy && imageEffectProxy->Init() == MEDIA_OK) {
        } else if (eventReceiver_ != nullptr) {
            MEDIA_INFO_LOG("Init mediaCodec fail");
            eventReceiver_->OnEvent({"image_effect_filter", FilterEventType::EVENT_ERROR, MSERR_UNKNOWN});
        }
        surface_ = nullptr;
    }
}

Status ImageEffectFilter::SetImageEffect(const std::string& filter, const std::string& filterParam)
{
    MEDIA_INFO_LOG("SetWatermark");
    auto imageEffectProxy = imageEffectProxy_.Get();
    CHECK_RETURN_RET_ELOG(imageEffectProxy == nullptr, Status::ERROR_UNKNOWN, "imageEffectProxy is nullptr");
    return imageEffectProxy->SetImageEffect(filter, filterParam) == MEDIA_OK ? Status::OK : Status::ERROR_UNKNOWN;
}

sptr<Surface> ImageEffectFilter::GetInputSurface()
{
    MEDIA_INFO_LOG("GetInputSurface");
    CHECK_RETURN_RET(surface_, surface_);
    auto imageEffectProxy = imageEffectProxy_.Get();
    if (imageEffectProxy != nullptr) {
        surface_ = imageEffectProxy->GetInputSurface();
    }
    return surface_;
}

Status ImageEffectFilter::DoPrepare()
{
    CHECK_RETURN_RET(filterCallback_ == nullptr, Status::ERROR_NULL_POINTER);
    MEDIA_INFO_LOG("Prepare");
    filterCallback_->OnCallback(shared_from_this(), CFilterCallBackCommand::NEXT_FILTER_NEEDED,
        CStreamType::RAW_VIDEO);
    return Status::OK;
}

Status ImageEffectFilter::DoStart()
{
    MEDIA_INFO_LOG("Start");
    auto imageEffectProxy = imageEffectProxy_.Get();
    CHECK_RETURN_RET(imageEffectProxy == nullptr, Status::ERROR_UNKNOWN);
    return imageEffectProxy->Start() == MEDIA_OK ? Status::OK : Status::ERROR_UNKNOWN;
}

Status ImageEffectFilter::DoPause()
{
    MEDIA_INFO_LOG("Pause");
    return DoStop();
}

Status ImageEffectFilter::DoResume()
{
    MEDIA_INFO_LOG("Resume");
    return DoStart();
}

Status ImageEffectFilter::DoStop()
{
    MEDIA_INFO_LOG("Stop enter");
    auto imageEffectProxy = imageEffectProxy_.Get();
    CHECK_RETURN_RET(imageEffectProxy == nullptr, Status::OK);

    auto thisWptr = weak_from_this();
    std::thread asyncThread([thisWptr]() {
        MEDIA_DEBUG_LOG("ImageEffectFilter::DoStop thread is called");
        auto thisPtr = thisWptr.lock();
        if (thisPtr) {
            MEDIA_DEBUG_LOG("ImageEffectFilter::DoStop wait is called");
            std::unique_lock<std::mutex> lock(thisPtr->stopMutex_);
            std::cv_status waitStatus = thisPtr->stopCondition_.wait_for(lock, std::chrono::milliseconds(1000));
            // Waiting timeout with no video frame received
            CHECK_PRINT_ELOG(waitStatus == std::cv_status::timeout,
                "ImageEffectFilter::DoStop wait timeout with no user meta received");
            MEDIA_DEBUG_LOG("ImageEffectFilter::DoStop notified or timeout");
        }
        if (thisPtr) {
            MEDIA_DEBUG_LOG("ImageEffectFilter::DoStop start stop imageEffectProxy_");
            auto imageEffectProxy = thisPtr->imageEffectProxy_.Get();
            CHECK_EXECUTE(imageEffectProxy, imageEffectProxy->Stop());
        }
    });
    asyncThread.detach();

    return Status::OK;
}

Status ImageEffectFilter::DoRelease()
{
    MEDIA_INFO_LOG("Release");
    auto imageEffectProxy = imageEffectProxy_.Get();
    CHECK_RETURN_RET(imageEffectProxy == nullptr, Status::OK);
    return imageEffectProxy->Reset() == MEDIA_OK ? Status::OK : Status::ERROR_UNKNOWN;
}

Status ImageEffectFilter::LinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("LinkNext");
    nextFilter_ = nextFilter;
    nextCFiltersMap_[outType].push_back(nextFilter_);
    std::shared_ptr<CFilterLinkCallback> filterLinkCallback =
        std::make_shared<ImageEffectFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, nullptr, filterLinkCallback);
    return Status::OK;
}

Status ImageEffectFilter::UpdateNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UpdateNext");
    return Status::OK;
}

Status ImageEffectFilter::UnLinkNext(const std::shared_ptr<CFilter> &nextFilter, CStreamType outType)
{
    MEDIA_INFO_LOG("UnLinkNext");
    return Status::OK;
}

CFilterType ImageEffectFilter::GetFilterType()
{
    return filterType_;
}

Status ImageEffectFilter::OnLinked(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnLinked");
    onLinkedResultCallback_ = callback;
    return Status::OK;
}

Status ImageEffectFilter::OnUpdated(CStreamType inType, const std::shared_ptr<Meta> &meta,
    const std::shared_ptr<CFilterLinkCallback> &callback)
{
    MEDIA_INFO_LOG("OnUpdated");
    return Status::OK;
}

Status ImageEffectFilter::OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback)
{
    MEDIA_INFO_LOG("OnUnLinked");
    return Status::OK;
}

void ImageEffectFilter::OnLinkedResult(const sptr<AVBufferQueueProducer> &outputBufferQueue,
    std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnLinkedResult...");
}

void ImageEffectFilter::OnLinkedResult(sptr<Surface> surface)
{
    MEDIA_INFO_LOG("OnLinkedResult");
    auto imageEffectProxy = imageEffectProxy_.Get();
    CHECK_RETURN(imageEffectProxy == nullptr);
    imageEffectProxy->SetOutputSurface(surface);
}

void ImageEffectFilter::OnUpdatedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUpdatedResult");
    // stop image filter after encoder stopped
    std::unique_lock<std::mutex> lock(stopMutex_);
    stopCondition_.notify_all();
}

void ImageEffectFilter::OnUnlinkedResult(std::shared_ptr<Meta> &meta)
{
    MEDIA_INFO_LOG("OnUnlinkedResult");
}

void ImageEffectFilter::SetCallingInfo(int32_t appUid, int32_t appPid,
    const std::string &bundleName, uint64_t instanceId)
{
    appUid_ = appUid;
    appPid_ = appPid;
    bundleName_ = bundleName;
    instanceId_ = instanceId;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP