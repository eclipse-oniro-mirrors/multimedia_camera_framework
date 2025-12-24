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

#ifndef IMAGE_EFFECT_FILTER_H
#define IMAGE_EFFECT_FILTER_H

#include "cfilter.h"
#include "avcodec_common.h"
#include "image_effect_proxy.h"
#include "sp_holder.h"

namespace OHOS {
namespace CameraStandard {
class ImageEffectFilter : public CFilter, public std::enable_shared_from_this<ImageEffectFilter> {
public:
    explicit ImageEffectFilter(std::string name, CFilterType type);
    ~ImageEffectFilter() override;

    void Init(const std::shared_ptr<CEventReceiver>& receiver,
        const std::shared_ptr<CFilterCallback>& callback) override;
    sptr<Surface> GetInputSurface() override;
    Status DoPrepare() override;
    Status DoStart() override;
    Status DoPause() override;
    Status DoResume() override;
    Status DoStop() override;
    Status DoRelease() override;
    Status SetImageEffect(const std::string& filter, const std::string& filterParam);
    Status LinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UpdateNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    Status UnLinkNext(const std::shared_ptr<CFilter>& nextFilter, CStreamType outType) override;
    CFilterType GetFilterType();
    void OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta);
    void OnLinkedResult(sptr<Surface> surface);
    void OnUpdatedResult(std::shared_ptr<Meta>& meta);
    void OnUnlinkedResult(std::shared_ptr<Meta>& meta);
    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string& bundleName, uint64_t instanceId);
protected:
    Status OnLinked(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUpdated(CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback) override;
    Status OnUnLinked(CStreamType inType, const std::shared_ptr<CFilterLinkCallback>& callback) override;
private:
    SpHolder<std::shared_ptr<ImageEffectIntf>> imageEffectProxy_;
    CFilterType filterType_ {CFilterType::IMAGE_EFFECT};
    std::shared_ptr<CEventReceiver> eventReceiver_ {nullptr};
    std::shared_ptr<CFilterCallback> filterCallback_ {nullptr};
    sptr<Surface> surface_ {nullptr};
    std::shared_ptr<CFilter> nextFilter_ {nullptr};
    std::shared_ptr<CFilterLinkCallback> onLinkedResultCallback_ {nullptr};
    
    std::string bundleName_;
    uint64_t instanceId_ {0};
    int32_t appUid_ {0};
    int32_t appPid_ {0};

    std::condition_variable stopCondition_;
    std::mutex stopMutex_;
};

class ImageEffectFilterLinkCallback : public CFilterLinkCallback {
public:
    explicit ImageEffectFilterLinkCallback(std::shared_ptr<ImageEffectFilter> imageEffectFilter)
        : imageEffectFilter_(std::move(imageEffectFilter))
    {
    }
    void OnLinkedResult(const sptr<AVBufferQueueProducer> &queue, std::shared_ptr<Meta> &meta) override
    {
        if (auto imageEffectFilter = imageEffectFilter_.lock()) {
            imageEffectFilter->OnLinkedResult(queue, meta);
        }
    }
    void OnUnlinkedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto imageEffectFilter = imageEffectFilter_.lock()) {
            imageEffectFilter->OnUnlinkedResult(meta);
        }
    }
    void OnUpdatedResult(std::shared_ptr<Meta> &meta) override
    {
        if (auto imageEffectFilter = imageEffectFilter_.lock()) {
            imageEffectFilter->OnUpdatedResult(meta);
        }
    }
    void OnLinkedResult(sptr<Surface> surface) override
    {
        if (auto imageEffectFilter = imageEffectFilter_.lock()) {
            imageEffectFilter->OnLinkedResult(surface);
        }
    }
private:
    std::weak_ptr<ImageEffectFilter> imageEffectFilter_;
};
}
}
#endif
