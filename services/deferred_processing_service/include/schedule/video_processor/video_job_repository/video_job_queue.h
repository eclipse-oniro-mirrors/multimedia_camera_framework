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

#ifndef OHOS_CAMERA_DPS_VIDEO_JOB_QUEUE_H
#define OHOS_CAMERA_DPS_VIDEO_JOB_QUEUE_H

#include "deferred_video_job.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr uint32_t DEFAULT = 0;
class VideoJobQueue {
public:
    typedef std::function<bool(DeferredVideoJobPtr, DeferredVideoJobPtr)> Comparator;
    explicit VideoJobQueue(Comparator comp);
    ~VideoJobQueue();

    bool Contains(DeferredVideoJobPtr obj) const;
    DeferredVideoJobPtr Peek() const;
    void Push(DeferredVideoJobPtr obj);
    DeferredVideoJobPtr Pop();
    void Remove(DeferredVideoJobPtr obj);
    void Update(DeferredVideoJobPtr obj);
    std::vector<DeferredVideoJobPtr> GetAllElements() const;
    void Clear();

    inline bool IsEmpty()
    {
        return size_ == DEFAULT;
    }

    inline int32_t GetSize()
    {
        DP_DEBUG_LOG("entered, size is %{public}d", size_);
        return size_;
    }

private:
    void HeapInsert(uint32_t index);
    void Heapify(uint32_t index);
    void Swap(uint32_t x, uint32_t y);

    uint32_t size_ {0};
    Comparator comp_;
    std::vector<DeferredVideoJobPtr> heap_ {};
    std::unordered_map<DeferredVideoJobPtr, uint32_t> indexMap_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_JOB_QUEUE_H