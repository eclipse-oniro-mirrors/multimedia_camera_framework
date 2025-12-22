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

#ifndef OHOS_CAMERA_DPS_PHOTO_JOB_QUEUE_H
#define OHOS_CAMERA_DPS_PHOTO_JOB_QUEUE_H

#include "deferred_photo_job.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using Comparator = std::function<bool(const DeferredPhotoJobPtr&, const DeferredPhotoJobPtr&)>;

class PhotoJobQueue {
public:
    explicit PhotoJobQueue(Comparator comp);
    ~PhotoJobQueue();

    bool Contains(DeferredPhotoJobPtr obj) const;
    DeferredPhotoJobPtr Pop();
    DeferredPhotoJobPtr Peek();
    void Push(const DeferredPhotoJobPtr& obj);
    void Remove(const DeferredPhotoJobPtr& obj);
    void Update(const DeferredPhotoJobPtr& obj);
    void UpdateById(const std::string& id);
    void Clear();
    DeferredPhotoJobPtr GetJobById(const std::string& id);

    inline std::vector<DeferredPhotoJobPtr> GetAllElements() const
    {
        return heap_;
    }

    inline bool IsEmpty() const
    {
        return heap_.empty();
    }

    inline int32_t GetSize() const
    {
        return heap_.size();
    }

private:
    void HeapInsert(uint32_t index) ;
    void Heapify(uint32_t index);
    void Swap(uint32_t x, uint32_t y);

    std::vector<DeferredPhotoJobPtr> heap_ {};
    std::unordered_map<DeferredPhotoJobPtr, uint32_t> indexMap_ {};
    std::unordered_map<std::string, DeferredPhotoJobPtr> catchMap_ {};
    Comparator comp_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_JOB_QUEUE_H