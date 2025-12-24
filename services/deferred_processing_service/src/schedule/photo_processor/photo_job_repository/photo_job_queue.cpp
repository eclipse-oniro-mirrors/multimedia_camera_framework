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

#include "photo_job_queue.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
PhotoJobQueue::PhotoJobQueue(Comparator comp) : comp_(comp)
{
    DP_DEBUG_LOG("entered.");
}

PhotoJobQueue::~PhotoJobQueue()
{
    DP_INFO_LOG("entered.");
    comp_ = nullptr;
    Clear();
}

// LCOV_EXCL_START
bool PhotoJobQueue::Contains(DeferredPhotoJobPtr obj) const
{
    return indexMap_.find(obj) != indexMap_.end();
}
// LCOV_EXCL_STOP
DeferredPhotoJobPtr PhotoJobQueue::Peek()
{
    DP_CHECK_RETURN_RET(heap_.empty(), nullptr);
    return heap_.front();
}
// LCOV_EXCL_START
void PhotoJobQueue::Push(const DeferredPhotoJobPtr& obj)
{
    uint32_t index = heap_.size();
    heap_.push_back(obj);
    indexMap_[obj] = index;
    catchMap_.emplace(obj->GetImageId(), obj);
    HeapInsert(index);
}

DeferredPhotoJobPtr PhotoJobQueue::Pop()
{
    DP_CHECK_RETURN_RET(heap_.empty(), nullptr);

    DeferredPhotoJobPtr top = heap_.front();
    Swap(0, heap_.size() - 1);
    indexMap_.erase(top);
    catchMap_.erase(top->GetImageId());
    heap_.pop_back();
    Heapify(0);
    return top;
}

void PhotoJobQueue::Remove(const DeferredPhotoJobPtr& obj)
{
    auto it = indexMap_.find(obj);
    DP_CHECK_RETURN(it == indexMap_.end());

    uint32_t index = it->second;
    DeferredPhotoJobPtr replace = heap_.back();
    indexMap_.erase(obj);
    catchMap_.erase(obj->GetImageId());
    heap_.pop_back();
    // If the removed job was the last one, no need to update
    DP_CHECK_RETURN(obj == replace);

    heap_[index] = replace;
    indexMap_[replace] = index;
    Update(replace);
}
// LCOV_EXCL_STOP
void PhotoJobQueue::Update(const DeferredPhotoJobPtr& obj)
{
    DP_CHECK_RETURN(obj == nullptr);
    uint32_t index = indexMap_[obj];
    HeapInsert(index);
    Heapify(index);
}

void PhotoJobQueue::UpdateById(const std::string& id)
{
    Update(GetJobById(id));
}

void PhotoJobQueue::Clear()
{
    heap_.clear();
    indexMap_.clear();
    catchMap_.clear();
}

DeferredPhotoJobPtr PhotoJobQueue::GetJobById(const std::string& id)
{
    auto it = catchMap_.find(id);
    DP_CHECK_RETURN_RET(it == catchMap_.end(), nullptr);
    return it->second;
}

void PhotoJobQueue::HeapInsert(uint32_t index)
{
    while (index > 0 && comp_(heap_[index], heap_[(index - 1) >> 1])) {
        Swap(index, (index - 1) >> 1);
        index = (index - 1) >> 1;
    }
}
// LCOV_EXCL_START
void PhotoJobQueue::Heapify(uint32_t index)
{
    uint32_t left = (index << 1) + 1;
    auto size = heap_.size();
    while (left < size) {
        uint32_t best = (left + 1 < size && comp_(heap_[left + 1], heap_[left])) ? left + 1 : left;
        best = comp_(heap_[best], heap_[index]) ? best : index;
        if (best == index) {
            break;
        }
        Swap(best, index);
        index = best;
        left = (index << 1) + 1;
    }
}

void PhotoJobQueue::Swap(uint32_t x, uint32_t y)
{
    DP_CHECK_ERROR_RETURN_LOG(x >= heap_.size() || y >= heap_.size(), "Swap failed: index out of range.");

    std::swap(heap_[x], heap_[y]);
    auto itemx = indexMap_.find(heap_[x]);
    if (itemx != indexMap_.end()) {
        itemx->second = x;
    }
    auto itemy = indexMap_.find(heap_[y]);
    if (itemy != indexMap_.end()) {
        itemy->second = y;
    }
}
// LCOV_EXCL_STOP
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS