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

#include "video_job_queue.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
VideoJobQueue::VideoJobQueue(Comparator comp)
    : comp_(comp)
{
    DP_DEBUG_LOG("entered.");
}

VideoJobQueue::~VideoJobQueue()
{
    DP_DEBUG_LOG("entered.");
    comp_ = nullptr;
}

bool VideoJobQueue::Contains(DeferredVideoJobPtr obj) const
{
    return indexMap_.find(obj) != indexMap_.end();
}

DeferredVideoJobPtr VideoJobQueue::Peek() const
{
    DP_CHECK_RETURN_RET(size_ == DEFAULT, nullptr);
    return heap_.front();
}

void VideoJobQueue::Push(DeferredVideoJobPtr obj)
{
    heap_.push_back(obj);
    indexMap_[obj] = size_;
    HeapInsert(size_++);
}

DeferredVideoJobPtr VideoJobQueue::Pop()
{
    DP_CHECK_RETURN_RET(size_ == DEFAULT, nullptr);
    DeferredVideoJobPtr ans = heap_.front();
    Swap(DEFAULT, size_ - 1);
    indexMap_.erase(ans);
    heap_.pop_back();
    --size_;
    Heapify(DEFAULT);
    return ans;
}

void VideoJobQueue::Remove(DeferredVideoJobPtr obj)
{
    auto it = indexMap_.find(obj);
    DP_CHECK_RETURN(it == indexMap_.end());

    uint32_t index = it->second;
    DeferredVideoJobPtr replace = heap_.back();
    indexMap_.erase(obj);
    heap_.pop_back();
    --size_;
    if (obj == replace) {
        return;
    }
    heap_[index] = replace;
    indexMap_[replace] = index;
    Update(replace);
}

void VideoJobQueue::Update(DeferredVideoJobPtr obj)
{
    uint32_t index = indexMap_[obj];
    HeapInsert(index);
    Heapify(index);
}

std::vector<DeferredVideoJobPtr> VideoJobQueue::GetAllElements() const
{
    return heap_;
}

void VideoJobQueue::HeapInsert(uint32_t index)
{
    while (index > 0 && comp_(heap_[index], heap_[(index - 1) >> 1])) {
        Swap(index, (index - 1) >> 1);
        index = (index - 1) >> 1;
    }
}

void VideoJobQueue::Heapify(uint32_t index)
{
    uint32_t left = (index << 1) + 1;
    while (left < size_) {
        uint32_t best = (left + 1 < size_ && comp_(heap_[left + 1], heap_[left])) ? left + 1 : left;
        best = comp_(heap_[best], heap_[index]) ? best : index;
        if (best == index) {
            break;
        }
        Swap(best, index);
        index = best;
        left = (index << 1) + 1;
    }
}

void VideoJobQueue::Swap(uint32_t x, uint32_t y)
{
    std::swap(heap_[x], heap_[y]);
    DP_CHECK_ERROR_RETURN_LOG(x < DEFAULT || x >= size_ || y < DEFAULT || y >= size_, "swap failed.");
    indexMap_[heap_[x]] = x;
    indexMap_[heap_[y]] = y;
}

void VideoJobQueue::Clear()
{
    heap_.clear();
    indexMap_.clear();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS