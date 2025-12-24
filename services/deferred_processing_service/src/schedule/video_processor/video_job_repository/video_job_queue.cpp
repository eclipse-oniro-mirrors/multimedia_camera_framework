/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "dp_log.h"

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
    DP_INFO_LOG("entered.");
    comp_ = nullptr;
    Clear();
}

bool VideoJobQueue::Contains(const DeferredVideoJobPtr& obj) const
{
    return indexMap_.find(obj) != indexMap_.end();
}

DeferredVideoJobPtr VideoJobQueue::Peek() const
{
    DP_CHECK_RETURN_RET(heap_.empty(), nullptr);
    // LCOV_EXCL_START
    return heap_.front();
    // LCOV_EXCL_STOP
}

void VideoJobQueue::Push(const DeferredVideoJobPtr& obj)
{
    uint32_t index = heap_.size();
    heap_.push_back(obj);
    indexMap_[obj] = index;
    catchMap_.emplace(obj->GetVideoId(), obj);
    HeapInsert(index);
}

DeferredVideoJobPtr VideoJobQueue::Pop()
{
    DP_CHECK_RETURN_RET(heap_.empty(), nullptr);
    DeferredVideoJobPtr top = heap_.front();
    Swap(0, heap_.size() - 1);
    indexMap_.erase(top);
    catchMap_.erase(top->GetVideoId());
    heap_.pop_back();
    Heapify(0);
    return top;
}

void VideoJobQueue::Remove(const DeferredVideoJobPtr& obj)
{
    auto it = indexMap_.find(obj);
    DP_CHECK_RETURN(it == indexMap_.end());
    // LCOV_EXCL_START
    uint32_t index = it->second;
    DeferredVideoJobPtr replace = heap_.back();
    indexMap_.erase(obj);
    catchMap_.erase(obj->GetVideoId());
    heap_.pop_back();
    DP_CHECK_RETURN(obj == replace);

    heap_[index] = replace;
    indexMap_[replace] = index;
    Update(replace);
    // LCOV_EXCL_STOP
}

void VideoJobQueue::Update(const DeferredVideoJobPtr& obj)
{
    // LCOV_EXCL_START
    DP_CHECK_RETURN(obj == nullptr);
    uint32_t index = indexMap_[obj];
    HeapInsert(index);
    Heapify(index);
    // LCOV_EXCL_STOP
}

void VideoJobQueue::HeapInsert(uint32_t index)
{
    while (index > 0 && comp_(heap_[index], heap_[(index - 1) >> 1])) {
        // LCOV_EXCL_START
        Swap(index, (index - 1) >> 1);
        index = (index - 1) >> 1;
        // LCOV_EXCL_STOP
    }
}

void VideoJobQueue::Heapify(uint32_t index)
{
    uint32_t left = (index << 1) + 1;
    auto size = heap_.size();
    while (left < size) {
        // LCOV_EXCL_START
        uint32_t best = (left + 1 < size && comp_(heap_[left + 1], heap_[left])) ? left + 1 : left;
        best = comp_(heap_[best], heap_[index]) ? best : index;
        if (best == index) {
            break;
        }
        Swap(best, index);
        index = best;
        left = (index << 1) + 1;
        // LCOV_EXCL_STOP
    }
}

void VideoJobQueue::Swap(uint32_t x, uint32_t y)
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

void VideoJobQueue::Clear()
{
    heap_.clear();
    indexMap_.clear();
    catchMap_.clear();
}

DeferredVideoJobPtr VideoJobQueue::GetJobById(const std::string& id)
{
    // LCOV_EXCL_START
    auto it = catchMap_.find(id);
    DP_CHECK_RETURN_RET(it == catchMap_.end(), nullptr);
    return it->second;
    // LCOV_EXCL_STOP
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS