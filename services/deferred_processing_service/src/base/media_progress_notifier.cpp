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

#include "media_progress_notifier.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
MediaProgressNotifier::MediaProgressNotifier(int64_t notifyInterval)
    : notifyInterval_(notifyInterval), nextNotifyPts_(notifyInterval)
{
    DP_DEBUG_LOG("entered.");
}

void MediaProgressNotifier::CheckNotify(int64_t currentPts) {
    DP_CHECK_EXECUTE(isCompleted_, {
        SendNotification(total_);
        return;
    });
    DP_CHECK_RETURN(currentPts < nextNotifyPts_);

    SendNotification(currentPts);
    nextNotifyPts_ += notifyInterval_;
    DP_CHECK_EXECUTE(nextNotifyPts_ >= total_, isCompleted_ = true);
}

void MediaProgressNotifier::SendNotification(int64_t currentPts) const {
    DP_CHECK_RETURN(total_ == 0);
    float progress = static_cast<float>(currentPts) / total_;
    auto callback = notifyCallback_.lock();
    DP_CHECK_EXECUTE(callback, callback->OnProgressUpdate(progress));
}

void MediaProgressNotifier::SetTotalDuration(int64_t total)
{
    total_ = total;
}

void MediaProgressNotifier::SetNotifyCallback(const std::weak_ptr<ProgressCallback>& callback)
{
    notifyCallback_ = callback;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS