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
#ifndef OHOS_CAMERA_DPS_MEDIA_PROGRESS_NOTIFIER_H
#define OHOS_CAMERA_DPS_MEDIA_PROGRESS_NOTIFIER_H

#include <cstdint>
#include <memory>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr int64_t NOTIFY_PROCESS_TIME_TAMP = 99000;
class ProgressCallback {
public:
    virtual ~ProgressCallback() = default;
    virtual void OnProgressUpdate(float progress) = 0;
};

class MediaProgressNotifier {
public:
    explicit MediaProgressNotifier(int64_t notifyInterval = NOTIFY_PROCESS_TIME_TAMP);
    ~MediaProgressNotifier() = default;

    void CheckNotify(int64_t currentPts);
    void SetTotalDuration(int64_t total);
    void SetNotifyCallback(const std::weak_ptr<ProgressCallback>& callback);

    inline bool isCompletedProcess() const {
        return isCompleted_;
    }

private:
    void SendNotification(int64_t currentPts) const;
    
    int64_t total_ {0};
    bool isCompleted_ {false};
    const int64_t notifyInterval_;
    int64_t nextNotifyPts_;
    std::weak_ptr<ProgressCallback> notifyCallback_;
};

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_MEDIA_PROGRESS_NOTIFIER_H