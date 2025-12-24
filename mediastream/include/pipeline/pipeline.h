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

#ifndef OHOS_CAMERA_PIPELINE_H
#define OHOS_CAMERA_PIPELINE_H

#include "cfilter.h"

namespace OHOS {
namespace CameraStandard {
class Pipeline : public CEventReceiver {
public:
    Pipeline();
    ~Pipeline();

    static int32_t GetNextPipelineId();
    void Init(const std::shared_ptr<CEventReceiver>& receiver,
        const std::shared_ptr<CFilterCallback>& callback, const std::string& groupId);
    Status Prepare();
    Status Start();
    Status Pause();
    Status Resume();
    Status Stop();
    Status Flush();
    Status Release();
    Status Preroll(bool render);
    Status SetPlayRange(int64_t start, int64_t end);
    Status AddHeadFilters(std::vector<std::shared_ptr<CFilter>> filters);
    Status RemoveHeadFilter(const std::shared_ptr<CFilter>& filter);
    Status LinkFilters(const std::shared_ptr<CFilter>& preFilter,
        const std::vector<std::shared_ptr<CFilter>>& filters, CStreamType type, bool needTurbo = false);
    Status UpdateFilters(const std::shared_ptr<CFilter>& preFilter,
        const std::vector<std::shared_ptr<CFilter>>& filters, CStreamType type);
    Status UnLinkFilters(const std::shared_ptr<CFilter>& preFilter,
        const std::vector<std::shared_ptr<CFilter>>& filters, CStreamType type);
    void OnEvent(const Event& event) override;

    inline void SubmitJobOnce(std::function<void()> job)
    {
        job();
    }
    Status SetStreamStarted(bool isStreamStarted);

private:
    std::string groupId_;
    std::mutex mutex_ {};
    std::vector<std::shared_ptr<CFilter>> filters_ {};
    std::shared_ptr<CEventReceiver> eventReceiver_ {nullptr};
    std::shared_ptr<CFilterCallback> filterCallback_ {nullptr};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_PIPELINE_H
