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

#ifndef OHOS_CAMERA_H_STREAM_OPERATOR_MANAGER_H
#define OHOS_CAMERA_H_STREAM_OPERATOR_MANAGER_H

#include <refbase.h>
#include <set>
#include <mutex>
#include "moving_photo_proxy.h"
#include "safe_map.h"
namespace OHOS {
namespace CameraStandard {
class HStreamOperator;
class HStreamOperatorManager : public RefBase {
public:

    ~HStreamOperatorManager();

    static sptr<HStreamOperatorManager> &GetInstance();

    void AddStreamOperator(sptr<HStreamOperator> hStreamOperator);

    void RemoveStreamOperator(int32_t& hStreamOperatorId);

    void UpdateStreamOperator(int32_t& hStreamOperatorId);

    int32_t GetOfflineOutputSize();

    void AddTaskManager(int32_t& hStreamOperatorId, sptr<AvcodecTaskManagerIntf> AvcodecTaskManagerProxy);

    void RemoveTaskManager(int32_t& hStreamOperatorId);

    std::vector<sptr<HStreamOperator>> GetStreamOperatorByPid(pid_t pidRequest);

private:
    HStreamOperatorManager();
    std::mutex mapMutex_;
    static sptr<HStreamOperatorManager> streamOperatorManager_;
    std::map<int32_t, sptr<HStreamOperator>> streamOperatorManagerMap_;
    SafeMap<int32_t, sptr<AvcodecTaskManagerIntf>> taskManagerMap_;
    static std::mutex instanceMutex_;
    std::atomic<int32_t> streamOperatorIdGenerator_ = -1;

    inline int32_t GenerateStreamOperatorId()
    {
        streamOperatorIdGenerator_.fetch_add(1);
        if (streamOperatorIdGenerator_ == INT32_MAX) {
            streamOperatorIdGenerator_ = 0;
        }
        return streamOperatorIdGenerator_;
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_H_STREAM_OPERATOR_MANAGER_H
