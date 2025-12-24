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

#ifndef OHOS_CAMERA_DPS_STATE_FACTORY_H
#define OHOS_CAMERA_DPS_STATE_FACTORY_H

#include "dp_log.h"
#include "istate.h"

#define REGISTER_STATE(T, ST, V) AutoRegister<T> gAutoRegster_##T(ST, V)

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class StateFactory {
public:
    ~StateFactory() = default;
    StateFactory(const StateFactory&) = delete;
    StateFactory operator=(const StateFactory&) = delete;
    static StateFactory& Instance();

    template<class T>
    void RegisterState(SchedulerType type, int32_t value)
    {
        DP_INFO_LOG("Register state, type=%{public}d", type);
        auto state = std::make_shared<T>(type, value);
        state->Initialize();
        states_.emplace(type, state);
    }

    std::shared_ptr<IState> GetState(SchedulerType type);

private:
    StateFactory() = default;

    std::unordered_map<SchedulerType, std::shared_ptr<IState>> states_ {};
};

template <typename T>
class AutoRegister {
public:
    explicit AutoRegister(SchedulerType type, int32_t value)
    {
        StateFactory::Instance().RegisterState<T>(type, value);
    }

    ~AutoRegister() = default;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_STATE_FACTORY_H