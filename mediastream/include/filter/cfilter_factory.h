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

#ifndef OHOS_CAMERA_CFILTER_FACTORY_H
#define OHOS_CAMERA_CFILTER_FACTORY_H

#include "camera_log.h"
#include "cfilter.h"

namespace OHOS {
namespace CameraStandard {
using InstanceGenerator = std::function<std::shared_ptr<CFilter>(const std::string&, const CFilterType)>;

class CFilterFactory {
public:
    CFilterFactory(const CFilterFactory&) = delete;
    CFilterFactory& operator= (const CFilterFactory&) = delete;
    CFilterFactory(CFilterFactory&&) = delete;
    CFilterFactory& operator= (CFilterFactory&&) = delete;
    static CFilterFactory& Instance();

    template <typename T>
    std::shared_ptr<T> CreateCFilter(const std::string& filterName, const CFilterType type)
    {
        auto filter = CreateCFilter(filterName, type);
        auto typedCFilter = ReinterpretPointerCast<T>(filter);
        return typedCFilter;
    }

    template <typename T>
    void RegisterCFilter(const std::string& name, const CFilterType type, const InstanceGenerator& generator = nullptr)
    {
        RegisterCFilterPriv<T>(name, type, generator);
    }

private:
    CFilterFactory() = default;
    ~CFilterFactory() = default;

    std::shared_ptr<CFilter> CreateCFilter(const std::string& filterName, const CFilterType type);

    template <typename T>
    void RegisterCFilterPriv(const std::string& name, const CFilterType type, const InstanceGenerator& generator)
    {
        if (generator == nullptr) {
            auto result = generators_.emplace(
                type, [](const std::string& aliaName, const CFilterType type) {
                    return std::make_shared<T>(aliaName, type);
                });
            if (!result.second) {
                result.first->second = generator;
            }
        } else {
            auto result = generators_.emplace(type, generator);
            if (!result.second) {
                result.first->second = generator;
            }
        }
    }

    std::unordered_map<CFilterType, InstanceGenerator> generators_;
};

template <typename T>
class AutoRegisterCFilter {
public:
    explicit AutoRegisterCFilter(const std::string& name, const CFilterType type)
    {
        CFilterFactory::Instance().RegisterCFilter<T>(name, type);
    }

    AutoRegisterCFilter(const std::string& name, const CFilterType type, const InstanceGenerator& generator)
    {
        CFilterFactory::Instance().RegisterCFilter<T>(name, type, generator);
    }

    ~AutoRegisterCFilter() = default;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_CFILTER_FACTORY_H
