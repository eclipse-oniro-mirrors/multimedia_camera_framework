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

#include "cfilter_factory.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
CFilterFactory& CFilterFactory::Instance()
{
    static CFilterFactory instance;
    return instance;
}

std::shared_ptr<CFilter> CFilterFactory::CreateCFilter(const std::string& filterName, const CFilterType type)
{
    auto it = generators_.find(type);
    CHECK_RETURN_RET(it != generators_.end(), it->second(filterName, type));
    return nullptr;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP