/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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


#ifndef PIPELINE_UNIT_TEST_H
#define PIPELINE_UNIT_TEST_H

#include "gtest/gtest.h"
#include "cfilter.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace CameraStandard {
using namespace testing::ext;
using namespace testing;
class CFilterUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp(void);

    void TearDown(void);

    const int32_t sleepTime_ = 1;
};

class MockFilter : public CFilter {
public:
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<CFilter>& nextCFilter, CStreamType outType), (override));
    MOCK_METHOD(Status, OnLinked,
            (CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback), (override));

    MockFilter(const std::string &name, CFilterType type, bool asyncMode = false)
        : CFilter("MockFilter", type)
    {
        ON_CALL(*this, LinkNext(_, _)).WillByDefault(Return(Status::OK));
        ON_CALL(*this, OnLinked(_, _, _)).WillByDefault(Return(Status::OK));
    }
};
} // namespace CameraStandard
} // namespace OHOS
#endif // PIPELINE_UNIT_TEST_H