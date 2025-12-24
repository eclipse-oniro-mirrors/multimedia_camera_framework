/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "pipeline.h"
#include "cfilter.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace CameraStandard {
using namespace testing::ext;
using namespace testing;
class TestFilter : public CFilter {
public:
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<CFilter>& nextCFilter, CStreamType outType), (override));
    MOCK_METHOD(Status, OnLinked,
            (CStreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<CFilterLinkCallback>& callback), (override));
    TestFilter(std::string name, CFilterType type) : CFilter(std::move(name), type) {
        ON_CALL(*this, LinkNext(_, _)).WillByDefault(Return(Status::OK));
        ON_CALL(*this, OnLinked(_, _, _)).WillByDefault(Return(Status::OK));
    };
    ~TestFilter() override = default;
};

class PiplineUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp(void);

    void TearDown(void);
private:
    std::shared_ptr<Pipeline> pipeline_;
    std::shared_ptr<TestFilter> filterOne_;
    std::shared_ptr<TestFilter> filterTwo_;
    std::string testId;
};
} // namespace CameraStandard
} // namespace OHOS
#endif // PIPELINE_UNIT_TEST_H