/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HSTREAM_OPERATOR_MANAGER_UNITTEST_H
#define HSTREAM_OPERATOR_MANAGER_UNITTEST_H

#include <gtest/gtest.h>
#include "hstream_operator_manager.h"
#include "hstream_operator.h"

namespace OHOS {
namespace CameraStandard {
using namespace testing;
using namespace testing::ext;

class HStreamOperatorManagerUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void NativeAuthorization();

private:
    uint64_t tokenId_ = 0;
    uid_t uid_ = 0;
    int32_t userId_ = 0;
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

#endif // HSTREAM_OPERATOR_MANAGER_UNITTEST_H