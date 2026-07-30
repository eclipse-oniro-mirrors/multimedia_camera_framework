/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MEDIA_MANAGER_ADAPTER_UNITTEST_H
#define MEDIA_MANAGER_ADAPTER_UNITTEST_H

#include "gtest/gtest.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

class MediaManagerAdapterUnittest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp:Execute before each test case */
    void SetUp();

    /* TearDown:Execute after each test case */
    void TearDown();

    int32_t srcFd_ {-1};
    int32_t temp1fd_ {-1};
    int32_t temp2fd_ {-1};

    static constexpr int32_t VIDEO_WIDTH = 1920;
    static constexpr int32_t VIDEO_HIGHT = 1080;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // MEDIA_MANAGER_ADAPTER_UNITTEST_H
