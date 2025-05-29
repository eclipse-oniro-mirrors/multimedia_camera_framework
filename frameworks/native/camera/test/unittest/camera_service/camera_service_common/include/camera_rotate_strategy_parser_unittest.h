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

#ifndef CAMERA_ROTATE_STRATEGY_PARSER_UNITTEST_H
#define CAMERA_ROTATE_STRATEGY_PARSER_UNITTEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "camera_rotate_strategy_parser.h"
#include "camera_log.h"
#include "camera_xml_parser.h"
#include "message_parcel.h"

namespace OHOS {
namespace CameraStandard {

class CameraRotateStrategyParserUnitTest : public testing::Test {
public:
    /* SetUpTestCase: The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);

    /* TearDownTestCase: The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);

    /* SetUp: Execute before each test case */
    void SetUp();

    /* TearDown: Execute after each test case */
    void TearDown();
    void NativeAuthorization();
private:
    uint64_t tokenId_ = 0;
    uid_t uid_ = 0;
    int32_t userId_ = 0;
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_ROTATE_STRATEGY_PARSER_UNITTEST_H