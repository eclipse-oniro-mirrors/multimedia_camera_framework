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

#include "camera_info_dumper_unittest.h"

#include "camera_log.h"
#include "camera_info_dumper.h"
#include "capture_scene_const.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CameraInfoDumperUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraInfoDumperUnitTest::SetUpTestCase started!");
}

void CameraInfoDumperUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CameraInfoDumperUnitTest::TearDownTestCase started!");
}

void CameraInfoDumperUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CameraInfoDumperUnitTest::SetUp started!");
}

void CameraInfoDumperUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CameraInfoDumperUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test CameraInfoDumper functional function with different parameter.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraInfoDumper functional function with different parameter.
 */
HWTEST_F(CameraInfoDumperUnitTest, camera_info_dumper_unittest_001, TestSize.Level0)
{
    CameraInfoDumper infoDumper(0);
    char msg_1[] = "testMsg_1";
    infoDumper.depth_ = 0;
    infoDumper.Print();
    infoDumper.Title(msg_1);
    EXPECT_EQ(infoDumper.dumperString_, "# testMsg_1\n");
    infoDumper.Push();
    EXPECT_EQ(infoDumper.depth_, 1);
    infoDumper.Pop();
    EXPECT_EQ(infoDumper.depth_, 0);
    infoDumper.Print();

    infoDumper.Msg(msg_1);
    EXPECT_EQ(infoDumper.dumperString_, "# testMsg_1\n  testMsg_1\n");
    infoDumper.Push();
    EXPECT_EQ(infoDumper.depth_, 1);
    infoDumper.Pop();
    EXPECT_EQ(infoDumper.depth_, 0);
    infoDumper.Print();

    infoDumper.Tip(msg_1);
    EXPECT_EQ(infoDumper.dumperString_, "# testMsg_1\n  testMsg_1\ntestMsg_1\n");
}
} // CameraStandard
} // OHOS
