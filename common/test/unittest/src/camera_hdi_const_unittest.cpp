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
#include "camera_hdi_const_unittest.h"
#include "camera_hdi_const.h"
#include "gtest/gtest.h"

using namespace OHOS::CameraStandard;
using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
void CameraHdiConstUnitTest::SetUpTestCase(void)
{}

void CameraHdiConstUnitTest::TearDownTestCase(void)
{}

void CameraHdiConstUnitTest::SetUp(void)
{}

void CameraHdiConstUnitTest::TearDown(void)
{}
/*
 * Feature: GetVersionId
 * Function: Test GetVersionId functionality
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetVersionId.
 */
HWTEST_F(CameraHdiConstUnitTest, Get_Version_Id_Compare_001, TestSize.Level0)
{
    EXPECT_TRUE(GetVersionId(1, 1) < GetVersionId(1, 2));
    EXPECT_TRUE(GetVersionId(1, 1) == GetVersionId(1, 1));
    EXPECT_TRUE(GetVersionId(1, 1) > GetVersionId(1, 0));
    EXPECT_TRUE(GetVersionId(2, 1) > GetVersionId(1, 2));
    EXPECT_TRUE(GetVersionId(2, 1) > GetVersionId(1, 1));
    EXPECT_TRUE(GetVersionId(2, 1) > GetVersionId(1, 0));

    EXPECT_TRUE(HDI_VERSION_ID_1_1 < GetVersionId(1, 2));
    EXPECT_TRUE(HDI_VERSION_ID_1_1 == GetVersionId(1, 1));
    EXPECT_TRUE(HDI_VERSION_ID_1_1 > GetVersionId(1, 0));
    EXPECT_TRUE(GetVersionId(2, 1) > HDI_VERSION_ID_1_2);
    EXPECT_TRUE(GetVersionId(2, 1) > HDI_VERSION_ID_1_1);
    EXPECT_TRUE(GetVersionId(2, 1) > HDI_VERSION_ID_1_0);
}
}  // namespace CameraStandard
}  // namespace OHOS