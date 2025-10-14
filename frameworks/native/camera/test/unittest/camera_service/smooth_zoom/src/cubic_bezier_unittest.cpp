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

#include "cubic_bezier_unittest.h"

#include "camera_log.h"
#include "cubic_bezier.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void CubicBezierUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("CubicBezierUnitTest::SetUpTestCase started!");
}

void CubicBezierUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("CubicBezierUnitTest::TearDownTestCase started!");
}

void CubicBezierUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("CubicBezierUnitTest::SetUp started!");
}

void CubicBezierUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("CubicBezierUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test GetDuration.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetDuration when currentZoom is 0.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_001, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float currentZoom = 0.0;
    float targetZoom = 1.0;
    float result = cubicBezier->GetDuration(currentZoom, targetZoom);
    EXPECT_EQ(result, 0);
}

/*
 * Feature: Framework
 * Function: Test GetDuration.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetDuration when currentZoom is not 0.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_002, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float currentZoom = 1.0;
    float targetZoom = 1.0;
    float result = cubicBezier->GetDuration(currentZoom, targetZoom);
    EXPECT_GT(result, 0);
}

/*
 * Feature: Framework
 * Function: Test SetBezierValue.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetBezierValue normal branch.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_003, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    std::vector<float> zoomBezierValue = {1.0, 0.5, 0.5, 1.0, 1.0};
    EXPECT_TRUE(cubicBezier->SetBezierValue(zoomBezierValue));
    EXPECT_FLOAT_EQ(cubicBezier->mDurationBase, 1.0);
    EXPECT_FLOAT_EQ(cubicBezier->mControPointX1, 0.5);
    EXPECT_FLOAT_EQ(cubicBezier->mControPointY1, 0.5);
    EXPECT_FLOAT_EQ(cubicBezier->mControPointX2, 1.0);
    EXPECT_FLOAT_EQ(cubicBezier->mControPointY2, 1.0);
}

/*
 * Feature: Framework
 * Function: Test GetCubicBezierY.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCubicBezierY when time is 0.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_004, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float time = 0.0f;
    float expected = 0.0f;
    float actual = cubicBezier->GetCubicBezierY(time);
    EXPECT_FLOAT_EQ(expected, actual);
}

/*
 * Feature: Framework
 * Function: Test GetCubicBezierY.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCubicBezierY when time is not 0.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_005, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float time = 1.0f;
    float expected = 1.0f;
    float actual = cubicBezier->GetCubicBezierY(time);
    EXPECT_FLOAT_EQ(expected, actual);
}

/*
 * Feature: Framework
 * Function: Test GetCubicBezierX.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCubicBezierX when time is 0.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_006, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float time = 0.0f;
    float expected = 0.0f;
    float actual = cubicBezier->GetCubicBezierX(time);
    EXPECT_FLOAT_EQ(expected, actual);
}

/*
 * Feature: Framework
 * Function: Test GetCubicBezierX.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCubicBezierX when time is not 0.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_007, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float time = 1.0f;
    float expected = 1.0f;
    float actual = cubicBezier->GetCubicBezierX(time);
    EXPECT_FLOAT_EQ(expected, actual);
}

/*
 * Feature: Framework
 * Function: Test GetInterpolation.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetInterpolation when input is 0.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_008, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float input = 0.0;
    float expected = 0.0;
    EXPECT_FLOAT_EQ(cubicBezier->GetInterpolation(input), expected);
}

/*
 * Feature: Framework
 * Function: Test GetZoomArray.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetZoomArray when currentZoom is 0 and frameInterval is not 0.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_009, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float currentZoom = 0.0;
    float targetZoom = 2.0;
    float frameInterval = 0.1;
    std::vector<float> result = cubicBezier->GetZoomArray(currentZoom, targetZoom, frameInterval);
    EXPECT_EQ(result.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetZoomArray.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetZoomArray when currentZoom is not 0 and frameInterval is 0.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_010, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float currentZoom = 1.0;
    float targetZoom = 2.0;
    float frameInterval = 0.0;
    std::vector<float> result = cubicBezier->GetZoomArray(currentZoom, targetZoom, frameInterval);
    EXPECT_EQ(result.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetZoomArray.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetZoomArray when arraySize more than.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_011, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float currentZoom = 1.0;
    float targetZoom = 2.0;
    float frameInterval = 0.000001;
    std::vector<float> result = cubicBezier->GetZoomArray(currentZoom, targetZoom, frameInterval);
    EXPECT_EQ(result.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetZoomArray.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetZoomArray normal branch.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_012, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float currentZoom = 1.0;
    float targetZoom = 21.0;
    float frameInterval = 10.0;
    std::vector<float> result = cubicBezier->GetZoomArray(currentZoom, targetZoom, frameInterval);
    EXPECT_NE(result.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetZoomArray.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetZoomArray normal branch.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_013, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    std::vector<float> zoomBezierValue = {0.0, 1.0, 0.5, 1.0, 1.0};
    bool res = cubicBezier->SetBezierValue(zoomBezierValue);
    EXPECT_EQ(res, true);
}


/*
 * Feature: Framework
 * Function: Test GetZoomArray.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetZoomArray normal branch.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_014, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    float value = 0.17421875;
    float res = cubicBezier->BinarySearch(value);
    EXPECT_NE(res, 0);
}

/*
 * Feature: Framework
 * Function: Test SetBezierValue.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetBezierValue with default value.
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_015, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    std::vector<float> zoomBezierValue = {450.0, 0.4, 0.0, 0.2, 1.0};
    EXPECT_TRUE(cubicBezier->SetBezierValue(zoomBezierValue));
    EXPECT_FLOAT_EQ(cubicBezier->mDurationBase, 450.0);
    EXPECT_FLOAT_EQ(cubicBezier->mControPointX1, 0.4);
    EXPECT_FLOAT_EQ(cubicBezier->mControPointY1, 0.0);
    EXPECT_FLOAT_EQ(cubicBezier->mControPointX2, 0.2);
    EXPECT_FLOAT_EQ(cubicBezier->mControPointY2, 1.0);
}

/*
 * Feature: Framework
 * Function: Test BinarySearch.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test BinarySearch normal branch..
 */
HWTEST_F(CubicBezierUnitTest, cubic_bezier_unittest_016, TestSize.Level1)
{
    auto cubicBezier = std::make_shared<CubicBezier>();
    constexpr float MAX_RESOLUTION = 4000.0;
    constexpr float SERCH_STEP = 1.0 / MAX_RESOLUTION;
    int low = 0;
    int high = MAX_RESOLUTION;
    int middle = (low + high) / 2;
    float intput = cubicBezier->GetCubicBezierX(SERCH_STEP * middle);
    EXPECT_FLOAT_EQ(cubicBezier->BinarySearch(intput), middle);
}
} // CameraStandard
} // OHOS
