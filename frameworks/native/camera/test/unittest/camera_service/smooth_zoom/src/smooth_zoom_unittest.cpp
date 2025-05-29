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

#include "smooth_zoom_unittest.h"

#include "camera_log.h"
#include "cubic_bezier.h"
#include "smooth_zoom.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void SmoothZoomUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("SmoothZoomUnitTest::SetUpTestCase started!");
}

void SmoothZoomUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("SmoothZoomUnitTest::TearDownTestCase started!");
}

void SmoothZoomUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("SmoothZoomUnitTest::SetUp started!");
}

void SmoothZoomUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("SmoothZoomUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test GetZoomAlgorithm normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetZoomAlgorithm normal branches.
 */
HWTEST_F(SmoothZoomUnitTest, smooth_zoom_unittest_001, TestSize.Level1)
{
    SmoothZoomType mode = SmoothZoomType::NORMAL;

    std::shared_ptr<IZoomAlgorithm> algorithm = SmoothZoom::GetZoomAlgorithm(mode);

    ASSERT_TRUE(algorithm != nullptr);
}

/*
 * Feature: Framework
 * Function: Test GetZoomAlgorithm normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetZoomAlgorithm normal branches.
 */
HWTEST_F(SmoothZoomUnitTest, smooth_zoom_unittest_002, TestSize.Level1)
{
    int32_t mode = 1;

    std::shared_ptr<IZoomAlgorithm> algorithm = SmoothZoom::GetZoomAlgorithm(static_cast<SmoothZoomType>(mode));

    ASSERT_TRUE(algorithm != nullptr);
}
} // CameraStandard
} // OHOS
