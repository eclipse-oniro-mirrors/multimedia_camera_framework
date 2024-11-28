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
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "os_account_manager.h"
#include "output/sketch_wrapper.h"
#include "hcamera_preconfig.h"
#include "ipc_skeleton.h"
#include "hcamera_preconfig_unittest.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
void HCameraPreconfigUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraHostManagerUnitTest::SetUpTestCase started!");
}

void HCameraPreconfigUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraHostManagerUnitTest::TearDownTestCase started!");
}

void HCameraPreconfigUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("SetUp");
}

void HCameraPreconfigUnitTest::TearDown()
{
    MEDIA_INFO_LOG("TearDown start");
}

/*
 * Feature: Framework
 * Function: Test GeneratePhotoSessionPreconfigRatio1v1.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GeneratePhotoSessionPreconfigRatio1v1. Test PRECONFIG_TYPE_720P,
 *  PRECONFIG_TYPE_1080P, PRECONFIG_TYPE_4K and PRECONFIG_TYPE_HIGH_QUALITY under the
 *  conditions of P3 and a ratio of 1:1.
 */
HWTEST_F(HCameraPreconfigUnitTest, DumpPreconfigInfo_001, TestSize.Level1)
{
    CameraInfoDumper infoDumper(0);
    sptr<HCameraHostManager> hostManager = new HCameraHostManager(nullptr);
    ASSERT_NE(hostManager, nullptr);
    DumpPreconfigInfo(infoDumper, hostManager);
    std::string target = "Colorspace:P3";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "ratio 1:1";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Format:CAMERA_FORMAT_YUV_420_SP";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:720x720";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1080x1080";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1440x1440";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Fps:12-30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "prefer:30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
}

/*
 * Feature: Framework
 * Function: Test GeneratePhotoSessionPreconfigRatio4v3.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GeneratePhotoSessionPreconfigRatio4v3. Test PRECONFIG_TYPE_720P,
 *  PRECONFIG_TYPE_1080P, PRECONFIG_TYPE_4K and PRECONFIG_TYPE_HIGH_QUALITY under the
 *  conditions of P3 and a ratio of 4:3.
 */
HWTEST_F(HCameraPreconfigUnitTest, DumpPreconfigInfo_002, TestSize.Level1)
{
    CameraInfoDumper infoDumper(0);
    sptr<HCameraHostManager> hostManager = new HCameraHostManager(nullptr);
    ASSERT_NE(hostManager, nullptr);
    DumpPreconfigInfo(infoDumper, hostManager);
    std::string target = "Colorspace:P3";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "ratio 4:3";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Format:CAMERA_FORMAT_YUV_420_SP";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:960x720";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1440x1080";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1920x1440";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Fps:12-30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "prefer:30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
}

/*
 * Feature: Framework
 * Function: Test GeneratePhotoSessionPreconfigRatio16v9.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GeneratePhotoSessionPreconfigRatio16v9. Test PRECONFIG_TYPE_720P,
 *  PRECONFIG_TYPE_1080P, PRECONFIG_TYPE_4K and PRECONFIG_TYPE_HIGH_QUALITY under the
 *  conditions of P3 and a ratio of 16:9.
 */
HWTEST_F(HCameraPreconfigUnitTest, DumpPreconfigInfo_003, TestSize.Level1)
{
    CameraInfoDumper infoDumper(0);
    sptr<HCameraHostManager> hostManager = new HCameraHostManager(nullptr);
    ASSERT_NE(hostManager, nullptr);
    DumpPreconfigInfo(infoDumper, hostManager);
    std::string target = "Colorspace:P3";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "ratio 16:9";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Format:CAMERA_FORMAT_YUV_420_SP";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1280x720";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1920x1080";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:2560x1440";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Fps:12-30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "prefer:30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
}

/*
 * Feature: Framework
 * Function: Test GenerateVideoSessionPreconfigRatio1v1.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GenerateVideoSessionPreconfigRatio1v1. Test PRECONFIG_TYPE_720P,
 *  PRECONFIG_TYPE_1080P, PRECONFIG_TYPE_4K and PRECONFIG_TYPE_HIGH_QUALITY under the
 *  conditions of BT709 and a ratio of 1:1.
 */
HWTEST_F(HCameraPreconfigUnitTest, DumpPreconfigInfo_004, TestSize.Level1)
{
    CameraInfoDumper infoDumper(0);
    sptr<HCameraHostManager> hostManager = new HCameraHostManager(nullptr);
    ASSERT_NE(hostManager, nullptr);
    DumpPreconfigInfo(infoDumper, hostManager);
    std::string target = "Colorspace:BT709";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "ratio 1:1";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Format:CAMERA_FORMAT_YUV_420_SP";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:720x720";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1080x1080";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Fps:24-30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "prefer:30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
}

/*
 * Feature: Framework
 * Function: Test GenerateVideoSessionPreconfigRatio4v3.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GenerateVideoSessionPreconfigRatio4v3. Test PRECONFIG_TYPE_720P,
 *  PRECONFIG_TYPE_1080P, PRECONFIG_TYPE_4K and PRECONFIG_TYPE_HIGH_QUALITY under the
 *  conditions of BT709 and a ratio of 4:3.
 */
HWTEST_F(HCameraPreconfigUnitTest, DumpPreconfigInfo_005, TestSize.Level1)
{
    CameraInfoDumper infoDumper(0);
    sptr<HCameraHostManager> hostManager = new HCameraHostManager(nullptr);
    ASSERT_NE(hostManager, nullptr);
    DumpPreconfigInfo(infoDumper, hostManager);
    std::string target = "Colorspace:BT709";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "ratio 4:3";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Format:CAMERA_FORMAT_YUV_420_SP";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:960x720";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1440x1080";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Fps:24-30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "prefer:30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
}

/*
 * Feature: Framework
 * Function: Test GenerateVideoSessionPreconfigRatio16v9.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GenerateVideoSessionPreconfigRatio16v9. Test PRECONFIG_TYPE_720P,
 *  PRECONFIG_TYPE_1080P, PRECONFIG_TYPE_4K and PRECONFIG_TYPE_HIGH_QUALITY under the
 *  conditions of BT709 and a ratio of 16:9.
 */
HWTEST_F(HCameraPreconfigUnitTest, DumpPreconfigInfo_006, TestSize.Level1)
{
    CameraInfoDumper infoDumper(0);
    sptr<HCameraHostManager> hostManager = new HCameraHostManager(nullptr);
    ASSERT_NE(hostManager, nullptr);
    DumpPreconfigInfo(infoDumper, hostManager);
    std::string target = "Colorspace:BT709";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "ratio 16:9";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Format:CAMERA_FORMAT_YUV_420_SP";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1280x720";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Size:1920x1080";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "Fps:24-30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
    target= "prefer:30";
    EXPECT_TRUE(infoDumper.dumperString_.find(target));
}
}
}