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

#include "hcamera_device_manager_unittest.h"

#include "camera_log.h"
#include "capture_scene_const.h"
#include "hcamera_device_manager.h"
#include "ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

void HCameraDeviceManagerUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraDeviceManagerUnitTest::SetUpTestCase started!");
}

void HCameraDeviceManagerUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("HCameraDeviceManagerUnitTest::TearDownTestCase started!");
}

void HCameraDeviceManagerUnitTest::SetUp()
{
    MEDIA_DEBUG_LOG("HCameraDeviceManagerUnitTest::SetUp started!");
}

void HCameraDeviceManagerUnitTest::TearDown()
{
    MEDIA_DEBUG_LOG("HCameraDeviceManagerUnitTest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test GetACameraId normal branches.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetACameraId normal branches.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_002, TestSize.Level0)
{
    std::string ret = HCameraDeviceManager::GetInstance()->GetACameraId();
    EXPECT_EQ(ret, "");
    std::string cameraId = "testId";
    int32_t state = 0;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    ret = HCameraDeviceManager::GetInstance()->GetACameraId();
    ASSERT_NE(ret, "");
}
} // CameraStandard
} // OHOS
