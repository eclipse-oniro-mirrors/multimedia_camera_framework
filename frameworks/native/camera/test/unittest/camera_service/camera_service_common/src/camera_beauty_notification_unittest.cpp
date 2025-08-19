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

#include "camera_beauty_notification_unittest.h"
#include "camera_beauty_notification.h"
#include "camera_log.h"
#include "hcamera_service.h"
#include "ipc_skeleton.h"
#include "pixel_map.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
void CameraBeautyNotificationUnit::SetUpTestCase(void) {}

void CameraBeautyNotificationUnit::TearDownTestCase(void) {}

void CameraBeautyNotificationUnit::SetUp() {}

void CameraBeautyNotificationUnit::TearDown() {}


/*
 * Feature: Framework
 * Function: Test CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the behavior of CameraBeautyNotification when the instance is set to nullptr and then
 *re-obtained. The expected result is that the instance should be re-created and not be nullptr. Test the behavior of
 *CameraBeautyNotification when the instance is set to itself and then re-obtained. The expected result is that the
 *instance should remain valid and not be nullptr.
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_001, TestSize.Level1)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    test->instance_ = nullptr;
    test->GetInstance();
    ASSERT_NE(test->instance_, nullptr);
    test->instance_ = test;
    test->GetInstance();
    ASSERT_NE(test->instance_, nullptr);
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test InitResourceManager abnormal branches
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_002, TestSize.Level1)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    bool isRecordTimes_1 = true;
    int32_t beautyStatus = 1;
    test->SetBeautyStatus(beautyStatus);
    EXPECT_EQ(test->GetBeautyStatus(), beautyStatus);
    test->PublishNotification(isRecordTimes_1);

    int32_t beautyTimes_1 = 1;
    test->SetBeautyTimes(beautyTimes_1);
    EXPECT_EQ(test->GetBeautyTimes(), beautyTimes_1);
    int32_t beautyTimes_2 = 10;
    test->SetBeautyTimes(beautyTimes_2);
    test->PublishNotification(isRecordTimes_1);
    EXPECT_EQ(test->GetBeautyTimes(), beautyTimes_2);

    test->CancelNotification();
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetBeautyTimesFromDataShareHelper abnormal branches
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_003, TestSize.Level1)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    test->cameraDataShareHelper_ = nullptr;
    int32_t beautyStatus = 0;
    EXPECT_EQ(test->SetBeautyStatusFromDataShareHelper(beautyStatus), 1);
    test->cameraDataShareHelper_ = nullptr;
    EXPECT_EQ(test->GetBeautyStatusFromDataShareHelper(beautyStatus), 0);
    int32_t times = 0;
    test->cameraDataShareHelper_ = nullptr;
    EXPECT_EQ(test->SetBeautyTimesFromDataShareHelper(times), 1);
    test->cameraDataShareHelper_ = nullptr;
    EXPECT_EQ(test->GetBeautyTimesFromDataShareHelper(times), 0);
    test->cameraDataShareHelper_ = std::make_shared<CameraDataShareHelper>();
    EXPECT_EQ(test->SetBeautyStatusFromDataShareHelper(beautyStatus), 1);
    EXPECT_EQ(test->GetBeautyStatusFromDataShareHelper(beautyStatus), 0);
    EXPECT_EQ(test->SetBeautyTimesFromDataShareHelper(times), 1);
    EXPECT_EQ(test->GetBeautyTimesFromDataShareHelper(times), 0);
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test PublishNotification
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_004, TestSize.Level0)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    bool isRecordTimes_1 = true;
    bool isRecordTimes_2 = false;
    int32_t beautyStatus = 1;
    test->SetBeautyStatus(beautyStatus);
    EXPECT_EQ(test->GetBeautyStatus(), beautyStatus);
    test->PublishNotification(isRecordTimes_1);
    test->PublishNotification(isRecordTimes_2);
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetBeautyTimesFromDataShareHelper
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_005, TestSize.Level0)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    int32_t beautyStatus = 1;
    test->SetBeautyStatus(beautyStatus);
    EXPECT_EQ(test->GetBeautyStatus(), beautyStatus);
    int32_t times = 0;
    test->SetBeautyTimesFromDataShareHelper(times);
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CreateNotificationNormalContent
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_006, TestSize.Level0)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    int32_t beautyStatus = 1;
    test->SetBeautyStatus(beautyStatus);
    EXPECT_EQ(test->GetBeautyStatus(), beautyStatus);

    std::shared_ptr<Notification::NotificationNormalContent> normalContent =
        test->CreateNotificationNormalContent(beautyStatus);
    EXPECT_NE(normalContent, nullptr);
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetActionButton
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_007, TestSize.Level0)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    int32_t beautyStatus = 1;
    test->SetBeautyStatus(beautyStatus);
    EXPECT_EQ(test->GetBeautyStatus(), beautyStatus);

    std::string buttonName;
    Notification::NotificationRequest request;
    int32_t times = 0;
    test->SetActionButton(buttonName, request, times);
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSystemStringByName
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_008, TestSize.Level0)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    int32_t beautyStatus = 1;
    test->SetBeautyStatus(beautyStatus);
    EXPECT_EQ(test->GetBeautyStatus(), beautyStatus);

    std::string testName = "ic_public_camera_beauty";
    std::string rseult = test->GetSystemStringByName(testName);
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetPixelMap
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_009, TestSize.Level0)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    int32_t beautyStatus = 1;
    test->SetBeautyStatus(beautyStatus);
    EXPECT_EQ(test->GetBeautyStatus(), beautyStatus);

    test->iconPixelMap_ = nullptr;
    test->GetPixelMap();
    test->iconPixelMap_ = std::make_shared<OHOS::Media::PixelMap>();
    test->GetPixelMap();
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetMediaDataByName
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_010, TestSize.Level0)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    int32_t beautyStatus = 1;
    test->SetBeautyStatus(beautyStatus);
    EXPECT_EQ(test->GetBeautyStatus(), beautyStatus);

    size_t len = 0;
    std::unique_ptr<uint8_t[]> data;
    std::string testName = "ic_public_camera_beauty";
    Global::Resource::RState rstate = test->GetMediaDataByName(testName.c_str(), len, data);
    EXPECT_EQ(rstate, 0);
}

/*
 * Feature: Framework
 * Function: CameraBeautyNotification
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RefreshResConfig
 */
HWTEST_F(CameraBeautyNotificationUnit, camera_beauty_notification_unittest_011, TestSize.Level0)
{
    sptr<CameraBeautyNotification> test = CameraBeautyNotification::GetInstance();
    ASSERT_NE(test, nullptr);
    int32_t beautyStatus = 1;
    test->SetBeautyStatus(beautyStatus);
    EXPECT_EQ(test->GetBeautyStatus(), beautyStatus);
    test->RefreshResConfig();
}
}
}