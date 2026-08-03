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

#include "events_info_unittest.h"

#include "basic_definitions.h"
#include "events_info.h"
#include "gtest/gtest.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

void EventsInfoUnitTest::SetUpTestCase(void) {}

void EventsInfoUnitTest::TearDownTestCase(void) {}

void EventsInfoUnitTest::SetUp(void) {}

void EventsInfoUnitTest::TearDown(void) {}

/*
 * Feature: EventsInfo
 * Function: Test GetScreenState returns default value SCREEN_OFF
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When CAMERA_USE_POWER is not defined, GetScreenState
 * should return the default SCREEN_OFF value
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_001, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    ScreenStatus state = eventsInfo.GetScreenState();

    EXPECT_EQ(state, eventsInfo.screenState_);
}

/*
 * Feature: EventsInfo
 * Function: Test GetBatteryState returns default value BATTERY_OKAY
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When CAMERA_USE_BATTERY is not defined, GetBatteryState
 * should return the default BATTERY_OKAY value
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_002, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    BatteryStatus state = eventsInfo.GetBatteryState();

    EXPECT_EQ(state, eventsInfo.batteryState_);
}

/*
 * Feature: EventsInfo
 * Function: Test GetChargingState returns default value CHARGING
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When CAMERA_USE_BATTERY is not defined, GetChargingState
 * should return the default CHARGING value
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_003, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    ChargingStatus state = eventsInfo.GetChargingState();

    EXPECT_EQ(state, eventsInfo.chargingState_);
}

/*
 * Feature: EventsInfo
 * Function: Test GetBatteryLevel returns default value BATTERY_LEVEL_LOW
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When CAMERA_USE_BATTERY is not defined, GetBatteryLevel
 * should return the default BATTERY_LEVEL_LOW value
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_004, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    BatteryLevel level = eventsInfo.GetBatteryLevel();

    EXPECT_EQ(level, eventsInfo.batteryLevel_);
}

/*
 * Feature: EventsInfo
 * Function: Test GetThermalLevel returns default value LEVEL_0
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When CAMERA_USE_THERMAL is not defined, GetThermalLevel
 * should return the default LEVEL_0 value
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_005, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    ThermalLevel level = eventsInfo.GetThermalLevel();

    EXPECT_EQ(level, eventsInfo.thermalLevel_);
}

/*
 * Feature: EventsInfo
 * Function: Test GetCameraState returns default SYSTEM_CAMERA_CLOSED
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: GetCameraState should return the default SYSTEM_CAMERA_CLOSED
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_006, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    CameraSessionStatus state = eventsInfo.GetCameraState();

    EXPECT_EQ(state, eventsInfo.cameraState_);
}

/*
 * Feature: EventsInfo
 * Function: Test SetCameraState and GetCameraState
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After SetCameraState, GetCameraState should return the set value
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_007, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetCameraState(CameraSessionStatus::NORMAL_CAMERA_OPEN);
    EXPECT_EQ(eventsInfo.GetCameraState(), CameraSessionStatus::NORMAL_CAMERA_OPEN);

    eventsInfo.SetCameraState(CameraSessionStatus::SYSTEM_CAMERA_OPEN);
    EXPECT_EQ(eventsInfo.GetCameraState(), CameraSessionStatus::SYSTEM_CAMERA_OPEN);

    eventsInfo.SetCameraState(CameraSessionStatus::SYSTEM_CAMERA_CLOSED);
    EXPECT_EQ(eventsInfo.GetCameraState(), CameraSessionStatus::SYSTEM_CAMERA_CLOSED);
}

/*
 * Feature: EventsInfo
 * Function: Test IsCameraOpen returns true when NORMAL_CAMERA_OPEN
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: IsCameraOpen should return true when camera is NORMAL_CAMERA_OPEN
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_008, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetCameraState(CameraSessionStatus::NORMAL_CAMERA_OPEN);

    EXPECT_TRUE(eventsInfo.IsCameraOpen());
}

/*
 * Feature: EventsInfo
 * Function: Test IsCameraOpen returns true when SYSTEM_CAMERA_OPEN
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: IsCameraOpen should return true when camera is SYSTEM_CAMERA_OPEN
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_009, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetCameraState(CameraSessionStatus::SYSTEM_CAMERA_OPEN);

    EXPECT_TRUE(eventsInfo.IsCameraOpen());
}

/*
 * Feature: EventsInfo
 * Function: Test IsCameraOpen returns false when CAMERA_CLOSED
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: IsCameraOpen should return false when camera is closed
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_010, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetCameraState(CameraSessionStatus::SYSTEM_CAMERA_CLOSED);

    EXPECT_FALSE(eventsInfo.IsCameraOpen());
}

/*
 * Feature: EventsInfo
 * Function: Test GetAvailableMemory returns default value
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: When MEMMGR_OVERRID is not defined, GetAvailableMemory
 * should return DEFAULT_MEMORY_SIZE
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_011, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    int32_t memory = eventsInfo.GetAvailableMemory();

    EXPECT_EQ(memory, -1);
}

/*
 * Feature: EventsInfo
 * Function: Test SetMediaLibraryState and IsMediaBusy
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: IsMediaBusy should reflect the state set by SetMediaLibraryState
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_012, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetMediaLibraryState(MediaLibraryStatus::MEDIA_LIBRARY_IDLE);
    EXPECT_FALSE(eventsInfo.IsMediaBusy());

    eventsInfo.SetMediaLibraryState(MediaLibraryStatus::MEDIA_LIBRARY_BUSY);
    EXPECT_TRUE(eventsInfo.IsMediaBusy());
}

/*
 * Feature: EventsInfo
 * Function: Test SetCurrentUser and GetCurrentUser
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After SetCurrentUser, GetCurrentUser should return the set value
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_013, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetCurrentUser(100);
    EXPECT_EQ(eventsInfo.GetCurrentUser(), 100);

    eventsInfo.SetCurrentUser(200);
    EXPECT_EQ(eventsInfo.GetCurrentUser(), 200);
}

/*
 * Feature: EventsInfo
 * Function: Test IsAllowedToSchedule returns true when userId matches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: IsAllowedToSchedule should return true when given userId
 * matches the stored userId
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_014, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetCurrentUser(100);

    EXPECT_TRUE(eventsInfo.IsAllowedToSchedule(100));
}

/*
 * Feature: EventsInfo
 * Function: Test IsAllowedToSchedule returns false when userId mismatches
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: IsAllowedToSchedule should return false when given userId
 * does not match the stored userId
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_015, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetCurrentUser(100);

    EXPECT_FALSE(eventsInfo.IsAllowedToSchedule(200));
}

/*
 * Feature: EventsInfo
 * Function: Test SetTrailing and NeedTrailing
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: NeedTrailing should return the value set by SetTrailing,
 * and reset to false after reading
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_016, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetTrailing(true);

    EXPECT_TRUE(eventsInfo.NeedTrailing());
    EXPECT_FALSE(eventsInfo.NeedTrailing());
}

/*
 * Feature: EventsInfo
 * Function: Test NeedTrailing returns false when not set
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: NeedTrailing should return false by default
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_017, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetTrailing(false);

    EXPECT_FALSE(eventsInfo.NeedTrailing());
}

/*
 * Feature: EventsInfo
 * Function: Test IsMediaBusy returns false when media library is idle
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: IsMediaBusy should return false when state is MEDIA_LIBRARY_IDLE
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_018, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetMediaLibraryState(MediaLibraryStatus::MEDIA_LIBRARY_IDLE);

    EXPECT_FALSE(eventsInfo.IsMediaBusy());
}

/*
 * Feature: EventsInfo
 * Function: Test IsMediaBusy returns true when media library is busy
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: IsMediaBusy should return true when state is MEDIA_LIBRARY_BUSY
 */
HWTEST_F(EventsInfoUnitTest, events_info_unittest_019, TestSize.Level0)
{
    auto& eventsInfo = EventsInfo::GetInstance();
    eventsInfo.SetMediaLibraryState(MediaLibraryStatus::MEDIA_LIBRARY_BUSY);

    EXPECT_TRUE(eventsInfo.IsMediaBusy());
}

} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS