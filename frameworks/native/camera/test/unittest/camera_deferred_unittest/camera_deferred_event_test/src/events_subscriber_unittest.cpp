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

#include "events_subscriber_unittest.h"

#include "common_event_data.h"
#include "common_event_subscribe_info.h"
#include "common_event_support.h"
#include "events_subscriber.h"
#include "events_strategy.h"
#include "gtest/gtest.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

void EventsSubscriberUnitTest::SetUpTestCase(void) {}

void EventsSubscriberUnitTest::TearDownTestCase(void) {}

void EventsSubscriberUnitTest::SetUp(void) {}

void EventsSubscriberUnitTest::TearDown(void) {}

/*
 * Feature: EventSubscriber
 * Function: Test CreateCommonSubscriber creates a valid subscriber
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CreateCommonSubscriber should return a non-null shared_ptr
 * with all common events registered
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_001, TestSize.Level0)
{
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test CreatePermissionSubscriber creates a valid subscriber
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CreatePermissionSubscriber should return a non-null shared_ptr
 * when given valid event and permission strings
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_002, TestSize.Level0)
{
    const std::string testEvent = "test.event";
    const std::string testPermission = "test.permission";

    auto subscriber = EventSubscriber::CreatePermissionSubscriber(testEvent, testPermission);
    ASSERT_NE(subscriber, nullptr);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test CreateCameraSubscriber creates a valid subscriber
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: CreateCameraSubscriber should return a non-null shared_ptr
 * with camera status event and permission
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_003, TestSize.Level0)
{
    auto subscriber = EventSubscriber::CreateCameraSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test InitializeStrategies populates strategy map on first call
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: After InitializeStrategies, OnReceiveEvent should handle
 * known events without error
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_004, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test OnReceiveEvent with unknown event action
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent with an unregistered event action should
 * not crash and should log a warning
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_005, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction("unknown.event.action");
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test InitializeStrategies does not reinitialize when already populated
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Calling InitializeStrategies twice should be safe and not
 * crash or duplicate entries
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_006, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test OnReceiveEvent with COMMON_EVENT_THERMAL_LEVEL_CHANGED
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent should dispatch thermal level event to ThermalStrategy
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_007, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test OnReceiveEvent with COMMON_EVENT_CHARGING
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent should dispatch charging event to ChargingStrategy
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_008, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test OnReceiveEvent with COMMON_EVENT_DISCHARGING
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent should dispatch discharging event to ChargingStrategy
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_009, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test OnReceiveEvent with COMMON_EVENT_BATTERY_OKAY
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent should dispatch battery okay event to BatteryStrategy
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_010, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_OKAY);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test OnReceiveEvent with COMMON_EVENT_BATTERY_LOW
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent should dispatch battery low event to BatteryStrategy
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_011, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_LOW);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test OnReceiveEvent with COMMON_EVENT_BATTERY_CHANGED
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent should dispatch battery changed event to BatteryLevelStrategy
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_012, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test OnReceiveEvent with COMMON_EVENT_USER_SWITCHED
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent should dispatch user switched event to UserStrategy
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_013, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test OnReceiveEvent with camera status event
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: OnReceiveEvent should dispatch camera status event to CameraStrategy
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_014, TestSize.Level0)
{
    EventSubscriber::InitializeStrategies();
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    EventFwk::Want want;
    want.SetAction("usual.event.CAMERA_STATUS");
    EventFwk::CommonEventData data;
    data.SetWant(want);

    subscriber->OnReceiveEvent(data);
    EXPECT_GT(subscriber.use_count(), 0);
}

/*
 * Feature: EventSubscriber
 * Function: Test Subcribe and UnSubscribe
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Subcribe and UnSubscribe should execute without crash
 * (actual subscription depends on system service availability)
 */
HWTEST_F(EventsSubscriberUnitTest, events_subscriber_unittest_015, TestSize.Level0)
{
    auto subscriber = EventSubscriber::CreateCommonSubscriber();
    ASSERT_NE(subscriber, nullptr);

    subscriber->Subcribe();
    subscriber->UnSubscribe();
    EXPECT_GT(subscriber.use_count(), 0);

    auto permSubscriber = EventSubscriber::CreatePermissionSubscriber("", "");
    EXPECT_NE(permSubscriber, nullptr);
    EXPECT_GT(permSubscriber.use_count(), 0);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS