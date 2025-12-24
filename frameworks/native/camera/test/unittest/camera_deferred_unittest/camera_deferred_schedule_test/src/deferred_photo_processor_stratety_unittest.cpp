/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "deferred_photo_processor_stratety_unittest.h"

#include "basic_definitions.h"
#include "dp_log.h"
#include "events_info.h"
#include "photo_trailing_state.h"
#include "state_factory.h"
#include "photo_job_repository.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
void DeferredPhotoProcessorStratetyUnittest::SetUpTestCase(void) {}

void DeferredPhotoProcessorStratetyUnittest::TearDownTestCase(void) {}

void DeferredPhotoProcessorStratetyUnittest::SetUp()
{
    sleep(1);
    auto repository = PhotoJobRepository::Create(userId_);
    strategyCenter_ = PhotoStrategyCenter::Create(repository);
    ASSERT_NE(strategyCenter_, nullptr);
}

void DeferredPhotoProcessorStratetyUnittest::TearDown() {}

class StateListenerMock : public IStateChangeListener<SchedulerType, SchedulerInfo> {
public:
    explicit StateListenerMock()
    {
        DP_DEBUG_LOG("entered.");
    }

    ~StateListenerMock() override
    {
        DP_DEBUG_LOG("entered.");
    }

    void OnSchedulerChanged(const SchedulerType& type, const SchedulerInfo& scheduleInfo) override
    {
        DP_DEBUG_LOG("entered.");
    }
};

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_001, TestSize.Level1)
{
    strategyCenter_->HandleEventChanged(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_AVAILABLE);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_0);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, NORMAL_CAMERA_CLOSED);
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_READY);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_READY_SPACE_LIMIT_REACHED);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_NOT_READY_PREEMPTED);
    EXPECT_EQ(strategyCenter_->IsReady(), false);
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_NOT_READY_OVERHEAT);
    EXPECT_EQ(strategyCenter_->IsReady(), false);
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_NOT_READY_TEMPORARILY);
    EXPECT_EQ(strategyCenter_->IsReady(), false);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_002, TestSize.Level1)
{
    strategyCenter_->HandleEventChanged(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_AVAILABLE);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_0);
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_READY);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, SYSTEM_CAMERA_CLOSED);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, NORMAL_CAMERA_CLOSED);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, SYSTEM_CAMERA_OPEN);
    EXPECT_EQ(strategyCenter_->IsReady(), false);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, NORMAL_CAMERA_OPEN);
    EXPECT_EQ(strategyCenter_->IsReady(), false);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_003, TestSize.Level1)
{
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_0);
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_READY);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, NORMAL_CAMERA_CLOSED);
    strategyCenter_->HandleEventChanged(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_DISCONNECTED);
    EXPECT_EQ(strategyCenter_->IsReady(), false);
    strategyCenter_->HandleEventChanged(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_AVAILABLE);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_004, TestSize.Level1)
{
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_READY);
    strategyCenter_->HandleEventChanged(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_AVAILABLE);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, NORMAL_CAMERA_OPEN);
    EventsInfo::GetInstance().SetCameraState(CameraSessionStatus::NORMAL_CAMERA_OPEN);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_0);
    auto mode = strategyCenter_->GetExecutionMode(JobPriority::HIGH);
    EXPECT_EQ(mode, ExecutionMode::HIGH_PERFORMANCE);
    mode = strategyCenter_->GetExecutionMode(JobPriority::NORMAL);
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_2);
    mode = strategyCenter_->GetExecutionMode(JobPriority::NORMAL);
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_005, TestSize.Level1)
{
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_READY);
    strategyCenter_->HandleEventChanged(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_AVAILABLE);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, SYSTEM_CAMERA_CLOSED);
    EventsInfo::GetInstance().SetCameraState(CameraSessionStatus::SYSTEM_CAMERA_CLOSED);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_0);
    auto mode = strategyCenter_->GetExecutionMode(JobPriority::HIGH);
    EXPECT_EQ(mode, ExecutionMode::HIGH_PERFORMANCE);
    mode = strategyCenter_->GetExecutionMode(JobPriority::NORMAL);
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_2);
    mode = strategyCenter_->GetExecutionMode(JobPriority::NORMAL);
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_006, TestSize.Level1)
{
    auto state = strategyCenter_->GetHdiStatus();
    EXPECT_EQ(state, HdiStatus::HDI_READY);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_007, TestSize.Level1)
{
    auto job = strategyCenter_->GetJob();
    ASSERT_EQ(job, nullptr);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_008, TestSize.Level1)
{
    auto listener = std::make_shared<StateListenerMock>();
    strategyCenter_->RegisterStateChangeListener(listener);
    ASSERT_EQ(strategyCenter_->photoStateChangeListener_.lock(), listener);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_009, TestSize.Level1)
{
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_7);
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_READY);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, SYSTEM_CAMERA_CLOSED);
    strategyCenter_->HandleEventChanged(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_AVAILABLE);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_0);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_1);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_2);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_3);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_4);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_5);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_6);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_7);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_010, TestSize.Level1)
{
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_7);
    strategyCenter_->HandleEventChanged(EventType::PHOTO_HDI_STATUS_EVENT, HDI_READY);
    strategyCenter_->HandleEventChanged(EventType::CAMERA_SESSION_STATUS_EVENT, SYSTEM_CAMERA_CLOSED);
    strategyCenter_->HandleEventChanged(EventType::MEDIA_LIBRARY_STATUS_EVENT, MEDIA_LIBRARY_AVAILABLE);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_0);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_1);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_2);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_3);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_4);
    EXPECT_EQ(strategyCenter_->IsReady(), true);
    sleep(26);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_5);
    EXPECT_EQ(strategyCenter_->IsReady(), false);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_6);
    EXPECT_EQ(strategyCenter_->IsReady(), false);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, LEVEL_7);
    EXPECT_EQ(strategyCenter_->IsReady(), false);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, -1);
    strategyCenter_->HandleEventChanged(EventType::THERMAL_LEVEL_STATUS_EVENT, 9);
}

HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_011, TestSize.Level1)
{
    StateFactory::Instance().states_.erase(PHOTO_HAL_STATE);
    auto state = strategyCenter_->GetHdiStatus();
    EXPECT_EQ(state, HdiStatus::HDI_DISCONNECTED);
}
} // DeferredProcessing
} // CameraStandard
} // OHOS
