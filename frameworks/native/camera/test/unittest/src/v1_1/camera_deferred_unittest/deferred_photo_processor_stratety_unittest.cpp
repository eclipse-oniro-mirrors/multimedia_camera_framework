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

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "token_setproc.h"

#include "background_strategy.h"
#include "deferred_photo_processor_stratety_unittest.h"
#include "photo_job_repository.h"
#include "user_initiated_strategy.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {

void DeferredPhotoProcessorStratetyUnittest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "DeferredPhotoProcessorStratetyUnittest::SetUpTestCase start";
}

void DeferredPhotoProcessorStratetyUnittest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "DeferredPhotoProcessorStratetyUnittest::TearDownTestCase start";
}

void DeferredPhotoProcessorStratetyUnittest::SetUp()
{
    GTEST_LOG_(INFO) << "DeferredPhotoProcessorStratetyUnittest::SetUp start";
    NativeAuthorization();
}

void DeferredPhotoProcessorStratetyUnittest::TearDown()
{
    GTEST_LOG_(INFO) << "DeferredPhotoProcessorStratetyUnittest::TearDown start";
}

void DeferredPhotoProcessorStratetyUnittest::NativeAuthorization()
{
    GTEST_LOG_(INFO) << "DeferredPhotoProcessorStratetyUnittest::NativeAuthorization start";
    const char *perms[2];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.CAMERA";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "native_camera_tdd",
        .aplStr = "system_basic",
    };
    tokenId_ = GetAccessTokenId(&infoInstance);
    uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid_, userId_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Deferred
 * Function: Test initialize backgroundStrategy
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test after initialize backgroundStrategy, strategy is not nullptr,
 *                  execution mode is LOAD_BALANCE, hdi status is HDI_READY.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_001 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    auto job = strategy->GetJob();
    auto work = strategy->GetWork();
    if (job) {
        EXPECT_NE(work, nullptr);
    } else {
        EXPECT_EQ(work, nullptr);
    }
    auto mode = strategy->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
    auto status = strategy->GetHdiStatus();
    EXPECT_EQ(status, HdiStatus::HDI_READY);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_001 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy GetWork
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while execution mode is DUMMY, work is nullptr.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_002 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyHdiStatusChanged(HdiStatus::HDI_NOT_READY_PREEMPTED);
    auto mode = strategy->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
    auto work = strategy->GetWork();
    EXPECT_EQ(work, nullptr);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_002 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while session status is SYSTEM_CAMERA_OPEN, execution mode is DUMMY.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_003 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyCameraStatusChanged(CameraSessionStatus::SYSTEM_CAMERA_OPEN);
    auto mode = strategy->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
    auto work = strategy->GetWork();
    EXPECT_EQ(work, nullptr);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_003 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while session status is NORMAL_CAMERA_OPEN, execution mode is DUMMY.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_004 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyCameraStatusChanged(CameraSessionStatus::NORMAL_CAMERA_OPEN);
    auto mode = strategy->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
    auto work = strategy->GetWork();
    EXPECT_EQ(work, nullptr);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_004 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while hdi status is not HDI_READY or HDI_READY_SPACE_LIMIT_REACHED, execution mode is DUMMY.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_005 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyHdiStatusChanged(HdiStatus::HDI_READY);
    auto mode = strategy->GetExecutionMode();
    EXPECT_NE(mode, ExecutionMode::DUMMY);
    strategy->NotifyHdiStatusChanged(HdiStatus::HDI_READY_SPACE_LIMIT_REACHED);
    mode = strategy->GetExecutionMode();
    EXPECT_NE(mode, ExecutionMode::DUMMY);
    strategy->NotifyHdiStatusChanged(HdiStatus::HDI_DISCONNECTED);
    mode = strategy->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
    auto work = strategy->GetWork();
    EXPECT_EQ(work, nullptr);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_005 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while media library status is MEDIA_LIBRARY_DISCONNECTED, execution mode is DUMMY.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_006 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyMediaLibStatusChanged(MediaLibraryStatus::MEDIA_LIBRARY_DISCONNECTED);
    auto mode = strategy->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
    auto work = strategy->GetWork();
    EXPECT_EQ(work, nullptr);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_006 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while strategy is in trailing, execution mode is LOAD_BALANCE.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_007 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->StartTrailing(TRAILING_DURATION_TWO_SEC);
    auto mode = strategy->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::LOAD_BALANCE);
    auto job = strategy->GetJob();
    auto work = strategy->GetWork();
    if (job) {
        EXPECT_NE(work, nullptr);
    } else {
        EXPECT_EQ(work, nullptr);
    }
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_007 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy GetExecutionMode
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while system pressure level is not NOMINAL, execution mode is DUMMY.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_008 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyPressureLevelChanged(SystemPressureLevel::FAIR);
    auto mode = strategy->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::DUMMY);
    auto work = strategy->GetWork();
    EXPECT_EQ(work, nullptr);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_008 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy NotifyCameraStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while session status is SYSTEM_CAMERA_OPEN, strategy is not in trailing.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_009 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyCameraStatusChanged(CameraSessionStatus::SYSTEM_CAMERA_OPEN);
    EXPECT_FALSE(strategy->isInTrailing_);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_009 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy NotifyCameraStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while session status is NORMAL_CAMERA_OPEN, strategy is not in trailing.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_010 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyCameraStatusChanged(CameraSessionStatus::NORMAL_CAMERA_OPEN);
    EXPECT_FALSE(strategy->isInTrailing_);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_010 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy NotifyCameraStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while session status is SYSTEM_CAMERA_CLOSED, strategy is in trailing.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_011 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyCameraStatusChanged(CameraSessionStatus::SYSTEM_CAMERA_CLOSED);
    EXPECT_TRUE(strategy->isInTrailing_);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_011 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy NotifyCameraStatusChanged
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while session status is NORMAL_CAMERA_CLOSED, strategy is not in trailing.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_012 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->NotifyCameraStatusChanged(CameraSessionStatus::NORMAL_CAMERA_CLOSED);
    EXPECT_FALSE(strategy->isInTrailing_);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_012 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy FlashTrailingState
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while strategy is in trailing, after the remain trailing time,
 *                  the trailing status can be changed from true to false by FlashTrailingState.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_013 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->FlashTrailingState();
    EXPECT_FALSE(strategy->isInTrailing_);
    strategy->StartTrailing(TRAILING_DURATION_TWO_SEC);
    EXPECT_TRUE(strategy->isInTrailing_);
    strategy->FlashTrailingState();
    EXPECT_TRUE(strategy->isInTrailing_);
    sleep(TRAILING_DURATION_TWO_SEC);
    strategy->FlashTrailingState();
    EXPECT_FALSE(strategy->isInTrailing_);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_013 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy StartTrailing
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while strategy is not in trailing,
 *                  the trailing status can be changed from false to true by StartTrailing.
 *                  After the remain trailing time, the trailing status can not be changed automatically.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_014 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->StartTrailing(0);
    EXPECT_FALSE(strategy->isInTrailing_);
    strategy->StartTrailing(TRAILING_DURATION_TWO_SEC);
    EXPECT_TRUE(strategy->isInTrailing_);
    strategy->StartTrailing(TRAILING_DURATION_TWO_SEC);
    EXPECT_TRUE(strategy->isInTrailing_);
    sleep(TRAILING_DURATION_FOUR_SEC);
    EXPECT_TRUE(strategy->isInTrailing_);
    strategy->StartTrailing(TRAILING_DURATION_TWO_SEC);
    EXPECT_TRUE(strategy->isInTrailing_);
    strategy->StartTrailing(TRAILING_DURATION_ONE_SEC);
    EXPECT_TRUE(strategy->isInTrailing_);
    strategy->FlashTrailingState();
    EXPECT_TRUE(strategy->isInTrailing_);
    sleep(TRAILING_DURATION_FOUR_SEC);
    strategy->FlashTrailingState();
    EXPECT_FALSE(strategy->isInTrailing_);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_014 end";
}

/*
 * Feature: Deferred
 * Function: Test backgroundStrategy StopTrailing
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test while strategy is in trailing, no matter whether it is after the remain trailing time,
 *                  the trailing status can be changed from true to false by StopTrailing.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_015 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<BackgroundStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    strategy->StopTrailing();
    EXPECT_FALSE(strategy->isInTrailing_);
    strategy->StartTrailing(TRAILING_DURATION_TWO_SEC);
    EXPECT_TRUE(strategy->isInTrailing_);
    strategy->StopTrailing();
    EXPECT_FALSE(strategy->isInTrailing_);
    strategy->StartTrailing(TRAILING_DURATION_TWO_SEC);
    EXPECT_TRUE(strategy->isInTrailing_);
    sleep(TRAILING_DURATION_FOUR_SEC);
    strategy->StopTrailing();
    EXPECT_FALSE(strategy->isInTrailing_);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_015 end";
}

/*
 * Feature: Deferred
 * Function: Test initialize userInitiatedStrategy
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test after initialize userInitiatedStrategy, strategy is not nullptr,
 *                  execution mode is HIGH_PERFORMANCE.
 */
HWTEST_F(DeferredPhotoProcessorStratetyUnittest, deferred_photo_processor_stratety_unittest_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_016 start";
    auto repository = std::make_shared<PhotoJobRepository>(userId_);
    ASSERT_NE(repository, nullptr);
    auto strategy = std::make_shared<UserInitiatedStrategy>(repository);
    ASSERT_NE(strategy, nullptr);

    auto job = strategy->GetJob();
    auto work = strategy->GetWork();
    if (job) {
        EXPECT_NE(work, nullptr);
    } else {
        EXPECT_EQ(work, nullptr);
    }
    auto mode = strategy->GetExecutionMode();
    EXPECT_EQ(mode, ExecutionMode::HIGH_PERFORMANCE);
    GTEST_LOG_(INFO) << "deferred_photo_processor_stratety_unittest_016 end";
}
} // CameraStandard
} // OHOS
