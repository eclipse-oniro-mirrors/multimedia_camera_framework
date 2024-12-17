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

#include "camera_output_capability_unittest.h"

#include "gtest/gtest.h"
#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "camera_manager.h"
#include "camera_util.h"
#include "capture_output.h"
#include "capture_session.h"
#include "gmock/gmock.h"
#include "input/camera_input.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "os_account_manager.h"

using namespace testing::ext;
using ::testing::A;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;

void CameraOutputCapabilityUnit::SetUpTestCase(void) {}

void CameraOutputCapabilityUnit::TearDownTestCase(void) {}

void CameraOutputCapabilityUnit::SetUp()
{
    NativeAuthorization();
}

void CameraOutputCapabilityUnit::TearDown() {}

void CameraOutputCapabilityUnit::NativeAuthorization()
{
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
    MEDIA_DEBUG_LOG("CameraOutputCapabilityUnit::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}


/*
 * Feature: Framework
 * Function: Test CameraOutputCapability with GetTargetRatio
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraOutputCapability with GetTargetRatio when sizeRatio is different
 */
HWTEST_F(CameraOutputCapabilityUnit, camera_output_capability_unittest_001, TestSize.Level0)
{
    ProfileSizeRatio sizeRatio = UNSPECIFIED;
    float unspecifiedValue = 2.0f;
    EXPECT_EQ(GetTargetRatio(sizeRatio, unspecifiedValue), 2.0f);

    sizeRatio = static_cast<ProfileSizeRatio>(16);
    EXPECT_EQ(GetTargetRatio(sizeRatio, unspecifiedValue), 2.0f);
}

/*
 * Feature: Framework
 * Function: Test Profile with IsContains
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test Profile with IsContains
 * when frameratres_ is null or profile.framerates_ is null
 */
HWTEST_F(CameraOutputCapabilityUnit, camera_output_capability_unittest_002, TestSize.Level0)
{
    std::vector<int32_t> framerates = {};
    Size size = {.width = 1920, .height = 1080};
    VideoProfile profile = VideoProfile(CameraFormat::CAMERA_FORMAT_YUV_420_SP, size, framerates);
    std::vector<int32_t> framerates_2 = {};
    VideoProfile profile_2 = VideoProfile(CameraFormat::CAMERA_FORMAT_YUV_420_SP, size, framerates_2);
    EXPECT_FALSE(profile.IsContains(profile_2));

    profile.framerates_ = {120, 120};
    EXPECT_TRUE(profile.IsContains(profile_2));
}

/*
 * Feature: Framework
 * Function: Test CameraOutputCapability with IsMatchPhotoProfiles
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraOutputCapability with IsMatchPhotoProfiles if no match occurs
 */
HWTEST_F(CameraOutputCapabilityUnit, camera_output_capability_unittest_003, TestSize.Level0)
{
    CameraFormat photoFormat = CAMERA_FORMAT_JPEG;
    Size photoSize = {480, 640};
    Size size = {640, 480};
    Profile photoProfile_1 = Profile(photoFormat, photoSize);
    Profile photoProfile_2 = Profile(photoFormat, size);
    Profile photoProfile_3 = Profile(CAMERA_FORMAT_INVALID, size);

    std::shared_ptr<CameraOutputCapability> capability = std::make_shared<CameraOutputCapability>();
    ASSERT_NE(capability, nullptr);

    capability->SetPhotoProfiles({photoProfile_1, photoProfile_2});
    std::vector<Profile> profiles = {photoProfile_3};
    EXPECT_FALSE(capability->IsMatchPhotoProfiles(profiles));
}

/*
 * Feature: Framework
 * Function: Test CameraOutputCapability with IsMatchPreviewProfiles
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraOutputCapability with IsMatchPreviewProfiles if no match occurs
 */
HWTEST_F(CameraOutputCapabilityUnit, camera_output_capability_unittest_004, TestSize.Level0)
{
    CameraFormat previewFormat = CAMERA_FORMAT_YUV_420_SP;
    Size previewSize = {480, 640};
    Size size = {640, 480};
    Profile previewProfile_1 = Profile(previewFormat, previewSize);
    Profile previewProfile_2 = Profile(previewFormat, size);
    Profile previewProfile_3 = Profile(CAMERA_FORMAT_INVALID, size);

    std::shared_ptr<CameraOutputCapability> capability = std::make_shared<CameraOutputCapability>();
    ASSERT_NE(capability, nullptr);

    capability->SetPreviewProfiles({previewProfile_1, previewProfile_2});
    std::vector<Profile> profiles = {previewProfile_3};
    EXPECT_FALSE(capability->IsMatchPreviewProfiles({profiles}));
}

/*
 * Feature: Framework
 * Function: Test CameraOutputCapability with RemoveDuplicatesProfiles
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test CameraOutputCapability with RemoveDuplicatesProfiles for normal branches
 */
HWTEST_F(CameraOutputCapabilityUnit, camera_output_capability_unittest_005, TestSize.Level0)
{
    CameraFormat format = CAMERA_FORMAT_YUV_420_SP;
    Size size = {480, 640};
    Size size_2 = {640, 480};
    Profile profile_1 = Profile(format, size);
    Profile profile_2 = Profile(format, size_2);
    Profile profile_3 = Profile(CAMERA_FORMAT_INVALID, size_2);

    std::shared_ptr<CameraOutputCapability> capability = std::make_shared<CameraOutputCapability>();
    ASSERT_NE(capability, nullptr);

    std::vector<Profile> profiles = {};
    capability->SetPhotoProfiles(profiles);
    capability->RemoveDuplicatesProfiles();
    EXPECT_TRUE(capability->GetPhotoProfiles().empty());

    profiles = {profile_1, profile_2, profile_3};
    capability->SetPhotoProfiles(profiles);
    capability->RemoveDuplicatesProfiles();
    EXPECT_EQ(capability->GetPhotoProfiles().size(), 3);

    profiles = {profile_1, profile_2, profile_2};
    capability->SetPhotoProfiles(profiles);
    capability->RemoveDuplicatesProfiles();
    EXPECT_EQ(capability->GetPhotoProfiles().size(), 2);

    profiles = {profile_1, profile_1, profile_1};
    capability->SetPhotoProfiles(profiles);
    capability->RemoveDuplicatesProfiles();
    EXPECT_EQ(capability->GetPhotoProfiles().size(), 1);
}

}
}