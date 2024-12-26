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

#include "deferred_photo_proxy_unittest.h"

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

void DeferredPhotoProxyUnit::SetUpTestCase(void) {}

void DeferredPhotoProxyUnit::TearDownTestCase(void) {}

void DeferredPhotoProxyUnit::SetUp()
{
    NativeAuthorization();
}

void DeferredPhotoProxyUnit::TearDown() {}

void DeferredPhotoProxyUnit::NativeAuthorization()
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
    MEDIA_DEBUG_LOG("DeferredPhotoProxyUnit::NativeAuthorization uid:%{public}d", uid_);
    SetSelfTokenID(tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy when destruction
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy when destruction and isMmaped is false
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_001, TestSize.Level0)
{
    auto proxy = std::make_shared<DeferredPhotoProxy>();
    ASSERT_NE(proxy, nullptr);
    proxy->Release();
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy when destruction
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy when destruction and isMmaped is true
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_002, TestSize.Level0)
{
    auto proxy = std::make_shared<DeferredPhotoProxy>();
    ASSERT_NE(proxy, nullptr);
    proxy->isMmaped_ = true;
    proxy->Release();
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy when GetDeferredProcType
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy with GetDeferredProcType when deferredProcType_ is 0 or 1
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_003, TestSize.Level0)
{
    auto proxy = std::make_shared<DeferredPhotoProxy>();
    ASSERT_NE(proxy, nullptr);
    Media::DeferredProcType ret = proxy->GetDeferredProcType();
    EXPECT_EQ(ret, Media::DeferredProcType::BACKGROUND);

    proxy->deferredProcType_ = 1;
    ret = proxy->GetDeferredProcType();
    EXPECT_EQ(ret, Media::DeferredProcType::OFFLINE);
}

/*
 * Feature: Framework
 * Function: Test DeferredPhotoProxy when GetFileDataAddr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test DeferredPhotoProxy with GetFileDataAddr when isMmaped_ is true
 */
HWTEST_F(DeferredPhotoProxyUnit, deferred_photo_proxy_unittest_004, TestSize.Level0)
{
    auto proxy = std::make_shared<DeferredPhotoProxy>();
    ASSERT_NE(proxy, nullptr);
    proxy->isMmaped_ = true;
    void* ret = proxy->GetFileDataAddr();
    EXPECT_EQ(ret, proxy->fileDataAddr_);
}

}
}