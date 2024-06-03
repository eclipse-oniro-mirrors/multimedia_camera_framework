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

#include "camera_deferred_unittest.h"

#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_log.h"
#include "hcamera_service.h"
#include "camera_manager.h"
#include "camera_output_capability.h"
#include "camera_util.h"
#include "capture_output.h"
#include "capture_scene_const.h"
#include "capture_session.h"
#include "gmock/gmock.h"
#include "hap_token_info.h"
#include "input/camera_input.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "nativetoken_kit.h"
#include "night_session.h"
#include "photo_output.h"
#include "photo_session.h"
#include "preview_output.h"
#include "scan_session.h"
#include "secure_camera_session.h"
#include "surface.h"
#include "test_common.h"
#include "token_setproc.h"
#include "video_session.h"
#include "os_account_manager.h"

using namespace testing::ext;
using namespace OHOS::CameraStandard::DeferredProcessing;

namespace OHOS {
namespace CameraStandard {

void DeferredUnitTest::SetUpTestCase(void) {
    MEDIA_DEBUG_LOG("DeferredUnitTest::SetUpTestCase started!");
}

void DeferredUnitTest::TearDownTestCase(void) {
    MEDIA_DEBUG_LOG("DeferredUnitTest::TearDownTestCase started!");
}

void DeferredUnitTest::SetUp() {
    MEDIA_DEBUG_LOG("SetUp testName:%{public}s",
        ::testing::UnitTest::GetInstance()->current_test_info()->name());   
    NativeAuthorization();
}

void DeferredUnitTest::TearDown() {
    MEDIA_DEBUG_LOG("DeferredUnitTest::TearDown started!");
}

void DeferredUnitTest::NativeAuthorization()
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
    g_tokenId_ = GetAccessTokenId(&infoInstance);
    g_uid_ = IPCSkeleton::GetCallingUid();
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(g_uid_, g_userId_);
    MEDIA_DEBUG_LOG("tokenId:%{public}" PRIu64 " uid:%{public}d userId:%{public}d",
        g_tokenId_, g_uid_, g_userId_);
    SetSelfTokenID(g_tokenId_);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

HWTEST_F(DeferredUnitTest, testDeferredProcSession, TestSize.Level0)
{
    sptr<DeferredPhotoProcSession> deferredProcSession;
    deferredProcSession = cameraManager_->CreateDeferredPhotoProcessingSession(g_userId_,
        std::make_shared<TestDeferredPhotoProcSessionCallback>());
    ASSERT_NE(deferredProcSession, nullptr);
    deferredProcSession->BeginSynchronize();

    std::string imageId = "testImageId";
    DpsMetadata metadata;
    bool discardable = true;
    deferredProcSession->AddImage(imageId, metadata, discardable);

    bool restorable = true;
    deferredProcSession->RemoveImage(imageId, restorable);

    deferredProcSession->RestoreImage(imageId);

    std::string appName = "com.cameraFwk.ut";
    deferredProcSession->ProcessImage(appName, imageId);

    deferredProcSession->CancelProcessImage(imageId);

    deferredProcSession->EndSynchronize();
}
} // CameraStandard
} // OHOS