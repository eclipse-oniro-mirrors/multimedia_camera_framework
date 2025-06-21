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

#include <cstdint>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "camera_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "metadata_utils.h"
#include "moon_capture_boost_feature_unittest.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "sketch_wrapper.h"
#include "surface.h"
#include "test_common.h"
#include "test_token.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
void MoonCaptureBoostUnitTest::SetUpTestCase(void)
{
    ASSERT_TRUE(TestToken::GetAllCameraPermission());
}

void MoonCaptureBoostUnitTest::TearDownTestCase(void) {}

void MoonCaptureBoostUnitTest::SetUp()
{
    cameraManager_ = CameraManager::GetInstance();
    ASSERT_NE(cameraManager_, nullptr);
}

void MoonCaptureBoostUnitTest::TearDown()
{
    cameraManager_ = nullptr;
    MEDIA_DEBUG_LOG("MoonCaptureBoostUnitTest TearDown");
}

/*
 * Feature: Framework
 * Function: Test MoonCaptureBoostFeature with GetSketchReferenceFovRatio, GetSketchEnableRatio
 * IsVideoDeferred
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetSketchReferenceFovRatio, GetSketchEnableRatio for just call.
 */
HWTEST_F(MoonCaptureBoostUnitTest, moon_capture_boost_function_unittest_001, TestSize.Level1)
{
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    SceneMode relatedMode = NORMAL;
    auto cameraProxy = CameraManager::g_cameraManager->GetServiceProxy();
    ASSERT_NE(cameraProxy, nullptr);
    std::shared_ptr<OHOS::Camera::CameraMetadata> metadata;
    std::string cameraId = cameras[0]->GetID();
    cameraProxy->GetCameraAbility(cameraId, metadata);
    ASSERT_NE(metadata, nullptr);
    std::shared_ptr<MoonCaptureBoostFeature> moonCapture = std::make_shared<MoonCaptureBoostFeature>(relatedMode,
        metadata);
    ASSERT_NE(moonCapture, nullptr);
    float zoomMin = -1.0f;
    moonCapture->GetSketchReferenceFovRatio(zoomMin);
    moonCapture->sketchZoomRatioRange_.zoomMin = zoomMin;
    EXPECT_EQ(moonCapture->GetSketchEnableRatio(), zoomMin);
}
}
}