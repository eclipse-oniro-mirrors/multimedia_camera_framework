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
#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

sptr<HCameraHostManager> HCameraDeviceManagerUnitTest::cameraHostManager_ = nullptr;

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
 * Function: Test RemoveDevice and GetConflictDevices normal branches while camera device holder is empty.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveDevice and GetConflictDevices abnormal branches while camera device holder is empty.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_001, TestSize.Level0)
{
    std::string cameraId;
    HCameraDeviceManager::GetInstance()->RemoveDevice(cameraId);
    EXPECT_TRUE(HCameraDeviceManager::GetInstance()->activeCameras_.empty());
 
    int32_t state = 1;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    state = 0;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    sptr<ICameraBroker> callback;
    HCameraDeviceManager::GetInstance()->SetPeerCallback(callback);
    HCameraDeviceManager::GetInstance()->UnsetPeerCallback();
 
    std::vector<sptr<HCameraDevice>> cameraNeedEvict;
    sptr<HCameraDevice> cameraRequestOpen;
    int32_t type = 1;
    bool ret = HCameraDeviceManager::GetInstance()->GetConflictDevices(cameraNeedEvict, cameraRequestOpen, type);
    EXPECT_FALSE(ret);
    std::vector<pid_t> pid = HCameraDeviceManager::GetInstance()->GetActiveClient();
    EXPECT_EQ(pid.size(), 0);
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

/*
 * Feature: Framework
 * Function: Test GetCameraHolderByPid.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCameraHolderByPid.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_008, TestSize.Level0)
{
    OHOS::Security::AccessToken::AccessTokenID pidRequest = IPCSkeleton::GetCallingTokenID();
    std::vector<sptr<HCameraDeviceHolder>> res = HCameraDeviceManager::GetInstance()->GetCameraHolderByPid(pidRequest);
    EXPECT_EQ(res.size(), 0);
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, pidRequest);
    ASSERT_NE(camDevice, nullptr);
    HCameraDeviceManager::GetInstance()->AddDevice(pidRequest, camDevice);
    res = HCameraDeviceManager::GetInstance()->GetCameraHolderByPid(pidRequest);
    ASSERT_NE(res.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetCamerasByPid.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCamerasByPid.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_009, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    pid_t pidRequest = 241228;
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, pidRequest);
    ASSERT_NE(camDevice, nullptr);

    HCameraDeviceManager::GetInstance()->AddDevice(pidRequest, camDevice);
    std::vector<sptr<HCameraDevice>>res = HCameraDeviceManager::GetInstance()->GetCamerasByPid(pidRequest);
    ASSERT_NE(res.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetActiveClient.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetActiveClient.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_010, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    vector<pid_t>res = HCameraDeviceManager::GetInstance()->GetActiveClient();
    ASSERT_NE(res.size(), 0);

    for (auto x:cameras) {
        HCameraDeviceManager::GetInstance()->RemoveDevice(x->GetID());
    }
    HCameraDeviceManager::GetInstance()->pidToCameras_.clear();
    res = HCameraDeviceManager::GetInstance()->GetActiveClient();
    EXPECT_EQ(res.size(), 0);

    pid_t pidRequest = 241228;
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, pidRequest);
    ASSERT_NE(camDevice, nullptr);

    HCameraDeviceManager::GetInstance()->AddDevice(pidRequest, camDevice);
    res = HCameraDeviceManager::GetInstance()->GetActiveClient();
    ASSERT_NE(res.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test SetStateOfACamera.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStateOfACamera.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_011, TestSize.Level0)
{
    std::string cameraId = "device/0";
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, 1);
    SafeMap<std::string, int32_t> res = HCameraDeviceManager::GetInstance()->GetCameraStateOfASide();
    EXPECT_EQ(res.Size(), 0);

    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, 0);
    res = HCameraDeviceManager::GetInstance()->GetCameraStateOfASide();
    ASSERT_NE(res.Size(), 0);
}

/*
 * Feature: Framework
 * Function: Test RefreshCameraDeviceHolderState.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RefreshCameraDeviceHolderState.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_012, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    pid_t pidRequest = 241228;
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, pidRequest);
    ASSERT_NE(camDevice, nullptr);
    
    HCameraDeviceManager::GetInstance()->AddDevice(pidRequest, camDevice);
    std::vector<sptr<HCameraDeviceHolder>> res = HCameraDeviceManager::GetInstance()->GetCameraHolderByPid(pidRequest);
    if (res.size() == 0) {
        return;
    }
    HCameraDeviceManager::GetInstance()->RefreshCameraDeviceHolderState(res[0]);
}

/*
 * Feature: Framework
 * Function: Test GetACameraId with stateOfRgmCamera_ Size is zero.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetACameraId with stateOfRgmCamera_ Size is zero.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_013, TestSize.Level0)
{
    std::string cameraId = "device/0";
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, 1);
    EXPECT_EQ(HCameraDeviceManager::GetInstance()->GetACameraId(), "");
}

/*
 * Feature: Framework
 * Function: Test IsMultiCameraActive with pid in activeCamera_.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsMultiCameraActive with pid in activeCamera_.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_015, TestSize.Level0)
{
    int32_t pid = 9;
    int32_t uid = 1;
    int32_t state = 1;
    int32_t focusState = 1;
    sptr<HCameraDevice> device = nullptr;
    uint32_t accessTokenId = 1;
    int32_t cost = 1;
    std::set<std::string> conflicting;
    uint32_t firstTokenId = 1;
    sptr<HCameraDeviceHolder> testCamera = new HCameraDeviceHolder(pid, uid, state, focusState,
        device, accessTokenId, cost, conflicting, firstTokenId);
    HCameraDeviceManager::GetInstance()->activeCameras_.push_back(testCamera);
    EXPECT_EQ(HCameraDeviceManager::GetInstance()->IsMultiCameraActive(pid), true);
}
} // CameraStandard
} // OHOS
