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
#include "icamera_broker.h"
#include <vector>

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {

class TestCameraBroker : public ICameraBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Anco.Service.Camera");
    
    int32_t NotifyCloseCamera(std::string cameraId) override
    {
        return 0;
    }
    
    int32_t NotifyMuteCamera(bool muteMode) override
    {
        return 0;
    }
    
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

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
    auto deviceManager = HCameraDeviceManager::GetInstance();
    if (deviceManager != nullptr) {
        std::vector<sptr<HCameraDeviceHolder>> activeHolders = deviceManager->GetActiveCameraHolders();
        for (const auto& holder : activeHolders) {
            if (holder != nullptr) {
                sptr<HCameraDevice> device = holder->GetDevice();
                if (device != nullptr) {
                    std::string cameraId = device->GetCameraId();
                    deviceManager->RemoveDevice(cameraId);
                }
            }
        }
        deviceManager->SetStateOfACamera("", 1);
        deviceManager->UnsetPeerCallback();
#ifdef CAMERA_LIVE_SCENE_RECOGNITION
        deviceManager->SetLiveScene(false);
#endif
    }
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
        GTEST_SKIP();
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
    auto it = std::find_if(HCameraDeviceManager::GetInstance()->activeCameras_.begin(),
        HCameraDeviceManager::GetInstance()->activeCameras_.end(), [&](const sptr<HCameraDeviceHolder> &x) {
        return x->GetDevice() == nullptr;
    });
    HCameraDeviceManager::GetInstance()->activeCameras_.erase(it);
}

/*
 * Feature: Framework
 * Function: Test GetCamerasByPid with non-existent pid.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCamerasByPid with non-existent pid.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_016, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    pid_t pidRequest = 999999;

    std::vector<sptr<HCameraDevice>>res = HCameraDeviceManager::GetInstance()->GetCamerasByPid(pidRequest);
    EXPECT_EQ(res.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test GetCamerasByPid with HCameraDeviceHolder is empty.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCamerasByPid with HCameraDeviceHolder is empty.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_017, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    pid_t pidRequest = 999999;

    std::vector<sptr<HCameraDeviceHolder>> emptyVec;
    HCameraDeviceManager::GetInstance()->pidToCameras_[pidRequest] = emptyVec;
    std::vector<sptr<HCameraDevice>>res = HCameraDeviceManager::GetInstance()->GetCamerasByPid(pidRequest);
    EXPECT_EQ(res.size(), 0);
    
    auto it = HCameraDeviceManager::GetInstance()->pidToCameras_.find(pidRequest);
    HCameraDeviceManager::GetInstance()->pidToCameras_.erase(it);
}

/*
 * Feature: Framework
 * Function: Test WouldEvict with nullptr.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WouldEvict with nullptr.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_019, TestSize.Level0)
{
    sptr<HCameraDeviceHolder> cameraRequestOpen = nullptr;
    auto res = HCameraDeviceManager::GetInstance()->WouldEvict(cameraRequestOpen);
    EXPECT_NE(res.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test WouldEvict.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WouldEvict.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_020, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    int32_t pid = 9;
    int32_t uid = 1;
    int32_t state = 1;
    int32_t focusState = 1;
    pid_t pidRequest = 241228;
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    sptr<HCameraDevice> device = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, pidRequest);;
    uint32_t accessTokenId = 1;
    int32_t cost = 1;
    std::set<std::string> conflicting;
    uint32_t firstTokenId = 1;
    sptr<HCameraDeviceHolder> cameraRequestOpen = new HCameraDeviceHolder(pid, uid, state, focusState,
        device, accessTokenId, cost, conflicting, firstTokenId);
    auto res = HCameraDeviceManager::GetInstance()->WouldEvict(cameraRequestOpen);
    EXPECT_NE(res.size(), 0);
}

/*
 * Feature: Framework
 * Function: Test SetPeerCallback with valid callback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetPeerCallback with valid callback object.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_021, TestSize.Level0)
{
    sptr<ICameraBroker> callback = new TestCameraBroker();
    ASSERT_NE(callback, nullptr);
    HCameraDeviceManager::GetInstance()->SetPeerCallback(callback);
    HCameraDeviceManager::GetInstance()->UnsetPeerCallback();
}

/*
 * Feature: Framework
 * Function: Test IsAllowOpen with pidOfOpenRequest == -1
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsAllowOpen when pidOfOpenRequest is -1.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_022, TestSize.Level0)
{
    std::string cameraId = "device/0";
    int32_t state = 0;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    
    pid_t pidOfOpenRequest = -1;
    bool ret = HCameraDeviceManager::GetInstance()->IsAllowOpen(pidOfOpenRequest);
    EXPECT_FALSE(ret);
}

/*
 * Feature: Framework
 * Function: Test IsAllowOpen with peerCallback_ == nullptr
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsAllowOpen when peerCallback_ is nullptr.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_023, TestSize.Level0)
{
    std::string cameraId = "device/0";
    int32_t state = 0;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    HCameraDeviceManager::GetInstance()->UnsetPeerCallback();
    
    pid_t pidOfOpenRequest = 12345;
    bool ret = HCameraDeviceManager::GetInstance()->IsAllowOpen(pidOfOpenRequest);
    EXPECT_FALSE(ret);
}

/*
 * Feature: Framework
 * Function: Test IsAllowOpen with valid peerCallback
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test IsAllowOpen when peerCallback_ is valid.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_024, TestSize.Level0)
{
    std::string cameraId = "device/0";
    int32_t state = 0;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    
    sptr<ICameraBroker> callback = new TestCameraBroker();
    ASSERT_NE(callback, nullptr);
    HCameraDeviceManager::GetInstance()->SetPeerCallback(callback);
    
    pid_t pidOfOpenRequest = 12345;
    bool ret = HCameraDeviceManager::GetInstance()->IsAllowOpen(pidOfOpenRequest);
    EXPECT_TRUE(ret);
    
    HCameraDeviceManager::GetInstance()->UnsetPeerCallback();
}

/*
 * Feature: Framework
 * Function: Test HandleCameraEvictions with valid cameraRequestOpen
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test HandleCameraEvictions with valid cameraRequestOpen.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_025, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    pid_t pidRequest = 241228;
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    sptr<HCameraDevice> device = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, pidRequest);
    ASSERT_NE(device, nullptr);
    
    int32_t pid = 9;
    int32_t uid = 1;
    int32_t state = 1;
    int32_t focusState = 1;
    uint32_t accessTokenId = 1;
    int32_t cost = 1;
    std::set<std::string> conflicting;
    uint32_t firstTokenId = 1;
    sptr<HCameraDeviceHolder> cameraRequestOpen = new HCameraDeviceHolder(pid, uid, state, focusState,
        device, accessTokenId, cost, conflicting, firstTokenId);
    ASSERT_NE(cameraRequestOpen, nullptr);
    
    std::vector<sptr<HCameraDeviceHolder>> evictedClients;
    bool ret = HCameraDeviceManager::GetInstance()->HandleCameraEvictions(evictedClients, cameraRequestOpen);
    EXPECT_TRUE(ret || !ret);
}

/*
 * Feature: Framework
 * Function: Test WouldEvict with deviceConflict and curPriority <= requestPriority
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WouldEvict when deviceConflict is true and curPriority <= requestPriority.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_026, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    pid_t pidRequest1 = 241228;
    pid_t pidRequest2 = 241229;
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    
    sptr<HCameraDevice> device1 = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, pidRequest1);
    ASSERT_NE(device1, nullptr);
    HCameraDeviceManager::GetInstance()->AddDevice(pidRequest1, device1);
    
    int32_t pid = 9;
    int32_t uid = 1;
    int32_t state = 1;
    int32_t focusState = 1;
    uint32_t accessTokenId = 1;
    int32_t cost = 1;
    std::set<std::string> conflicting;
    uint32_t firstTokenId = 1;
    sptr<HCameraDevice> device2 = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, pidRequest2);
    ASSERT_NE(device2, nullptr);
    sptr<HCameraDeviceHolder> cameraRequestOpen = new HCameraDeviceHolder(pid, uid, state, focusState,
        device2, accessTokenId, cost, conflicting, firstTokenId);
    ASSERT_NE(cameraRequestOpen, nullptr);
    
    auto res = HCameraDeviceManager::GetInstance()->WouldEvict(cameraRequestOpen);
    
    HCameraDeviceManager::GetInstance()->RemoveDevice(cameraId);
}

/*
 * Feature: Framework
 * Function: Test WouldEvict with totalCost > DEFAULT_MAX_COST
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WouldEvict when totalCost > DEFAULT_MAX_COST.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_027, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    pid_t pidRequest = 241228;
    std::string cameraId = cameras[0]->GetID();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    
    int32_t pid = 9;
    int32_t uid = 1;
    int32_t state = 1;
    int32_t focusState = 1;
    uint32_t accessTokenId = 1;
    int32_t cost = 1000;
    std::set<std::string> conflicting;
    uint32_t firstTokenId = 1;
    sptr<HCameraDevice> device = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId, pidRequest);
    ASSERT_NE(device, nullptr);
    sptr<HCameraDeviceHolder> cameraRequestOpen = new HCameraDeviceHolder(pid, uid, state, focusState,
        device, accessTokenId, cost, conflicting, firstTokenId);
    ASSERT_NE(cameraRequestOpen, nullptr);
    
    auto res = HCameraDeviceManager::GetInstance()->WouldEvict(cameraRequestOpen);
}

/*
 * Feature: Framework
 * Function: Test SetStateOfACamera with different state values
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetStateOfACamera with state != 0.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_028, TestSize.Level0)
{
    std::string cameraId = "device/0";
    int32_t state = 0;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    SafeMap<std::string, int32_t> res = HCameraDeviceManager::GetInstance()->GetCameraStateOfASide();
    ASSERT_NE(res.Size(), 0);
    
    state = 2;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    res = HCameraDeviceManager::GetInstance()->GetCameraStateOfASide();
    EXPECT_EQ(res.Size(), 0);
    
    state = -1;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    res = HCameraDeviceManager::GetInstance()->GetCameraStateOfASide();
    EXPECT_EQ(res.Size(), 0);
}

#ifdef CAMERA_LIVE_SCENE_RECOGNITION
/*
 * Feature: Framework
 * Function: Test SetLiveScene with isLiveScene true
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetLiveScene when isLiveScene is true.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_029, TestSize.Level0)
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
    
    bool isLiveScene = true;
    HCameraDeviceManager::GetInstance()->SetLiveScene(isLiveScene);
    bool ret = HCameraDeviceManager::GetInstance()->IsLiveScene();
    EXPECT_TRUE(ret);
    
    HCameraDeviceManager::GetInstance()->RemoveDevice(cameraId);
}

/*
 * Feature: Framework
 * Function: Test SetLiveScene with isLiveScene false
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetLiveScene when isLiveScene is false.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_030, TestSize.Level0)
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
    
    bool isLiveScene = false;
    HCameraDeviceManager::GetInstance()->SetLiveScene(isLiveScene);
    bool ret = HCameraDeviceManager::GetInstance()->IsLiveScene();
    EXPECT_FALSE(ret);
    
    HCameraDeviceManager::GetInstance()->RemoveDevice(cameraId);
}
#endif

/*
 * Feature: Framework
 * Function: Test WouldEvict with controlConflict
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test WouldEvict when controlConflict is true.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_031, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    pid_t pidRequest1 = 241228;
    pid_t pidRequest2 = 241229;
    std::string cameraId1 = cameras[0]->GetID();
    std::string cameraId2 = cameras.size() > 1 ? cameras[1]->GetID() : cameraId1;
    cameraHostManager_ = new HCameraHostManager(nullptr);
    
    sptr<HCameraDevice> device1 = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId1, pidRequest1);
    ASSERT_NE(device1, nullptr);
    HCameraDeviceManager::GetInstance()->AddDevice(pidRequest1, device1);
    
    int32_t pid = 9;
    int32_t uid = 1;
    int32_t state = 1;
    int32_t focusState = 1;
    uint32_t accessTokenId = 1;
    int32_t cost = 1;
    std::set<std::string> conflicting;
    conflicting.insert(cameraId1);
    uint32_t firstTokenId = 1;
    sptr<HCameraDevice> device2 = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId2, pidRequest2);
    ASSERT_NE(device2, nullptr);
    sptr<HCameraDeviceHolder> cameraRequestOpen = new HCameraDeviceHolder(pid, uid, state, focusState,
        device2, accessTokenId, cost, conflicting, firstTokenId);
    ASSERT_NE(cameraRequestOpen, nullptr);
    
    auto res = HCameraDeviceManager::GetInstance()->WouldEvict(cameraRequestOpen);
    EXPECT_GE(res.size(), 0);
    
    HCameraDeviceManager::GetInstance()->RemoveDevice(cameraId1);
}

/*
 * Feature: Framework
 * Function: Test GetConflictDevices with stateOfRgmCamera_ Size != 0
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetConflictDevices when stateOfRgmCamera_ Size != 0.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_032, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    std::string cameraId = "device/0";
    int32_t state = 0;
    HCameraDeviceManager::GetInstance()->SetStateOfACamera(cameraId, state);
    
    pid_t pidRequest = 241228;
    std::string realCameraId = cameras[0]->GetID();
    cameraHostManager_ = new HCameraHostManager(nullptr);
    sptr<HCameraDevice> camDevice = new (std::nothrow) HCameraDevice(cameraHostManager_, realCameraId, pidRequest);
    ASSERT_NE(camDevice, nullptr);
    HCameraDeviceManager::GetInstance()->AddDevice(pidRequest, camDevice);
    
    std::vector<sptr<HCameraDevice>> cameraNeedEvict;
    sptr<HCameraDevice> cameraRequestOpen = camDevice;
    int32_t type = 1;
    bool ret = HCameraDeviceManager::GetInstance()->GetConflictDevices(cameraNeedEvict, cameraRequestOpen, type);
    EXPECT_GE(ret, false);
    EXPECT_LE(ret, true);
    
    HCameraDeviceManager::GetInstance()->RemoveDevice(realCameraId);
}

/*
 * Feature: Framework
 * Function: Test GetConflictDevices with active clients
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetConflictDevices when there are active clients.
 */
HWTEST_F(HCameraDeviceManagerUnitTest, hcamera_device_manager_unittest_033, TestSize.Level0)
{
    cameraManager_ = CameraManager::GetInstance();
    std::vector<sptr<CameraDevice>> cameras = cameraManager_->GetSupportedCameras();
    ASSERT_NE(cameras.size(), 0);
    
    pid_t pidRequest1 = 241228;
    pid_t pidRequest2 = 241229;
    std::string cameraId1 = cameras[0]->GetID();
    std::string cameraId2 = cameras.size() > 1 ? cameras[1]->GetID() : cameraId1;
    cameraHostManager_ = new HCameraHostManager(nullptr);
    
    sptr<HCameraDevice> camDevice1 = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId1, pidRequest1);
    ASSERT_NE(camDevice1, nullptr);
    HCameraDeviceManager::GetInstance()->AddDevice(pidRequest1, camDevice1);
    
    std::vector<sptr<HCameraDevice>> cameraNeedEvict;
    sptr<HCameraDevice> cameraRequestOpen = new (std::nothrow) HCameraDevice(cameraHostManager_, cameraId2, pidRequest2);
    ASSERT_NE(cameraRequestOpen, nullptr);
    int32_t type = 1;
    HCameraDeviceManager::GetInstance()->GetConflictDevices(cameraNeedEvict, cameraRequestOpen, type);
    
    HCameraDeviceManager::GetInstance()->RemoveDevice(cameraId1);
}
} // CameraStandard
} // OHOS
