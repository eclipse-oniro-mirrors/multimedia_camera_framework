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

#include "camera_app_manager_client_unittest.h"
#include "camera_app_manager_client.h"
#include "camera_log.h"
#include "hcamera_service.h"
#include "ipc_skeleton.h"

using namespace testing::ext;
namespace OHOS {
namespace CameraStandard {
using namespace OHOS::HDI::Camera::V1_1;
void CameraAppManagerClientUnit::SetUpTestCase(void) {}

void CameraAppManagerClientUnit::TearDownTestCase(void) {}

void CameraAppManagerClientUnit::SetUp() {}

void CameraAppManagerClientUnit::TearDown() {}


/*
 * Feature: Framework
 * Function: Test CameraAppManagerClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the behavior of CameraAppManagerClient when the instance is set to nullptr and then
 *re-obtained. The expected result is that the instance should be re-created and not be nullptr.
 */
HWTEST_F(CameraAppManagerClientUnit, camera_app_manager_client_unittest_001, TestSize.Level1)
{
    sptr<CameraAppManagerClient> client = CameraAppManagerClient::GetInstance();
    ASSERT_NE(client, nullptr);
    client->cameraAppManagerClient_ = nullptr;
    client->GetInstance();
    ASSERT_NE(client->cameraAppManagerClient_, nullptr);
}

/*
 * Feature: Framework
 * Function: CameraAppManagerClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the behavior of CameraAppManagerClient when the instance is set to itself and then re-obtained.
 *The expected result is that the instance should remain valid and not be nullptr.
 */
HWTEST_F(CameraAppManagerClientUnit, camera_app_manager_client_unittest_002, TestSize.Level1)
{
    sptr<CameraAppManagerClient> client = CameraAppManagerClient::GetInstance();
    ASSERT_NE(client, nullptr);
    client->cameraAppManagerClient_ = client;
    client->GetInstance();
    ASSERT_NE(client->cameraAppManagerClient_, nullptr);
}

/*
 * Feature: Framework
 * Function: CameraAppManagerClient
 * SubFunction: GetProcessState
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test the behavior of CameraAppManagerClient::GetProcessState with valid and invalid process IDs.
 * The expected result is that the method should return the correct state for valid PIDs and -1 for invalid PIDs.
 */
HWTEST_F(CameraAppManagerClientUnit, camera_app_manager_client_unittest_003, TestSize.Level0)
{
    sptr<CameraAppManagerClient> client = CameraAppManagerClient::GetInstance();
    ASSERT_NE(client, nullptr);

    int32_t Pid = 1234; 
    AppExecFwk::RunningProcessInfo runningProcessstate;
    std::shared_ptr<AppExecFwk::AppMgrClient> appMgrHolder_ = std::make_shared<AppExecFwk::AppMgrClient>();
    int ret = appMgrHolder_->GetRunningProcessInfoByPid(Pid, runningProcessstate);
    if (ret == CAMERA_OK) {
        EXPECT_EQ(client->GetProcessState(Pid), 0);
    } else {
        EXPECT_EQ(client->GetProcessState(Pid), -1);
    }

}

}
}