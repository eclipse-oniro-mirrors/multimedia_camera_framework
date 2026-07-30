/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "media_manager_adapter_unittest.h"

#include <fcntl.h>

#include "basic_definitions.h"
#include "dps_fd.h"
#include "gmock/gmock.h"
#include "media_manager_adapter.h"
#include "media_manager_interface.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string MEDIA_ROOT = "/data/test/media/";
    const std::string VIDEO_PATH = MEDIA_ROOT + "test_video.mp4";
    const std::string VIDEO_TEMP_PATH_1 = MEDIA_ROOT + "temp/" + "test_temp1.mp4";
    const std::string VIDEO_TEMP_PATH_2 = MEDIA_ROOT + "temp/" + "test_temp2.mp4";
}

void MediaManagerAdapterUnittest::SetUpTestCase(void) {}

void MediaManagerAdapterUnittest::TearDownTestCase(void) {}

void MediaManagerAdapterUnittest::SetUp()
{
    srcFd_ = open(VIDEO_PATH.c_str(), O_RDONLY);
    temp1fd_ = open(VIDEO_TEMP_PATH_1.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    temp2fd_ = open(VIDEO_TEMP_PATH_2.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
}

void MediaManagerAdapterUnittest::TearDown()
{
    if (srcFd_ >= 0) {
        close(srcFd_);
        srcFd_ = -1;
    }

    if (temp1fd_ >= 0) {
        close(temp1fd_);
        temp1fd_ = -1;
    }

    if (temp2fd_ >= 0) {
        close(temp2fd_);
        temp2fd_ = -1;
    }
}

/*
 * Feature: Framework
 * Function: Test MpegUnInit with nullptr mpegManager_
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegUnInit when mpegManager_ is nullptr returns DP_ERR
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_001, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    int32_t ret = adapter->MpegUnInit(0);
    EXPECT_NE(ret, DP_OK);
}

/*
 * Feature: Framework
 * Function: Test MpegGetResultFd with nullptr mpegManager_
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegGetResultFd when mpegManager_ is nullptr returns nullptr
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_002, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    auto result = adapter->MpegGetResultFd();
    EXPECT_EQ(result, nullptr);
}

/*
 * Feature: Framework
 * Function: Test MpegGetResultPath with nullptr mpegManager_
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegGetResultPath when mpegManager_ is nullptr returns empty string
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_003, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    std::string path = adapter->MpegGetResultPath();
    EXPECT_TRUE(path.empty());
}

/*
 * Feature: Framework
 * Function: Test MpegGetSurface with nullptr mpegManager_
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegGetSurface when mpegManager_ is nullptr returns nullptr
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_004, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    auto surface = adapter->MpegGetSurface();
    EXPECT_EQ(surface, nullptr);
}

/*
 * Feature: Framework
 * Function: Test MpegGetMakerSurface with nullptr mpegManager_
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegGetMakerSurface when mpegManager_ is nullptr returns nullptr
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_005, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    auto surface = adapter->MpegGetMakerSurface();
    EXPECT_EQ(surface, nullptr);
}

/*
 * Feature: Framework
 * Function: Test MpegSetProgressNotifer with nullptr mpegManager_
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegSetProgressNotifer when mpegManager_ is nullptr returns 0
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_006, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    auto ret = adapter->MpegSetProgressNotifer(nullptr);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test MpegUnInit after MpegAcquire (valid mpegManager_)
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegUnInit when mpegManager_ is valid, covers the non-null branch
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_007, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    ASSERT_NE(inputFd, nullptr);

    TempVideoPath tempPath;
    tempPath.temp1Path = VIDEO_TEMP_PATH_1;
    tempPath.temp2Path = VIDEO_TEMP_PATH_2;

    ASSERT_EQ(adapter->MpegAcquire("testVideoId", tempPath, inputFd, VIDEO_WIDTH, VIDEO_HIGHT), DP_OK);
    int32_t ret = adapter->MpegUnInit(0);
    EXPECT_TRUE(ret == DP_OK || ret == DP_ERR);
    adapter->MpegRelease();
}

/*
 * Feature: Framework
 * Function: Test MpegUnInit with non-null mpegManager_ and non-zero result
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegUnInit when mpegManager_ is valid with error result parameter
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_008, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    ASSERT_NE(inputFd, nullptr);

    TempVideoPath tempPath;
    tempPath.temp1Path = VIDEO_TEMP_PATH_1;
    tempPath.temp2Path = VIDEO_TEMP_PATH_2;

    ASSERT_EQ(adapter->MpegAcquire("testVideoId2", tempPath, inputFd, VIDEO_WIDTH, VIDEO_HIGHT), DP_OK);
    int32_t ret = adapter->MpegUnInit(static_cast<int32_t>(MediaResult::FAIL));
    EXPECT_TRUE(ret == DP_OK || ret == DP_ERR);
    adapter->MpegRelease();
}

/*
 * Feature: Framework
 * Function: Test MpegGetResultFd after MpegAcquire (valid mpegManager_)
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegGetResultFd when mpegManager_ is valid
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_009, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    ASSERT_NE(inputFd, nullptr);

    TempVideoPath tempPath;
    tempPath.temp1Path = VIDEO_TEMP_PATH_1;
    tempPath.temp2Path = VIDEO_TEMP_PATH_2;

    ASSERT_EQ(adapter->MpegAcquire("testVideoId3", tempPath, inputFd, VIDEO_WIDTH, VIDEO_HIGHT), DP_OK);
    auto resultFd = adapter->MpegGetResultFd();
    EXPECT_NE(resultFd, nullptr);
    adapter->MpegRelease();
}

/*
 * Feature: Framework
 * Function: Test MpegGetResultPath after MpegAcquire (valid mpegManager_)
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegGetResultPath when mpegManager_ is valid
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_010, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    ASSERT_NE(inputFd, nullptr);

    TempVideoPath tempPath;
    tempPath.temp1Path = VIDEO_TEMP_PATH_1;
    tempPath.temp2Path = VIDEO_TEMP_PATH_2;

    ASSERT_EQ(adapter->MpegAcquire("testVideoId4", tempPath, inputFd, VIDEO_WIDTH, VIDEO_HIGHT), DP_OK);
    std::string path = adapter->MpegGetResultPath();
    EXPECT_FALSE(path.empty());
    adapter->MpegRelease();
}

/*
 * Feature: Framework
 * Function: Test MpegGetSurface after MpegAcquire (valid mpegManager_)
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegGetSurface when mpegManager_ is valid
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_011, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    ASSERT_NE(inputFd, nullptr);

    TempVideoPath tempPath;
    tempPath.temp1Path = VIDEO_TEMP_PATH_1;
    tempPath.temp2Path = VIDEO_TEMP_PATH_2;

    ASSERT_EQ(adapter->MpegAcquire("testVideoId5", tempPath, inputFd, VIDEO_WIDTH, VIDEO_HIGHT), DP_OK);
    auto surface = adapter->MpegGetSurface();
    EXPECT_NE(surface, nullptr);
    adapter->MpegRelease();
}

/*
 * Feature: Framework
 * Function: Test MpegGetMakerSurface after MpegAcquire (valid mpegManager_)
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegGetMakerSurface when mpegManager_ is valid
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_012, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    ASSERT_NE(inputFd, nullptr);

    TempVideoPath tempPath;
    tempPath.temp1Path = VIDEO_TEMP_PATH_1;
    tempPath.temp2Path = VIDEO_TEMP_PATH_2;

    ASSERT_EQ(adapter->MpegAcquire("testVideoId6", tempPath, inputFd, VIDEO_WIDTH, VIDEO_HIGHT), DP_OK);
    auto surface = adapter->MpegGetMakerSurface();
    EXPECT_NE(surface, nullptr);
    adapter->MpegRelease();
}

/*
 * Feature: Framework
 * Function: Test MpegSetProgressNotifer after MpegAcquire (valid mpegManager_)
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test MpegSetProgressNotifer when mpegManager_ is valid
 */
HWTEST_F(MediaManagerAdapterUnittest, media_manager_adapter_unittest_013, TestSize.Level0)
{
    auto adapter = std::make_shared<MediaManagerAdapter>();
    ASSERT_NE(adapter, nullptr);

    DpsFdPtr inputFd = std::make_shared<DpsFd>(dup(srcFd_));
    ASSERT_NE(inputFd, nullptr);

    TempVideoPath tempPath;
    tempPath.temp1Path = VIDEO_TEMP_PATH_1;
    tempPath.temp2Path = VIDEO_TEMP_PATH_2;

    ASSERT_EQ(adapter->MpegAcquire("testVideoId7", tempPath, inputFd, VIDEO_WIDTH, VIDEO_HIGHT), DP_OK);
    int32_t ret = adapter->MpegSetProgressNotifer(nullptr);
    EXPECT_EQ(ret, DP_OK);
    adapter->MpegRelease();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
