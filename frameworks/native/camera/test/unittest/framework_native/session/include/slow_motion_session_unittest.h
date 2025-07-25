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

#ifndef SLOW_MOTION_SESSION_UNITTEST_H
#define SLOW_MOTION_SESSION_UNITTEST_H

#include <cmath>

#include "camera_log.h"
#include "camera_manager.h"
#include "gtest/gtest.h"
#include "slow_motion_session.h"

namespace OHOS {
namespace CameraStandard {
class CameraSlowMotionSessionUnitTest : public testing::Test {
public:
    /* SetUpTestCase:The preset action of the test suite is executed before the first TestCase */
    static void SetUpTestCase(void);
    /* TearDownTestCase:The test suite cleanup action is executed after the last TestCase */
    static void TearDownTestCase(void);
    /* SetUp:Execute before each test case */
    void SetUp(void);
    /* TearDown:Execute after each test case */
    void TearDown(void);

    sptr<CaptureOutput> CreatePreviewOutput();
    sptr<CaptureOutput> CreateVideoOutput();

private:
    static bool IsAspectRatioEqual(float a, float b);
    template<typename ToFitProfileTp, typename FitProfileTp>
    std::pair<bool, FitProfileTp> FindSameRatioProfile(ToFitProfileTp toFitProfile, std::vector<FitProfileTp>& profiles)
    {
        FitProfileTp resProfile;
        auto size = toFitProfile.GetSize();
        if (size.height == 0) {
            return { false, {} };
        }
        float toFitRatio = static_cast<float>(size.width) / size.height;
        for (auto& profile : profiles) {
            auto theSize = profile.GetSize();
            if (theSize.height == 0) {
                continue;
            }
            bool isEqual = IsAspectRatioEqual(static_cast<float>(theSize.width) / theSize.height, toFitRatio);
            if (isEqual) {
                resProfile = profile;
                GTEST_LOG_(INFO) << "find targetProfile: width: " << resProfile.GetSize().width
                                 << ", height: " << resProfile.GetSize().height;
                break;
            }
        }
        return { resProfile.GetSize().height != 0, resProfile };
    }

    uint64_t tokenId_ = 0;
    int32_t uid_ = 0;
    int32_t userId_ = 0;
    sptr<CameraManager> cameraManager_ = nullptr;
    std::vector<Profile> previewProfile_;
    std::vector<VideoProfile> profile_;
    bool preIsSupportedSlowmode_ = false;
    bool vidIsSupportedSlowmode_ = false;
    Profile savedPreviewProfile_;
    VideoProfile savedVideoProfile_;
};

class MockSlowMotionStateCallback : public OHOS::CameraStandard::SlowMotionStateCallback {
    void OnSlowMotionState(const SlowMotionState state) override {}
};
}
}

#endif