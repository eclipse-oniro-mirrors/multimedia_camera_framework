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

#include "camera_log.h"
#include "deferred_video_job.h"
#include "dps_video_report.h"
#include "dps_video_report_unittest.h"
#include "ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
    
const std::string VIDEO_ID = "videoId";
const std::string VIDEO_SECOND_ID = "videoIdSecond";

void DfxVideoReportUnittest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("DfxVideoReportUnittest::SetUpTestCase started!");
}

void DfxVideoReportUnittest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("DfxVideoReportUnittest::TearDownTestCase started!");
}

void DfxVideoReportUnittest::SetUp()
{
    MEDIA_INFO_LOG("DfxVideoReportUnittest::SetUp started!");
}

void DfxVideoReportUnittest::TearDown()
{
    MEDIA_INFO_LOG("DfxVideoReportUnittest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test ReportAddVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportAddVideoEvent with existent videoId.
 */
HWTEST_F(DfxVideoReportUnittest, ReportAddVideoEvent001, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportAddVideoEvent(videoId, callerInfo);
    EXPECT_TRUE(dfxVideoReport->processVideoInfo_.Find(videoId, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportAddVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportAddVideoEvent with not existent videoId.
 */
HWTEST_F(DfxVideoReportUnittest, ReportAddVideoEvent002, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    const std::string videoIdSec = VIDEO_SECOND_ID;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportAddVideoEvent(videoIdSec, callerInfo);
    EXPECT_TRUE(dfxVideoReport->processVideoInfo_.Find(videoIdSec, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportRemoveVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportRemoveVideoEvent with existent videoId.
 */
HWTEST_F(DfxVideoReportUnittest, ReportRemoveVideoEvent001, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportRemoveVideoEvent(videoId, callerInfo);
    EXPECT_FALSE(dfxVideoReport->processVideoInfo_.Find(videoId, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportRemoveVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportRemoveVideoEvent with not existent videoId.
 */
HWTEST_F(DfxVideoReportUnittest, ReportRemoveVideoEvent002, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    const std::string videoIdSec = VIDEO_SECOND_ID;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportRemoveVideoEvent(videoIdSec, callerInfo);
    EXPECT_FALSE(dfxVideoReport->processVideoInfo_.Find(videoIdSec, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportPauseVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportPauseVideoEvent with existent videoId.
 */
HWTEST_F(DfxVideoReportUnittest, ReportPauseVideoEvent001, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    int32_t pauseReason = 0;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportPauseVideoEvent(videoId, pauseReason);
    EXPECT_TRUE(dfxVideoReport->processVideoInfo_.Find(videoId, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportPauseVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportPauseVideoEvent with not existent videoId.
 */
HWTEST_F(DfxVideoReportUnittest, ReportPauseVideoEvent002, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    const std::string videoIdSec = VIDEO_SECOND_ID;
    int32_t pauseReason = 0;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportPauseVideoEvent(videoIdSec, pauseReason);
    EXPECT_FALSE(dfxVideoReport->processVideoInfo_.Find(videoIdSec, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportResumeVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportResumeVideoEvent with not existent videoId.
 */
HWTEST_F(DfxVideoReportUnittest, ReportResumeVideoEvent001, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    const std::string videoIdSec = VIDEO_SECOND_ID;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportResumeVideoEvent(videoIdSec);
    EXPECT_FALSE(dfxVideoReport->processVideoInfo_.Find(videoIdSec, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportResumeVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportResumeVideoEvent with not existent videoId and processTime = 0.
 */
HWTEST_F(DfxVideoReportUnittest, ReportResumeVideoEvent002, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    videoRecord.processTime = 0;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportResumeVideoEvent(videoId);
    EXPECT_TRUE(dfxVideoReport->processVideoInfo_.Find(videoId, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportResumeVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportResumeVideoEvent with not existent videoId and processTime != 0.
 */
HWTEST_F(DfxVideoReportUnittest, ReportResumeVideoEvent003, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    videoRecord.processTime = 1;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportResumeVideoEvent(videoId);
    EXPECT_TRUE(dfxVideoReport->processVideoInfo_.Find(videoId, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportCompleteVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportCompleteVideoEvent with not existent videoId.
 */
HWTEST_F(DfxVideoReportUnittest, ReportCompleteVideoEvent001, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    const std::string videoIdSec = VIDEO_SECOND_ID;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportCompleteVideoEvent(videoIdSec);
    EXPECT_FALSE(dfxVideoReport->processVideoInfo_.Find(videoIdSec, videoRecord));
    delete dfxVideoReport;
}

/*
 * Feature: Framework
 * Function: Test ReportCompleteVideoEvent.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportCompleteVideoEvent with existent videoId.
 */
HWTEST_F(DfxVideoReportUnittest, ReportCompleteVideoEvent002, TestSize.Level0)
{
    const std::string videoId = VIDEO_ID;
    DpsCallerInfo callerInfo;
    VideoRecord videoRecord;
    auto dfxVideoReport = new DfxVideoReport();
    EXPECT_NE(dfxVideoReport, nullptr);
    dfxVideoReport->processVideoInfo_.EnsureInsert(videoId, videoRecord);
    dfxVideoReport->ReportCompleteVideoEvent(videoId);
    EXPECT_TRUE(dfxVideoReport->processVideoInfo_.Find(videoId, videoRecord));
    delete dfxVideoReport;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS