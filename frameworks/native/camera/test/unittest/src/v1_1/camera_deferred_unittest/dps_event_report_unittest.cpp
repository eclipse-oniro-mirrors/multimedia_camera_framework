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
#include "dps_event_report_unittest.h"
#include "ipc_skeleton.h"

using namespace testing::ext;

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

const uint64_t UINT64_BEGINTIME = 0;
const uint64_t UINT64_ENDTIME = 10;
const int32_t INT32_ONE = 1;
const int32_t USERID = 1;
const std::string IMAGEID = "imageId";
const std::string IMAGEID_SECOND = "imageId_second";

void DpsEventReportUnittest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("DpsEventReportUnittest::SetUpTestCase started!");
}

void DpsEventReportUnittest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("DpsEventReportUnittest::TearDownTestCase started!");
}

void DpsEventReportUnittest::SetUp()
{
    MEDIA_INFO_LOG("DpsEventReportUnittest::SetUp started!");
}

void DpsEventReportUnittest::TearDown()
{
    MEDIA_INFO_LOG("DpsEventReportUnittest::TearDown started!");
}

/*
 * Feature: Framework
 * Function: Test GetTotalTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetTotalTime with correct beginTime and endTime.
 * Expected: return endTime - beginTime = 10.
 */
HWTEST_F(DpsEventReportUnittest, GetTotalTime001, TestSize.Level0)
{
    
    uint64_t beginTime = UINT64_BEGINTIME;
    uint64_t endTime = UINT64_ENDTIME;
    auto ret = DPSEventReport::GetInstance().GetTotalTime(beginTime, endTime);
    EXPECT_EQ(ret, 10);
}

/*
 * Feature: Framework
 * Function: Test GetTotalTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetTotalTime with abnormal beginTime and endTime.
 * Expected: return 0.
 */
HWTEST_F(DpsEventReportUnittest, GetTotalTime002, TestSize.Level0)
{
    uint64_t endTime = UINT64_BEGINTIME;
    uint64_t beginTime = UINT64_ENDTIME;
    auto ret = DPSEventReport::GetInstance().GetTotalTime(beginTime, endTime);
    EXPECT_EQ(ret, 0);
}

/*
 * Feature: Framework
 * Function: Test ReportImageProcessResult.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportImageProcessResult with correct endTime.
 */
HWTEST_F(DpsEventReportUnittest, ReportImageProcessResult001, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    uint64_t endTime = UINT64_ENDTIME;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.imageDoneTimeEndTime = 0;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().ReportImageProcessResult(imageId, userId, endTime);
    EXPECT_EQ(dpsEventInfo.imageDoneTimeEndTime, 0);

}

/*
 * Feature: Framework
 * Function: Test ReportImageProcessResult.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test ReportImageProcessResult with abnormal endTime.
 */
HWTEST_F(DpsEventReportUnittest, ReportImageProcessResult002, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    uint64_t endTime = 0;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.imageDoneTimeEndTime = 0;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().ReportImageProcessResult(imageId, userId, endTime);
    EXPECT_EQ(dpsEventInfo.imageDoneTimeEndTime, 0);
}

/*
 * Feature: Framework
 * Function: Test SetEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetEventInfo which input is userId and imageId with abnormal userId.
 */
HWTEST_F(DpsEventReportUnittest, SetEventInfo001, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    userId = 0;
    DPSEventReport::GetInstance().SetEventInfo(imageId, userId);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo.find(0) !=
        DPSEventReport::GetInstance().userIdToImageIdEventInfo.end(), true);
}

/*
 * Feature: Framework
 * Function: Test SetEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetEventInfo which input is userId and imageId with correct userId.
 */
HWTEST_F(DpsEventReportUnittest, SetEventInfo002, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.highJobNum = INT32_ONE;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().SetEventInfo(imageId, userId);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo[USERID][IMAGEID].highJobNum, 0);
}

/*
 * Feature: Framework
 * Function: Test SetEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetEventInfo which input is dpsEventInfo with correct userId.
 */
HWTEST_F(DpsEventReportUnittest, SetEventInfo003, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.highJobNum = INT32_ONE;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().SetEventInfo(dpsEventInfo);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo[userId][IMAGEID].highJobNum, 0);
}

/*
 * Feature: Framework
 * Function: Test SetEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test SetEventInfo which input is dpsEventInfo with abnormal userId.
 */
HWTEST_F(DpsEventReportUnittest, SetEventInfo004, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    const std::string imageIdSec = IMAGEID_SECOND;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageIdSec, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().SetEventInfo(dpsEventInfo);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo.find(USERID) !=
        DPSEventReport::GetInstance().userIdToImageIdEventInfo.end(), true);
}

/*
 * Feature: Framework
 * Function: Test UpdateEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateEventInfo which input is dpsEventInfo with abnormal userId.
 */
HWTEST_F(DpsEventReportUnittest, UpdateEventInfo001, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    const std::string imageIdSec = IMAGEID_SECOND;
    int32_t userId = 0;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageIdSec, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().UpdateEventInfo(dpsEventInfo);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo.find(0) !=
        DPSEventReport::GetInstance().userIdToImageIdEventInfo.end(), true);
}

/*
 * Feature: Framework
 * Function: Test UpdateEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateEventInfo which input is dpsEventInfo with correct userId.
 */
HWTEST_F(DpsEventReportUnittest, UpdateEventInfo002, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.highJobNum = INT32_ONE;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().UpdateEventInfo(dpsEventInfo);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo[userId][IMAGEID].highJobNum, INT32_ONE);
}

/*
 * Feature: Framework
 * Function: Test GetEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetEventInfo with abnormal userId and imageId.return empty DPSEventInfo.
 */
HWTEST_F(DpsEventReportUnittest, GetEventInfo001, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = 0;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    userId = 0;
    auto ret = DPSEventReport::GetInstance().GetEventInfo(imageId, userId);
    EXPECT_EQ(ret.userId, 0);
}

/*
 * Feature: Framework
 * Function: Test GetEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetEventInfo with correct userId but abnormal imageId.return empty DPSEventInfo.
 */
HWTEST_F(DpsEventReportUnittest, GetEventInfo002, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = 0;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    const std::string error_imageId = "";
    DPSEventReport::GetInstance().GetEventInfo(error_imageId, userId);
    EXPECT_NE(dpsEventInfo.userId, USERID);
}

/*
 * Feature: Framework
 * Function: Test GetEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetEventInfo with correct userId and imageId.return correct DPSEventInfo.
 */
HWTEST_F(DpsEventReportUnittest, GetEventInfo003, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    auto ret = DPSEventReport::GetInstance().GetEventInfo(imageId, userId);
    EXPECT_EQ(ret.userId, USERID);
}

/*
 * Feature: Framework
 * Function: Test RemoveEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveEventInfo with abnormal userId.return original DPSEventInfo.
 */
HWTEST_F(DpsEventReportUnittest, RemoveEventInfo001, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = 0;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    userId = 0;
    DPSEventReport::GetInstance().RemoveEventInfo(imageId, userId);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo.find(USERID) !=
        DPSEventReport::GetInstance().userIdToImageIdEventInfo.end(), true);
}

/*
 * Feature: Framework
 * Function: Test RemoveEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveEventInfo with correct userId but abnormal imageId.return original DPSEventInfo.
 */
HWTEST_F(DpsEventReportUnittest, RemoveEventInfo002, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = 0;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    const std::string error_imageId = "";
    DPSEventReport::GetInstance().RemoveEventInfo(error_imageId, userId);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo.find(USERID) !=
        DPSEventReport::GetInstance().userIdToImageIdEventInfo.end(), true);
}

/*
 * Feature: Framework
 * Function: Test RemoveEventInfo.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RemoveEventInfo with correct userId and imageId.Remove DPSEventInfo.
 */
HWTEST_F(DpsEventReportUnittest, RemoveEventInfo003, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().GetEventInfo(imageId, userId);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo.find(USERID) ==
        DPSEventReport::GetInstance().userIdToImageIdEventInfo.end(), false);
}

/*
 * Feature: Framework
 * Function: Test UpdateProcessDoneTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateProcessDoneTime with abnormal userId.
 */
HWTEST_F(DpsEventReportUnittest, UpdateProcessDoneTime001, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    userId = 0;
    DPSEventReport::GetInstance().UpdateProcessDoneTime(imageId, userId);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo.find(USERID) !=
        DPSEventReport::GetInstance().userIdToImageIdEventInfo.end(), true);
}

/*
 * Feature: Framework
 * Function: Test UpdateProcessDoneTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateProcessDoneTime with correct userId.
 */
HWTEST_F(DpsEventReportUnittest, UpdateProcessDoneTime002, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().UpdateProcessDoneTime(imageId, userId);
    EXPECT_NE(DPSEventReport::GetInstance().userIdToImageIdEventInfo[userId][IMAGEID].processTimeEndTime, 0);
}

/*
 * Feature: Framework
 * Function: Test UpdateSynchronizeTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateSynchronizeTime with dpsEventInfoSrc.synchronizeTimeEndTime > 0 
 * and dpsEventInfoSrc.synchronizeTimeBeginTime > 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateSynchronizeTime001, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.synchronizeTimeEndTime = 0;
    dpsEventInfo.synchronizeTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.synchronizeTimeEndTime = UINT64_ENDTIME;
    dpsEventInfoSrc.synchronizeTimeBeginTime = UINT64_ENDTIME;
    DPSEventReport::GetInstance().UpdateSynchronizeTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.synchronizeTimeEndTime, UINT64_ENDTIME);
    EXPECT_EQ(dpsEventInfo.synchronizeTimeBeginTime, UINT64_ENDTIME);
}

/*
 * Feature: Framework
 * Function: Test UpdateSynchronizeTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateSynchronizeTime with dpsEventInfoSrc.synchronizeTimeEndTime = 0 
 * and dpsEventInfoSrc.synchronizeTimeBeginTime = 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateSynchronizeTime002, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.synchronizeTimeEndTime = 0;
    dpsEventInfo.synchronizeTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.synchronizeTimeEndTime = 0;
    dpsEventInfoSrc.synchronizeTimeBeginTime = 0;
    DPSEventReport::GetInstance().UpdateSynchronizeTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.synchronizeTimeEndTime, 0);
    EXPECT_EQ(dpsEventInfo.synchronizeTimeBeginTime, 0);
}

/*
 * Feature: Framework
 * Function: Test UpdateDispatchTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateDispatchTime with dpsEventInfoSrc.dispatchTimeEndTime > 0 
 * and dpsEventInfoSrc.dispatchTimeBeginTime > 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateDispatchTime001, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.dispatchTimeEndTime = 0;
    dpsEventInfo.dispatchTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.dispatchTimeEndTime = UINT64_ENDTIME;
    dpsEventInfoSrc.dispatchTimeBeginTime = UINT64_ENDTIME;
    DPSEventReport::GetInstance().UpdateDispatchTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.dispatchTimeEndTime, UINT64_ENDTIME);
    EXPECT_EQ(dpsEventInfo.dispatchTimeBeginTime, UINT64_ENDTIME);
}

/*
 * Feature: Framework
 * Function: Test UpdateDispatchTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateDispatchTime with dpsEventInfoSrc.dispatchTimeEndTime = 0 
 * and dpsEventInfoSrc.dispatchTimeBeginTime = 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateDispatchTime002, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.dispatchTimeEndTime = 0;
    dpsEventInfo.dispatchTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.dispatchTimeEndTime = 0;
    dpsEventInfoSrc.dispatchTimeBeginTime = 0;
    DPSEventReport::GetInstance().UpdateDispatchTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.dispatchTimeEndTime, 0);
    EXPECT_EQ(dpsEventInfo.dispatchTimeBeginTime, 0);
}

/*
 * Feature: Framework
 * Function: Test UpdateProcessTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateProcessTime with dpsEventInfoSrc.processTimeEndTime > 0 
 * and dpsEventInfoSrc.processTimeBeginTime > 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateProcessTime001, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.processTimeEndTime = 0;
    dpsEventInfo.processTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.processTimeEndTime = UINT64_ENDTIME;
    dpsEventInfoSrc.processTimeBeginTime = UINT64_ENDTIME;
    DPSEventReport::GetInstance().UpdateProcessTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.processTimeEndTime, UINT64_ENDTIME);
    EXPECT_EQ(dpsEventInfo.processTimeBeginTime, UINT64_ENDTIME);
}

/*
 * Feature: Framework
 * Function: Test UpdateProcessTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateProcessTime with dpsEventInfoSrc.processTimeEndTime = 0 
 * and dpsEventInfoSrc.processTimeBeginTime = 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateProcessTime002, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.processTimeEndTime = 0;
    dpsEventInfo.processTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.processTimeEndTime = 0;
    dpsEventInfoSrc.processTimeBeginTime = 0;
    DPSEventReport::GetInstance().UpdateProcessTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.processTimeEndTime, 0);
    EXPECT_EQ(dpsEventInfo.processTimeBeginTime, 0);
}

/*
 * Feature: Framework
 * Function: Test UpdateImageDoneTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateImageDoneTime with dpsEventInfoSrc.imageDoneTimeEndTime > 0 
 * and dpsEventInfoSrc.imageDoneTimeBeginTime > 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateImageDoneTime001, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.imageDoneTimeEndTime = 0;
    dpsEventInfo.imageDoneTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.imageDoneTimeEndTime = UINT64_ENDTIME;
    dpsEventInfoSrc.imageDoneTimeBeginTime = UINT64_ENDTIME;
    DPSEventReport::GetInstance().UpdateImageDoneTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.imageDoneTimeEndTime, UINT64_ENDTIME);
    EXPECT_EQ(dpsEventInfo.imageDoneTimeBeginTime, UINT64_ENDTIME);
}

/*
 * Feature: Framework
 * Function: Test UpdateImageDoneTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateImageDoneTime with dpsEventInfoSrc.imageDoneTimeEndTime = 0 
 * and dpsEventInfoSrc.imageDoneTimeBeginTime = 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateImageDoneTime002, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.imageDoneTimeEndTime = 0;
    dpsEventInfo.imageDoneTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.imageDoneTimeEndTime = 0;
    dpsEventInfoSrc.imageDoneTimeBeginTime = 0;
    DPSEventReport::GetInstance().UpdateImageDoneTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.imageDoneTimeEndTime, 0);
    EXPECT_EQ(dpsEventInfo.imageDoneTimeBeginTime, 0);
}

/*
 * Feature: Framework
 * Function: Test UpdateRestoreTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRestoreTime with dpsEventInfoSrc.restoreTimeEndTime > 0 
 * and dpsEventInfoSrc.restoreTimeBeginTime > 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateRestoreTime001, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.restoreTimeEndTime = 0;
    dpsEventInfo.restoreTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.restoreTimeEndTime = UINT64_ENDTIME;
    dpsEventInfoSrc.restoreTimeBeginTime = UINT64_ENDTIME;
    DPSEventReport::GetInstance().UpdateRestoreTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.restoreTimeEndTime, UINT64_ENDTIME);
    EXPECT_EQ(dpsEventInfo.restoreTimeBeginTime, UINT64_ENDTIME);
}

/*
 * Feature: Framework
 * Function: Test UpdateRestoreTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRestoreTime with dpsEventInfoSrc.restoreTimeEndTime = 0 
 * and dpsEventInfoSrc.restoreTimeBeginTime = 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateRestoreTime002, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.restoreTimeEndTime = 0;
    dpsEventInfo.restoreTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.restoreTimeEndTime = 0;
    dpsEventInfoSrc.restoreTimeBeginTime = 0;
    DPSEventReport::GetInstance().UpdateRestoreTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.restoreTimeEndTime, 0);
    EXPECT_EQ(dpsEventInfo.restoreTimeBeginTime, 0);
}

/*
 * Feature: Framework
 * Function: Test UpdateRemoveTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRemoveTime with dpsEventInfoSrc.removeTimeEndTime > 0 
 * and dpsEventInfoSrc.removeTimeBeginTime > 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateRemoveTime001, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.removeTimeEndTime = 0;
    dpsEventInfo.removeTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.removeTimeEndTime = UINT64_ENDTIME;
    dpsEventInfoSrc.removeTimeBeginTime = UINT64_ENDTIME;
    DPSEventReport::GetInstance().UpdateRemoveTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.removeTimeEndTime, UINT64_ENDTIME);
    EXPECT_EQ(dpsEventInfo.removeTimeBeginTime, UINT64_ENDTIME);
}

/*
 * Feature: Framework
 * Function: Test UpdateRemoveTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRemoveTime with dpsEventInfoSrc.removeTimeEndTime = 0 
 * and dpsEventInfoSrc.removeTimeBeginTime = 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateRemoveTime002, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.removeTimeEndTime = 0;
    dpsEventInfo.removeTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.removeTimeEndTime = 0;
    dpsEventInfoSrc.removeTimeBeginTime = 0;
    DPSEventReport::GetInstance().UpdateRemoveTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.removeTimeEndTime, 0);
    EXPECT_EQ(dpsEventInfo.removeTimeBeginTime, 0);
}

/*
 * Feature: Framework
 * Function: Test UpdateRemoveTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRemoveTime with abnormal userId.
 */
HWTEST_F(DpsEventReportUnittest, UpdateRemoveTime003, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    userId = 0;
    DPSEventReport::GetInstance().UpdateRemoveTime(imageId, userId);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo.find(USERID) !=
        DPSEventReport::GetInstance().userIdToImageIdEventInfo.end(), true);
}

/*
 * Feature: Framework
 * Function: Test UpdateRemoveTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateRemoveTime with correct userId.
 */
HWTEST_F(DpsEventReportUnittest, UpdateRemoveTime004, TestSize.Level0)
{
    const std::string imageId = IMAGEID;
    int32_t userId = USERID;
    std::map<std::string, DPSEventInfo> eventInfo;
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    eventInfo.emplace(imageId, dpsEventInfo);
    DPSEventReport::GetInstance().userIdToImageIdEventInfo.emplace(userId, eventInfo);
    DPSEventReport::GetInstance().UpdateRemoveTime(imageId, userId);
    EXPECT_EQ(DPSEventReport::GetInstance().userIdToImageIdEventInfo.find(USERID) !=
        DPSEventReport::GetInstance().userIdToImageIdEventInfo.end(), true);
}

/*
 * Feature: Framework
 * Function: Test UpdateTrailingTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateTrailingTime with dpsEventInfoSrc.trailingTimeEndTime > 0 
 * and dpsEventInfoSrc.trailingTimeBeginTime > 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateTrailingTime001, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.trailingTimeEndTime = 0;
    dpsEventInfo.trailingTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.trailingTimeEndTime = UINT64_ENDTIME;
    dpsEventInfoSrc.trailingTimeBeginTime = UINT64_ENDTIME;
    DPSEventReport::GetInstance().UpdateTrailingTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.trailingTimeEndTime, UINT64_ENDTIME);
    EXPECT_EQ(dpsEventInfo.trailingTimeBeginTime, UINT64_ENDTIME);
}

/*
 * Feature: Framework
 * Function: Test UpdateTrailingTime.
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test UpdateTrailingTime with dpsEventInfoSrc.trailingTimeEndTime = 0 
 * and dpsEventInfoSrc.trailingTimeBeginTime = 0.
 */
HWTEST_F(DpsEventReportUnittest, UpdateTrailingTime002, TestSize.Level0)
{
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.userId = USERID;
    dpsEventInfo.imageId = IMAGEID;
    dpsEventInfo.trailingTimeEndTime = 0;
    dpsEventInfo.trailingTimeBeginTime = 0;
    DPSEventInfo dpsEventInfoSrc;
    dpsEventInfoSrc.userId = USERID;
    dpsEventInfoSrc.imageId = IMAGEID;
    dpsEventInfoSrc.trailingTimeEndTime = 0;
    dpsEventInfoSrc.trailingTimeBeginTime = 0;
    DPSEventReport::GetInstance().UpdateTrailingTime(dpsEventInfo, dpsEventInfoSrc);
    EXPECT_EQ(dpsEventInfo.trailingTimeEndTime, 0);
    EXPECT_EQ(dpsEventInfo.trailingTimeBeginTime, 0);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS