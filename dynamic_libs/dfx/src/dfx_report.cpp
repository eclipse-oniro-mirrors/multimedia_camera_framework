/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#include "dfx_report.h"
 
namespace OHOS {
namespace CameraStandard {
 
void CameraReportUtils::ReportCameraCreateNullptr(std::string funcName,
    std::string useFunc)
{
    std::string str = funcName;
    str += " use ";
    str += useFunc;
    str += " get nullptr";
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "CAMERA_ERR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", str);
}
 
void CameraReportUtils::ReportCameraFalse(std::string funcName, std::string useFunc)
{
    std::string str = funcName;
    str += " use ";
    str += useFunc;
    str += "get false";
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "CAMERA_ERR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", str);
}
 
template<typename T>
void CameraReportUtils::ReportCameraError(std::string funcName, std::string useFunc, T ret)
{
    std::string str = funcName;
    str += " use ";
    str += useFunc;
    str += "get retCode is " + std::to_string(ret);
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "CAMERA_ERR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", str);
}
 
template void CameraReportUtils::ReportCameraError<int32_t>(
    std::string, std::string, int32_t);
template void CameraReportUtils::ReportCameraError<uint32_t>(
    std::string, std::string, uint32_t);
 
void CameraReportUtils::ReportCameraGetNullStr(std::string funcName, std::string useFunc)
{
    std::string str = funcName;
    str += " use ";
    str += useFunc;
    str += "get null string ";
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "CAMERA_ERR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", str);
}
 
void CameraReportUtils::ReportCameraFail(std::string funcName, std::string useFunc)
{
    std::string str = funcName;
    str += " use ";
    str += useFunc;
    str += " is false";
    HiSysEventWrite(
        HiviewDFX::HiSysEvent::Domain::CAMERA,
        "CAMERA_ERR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "MSG", str);
}
 
}  // namespace CameraStandard
}  // namespace OHOS