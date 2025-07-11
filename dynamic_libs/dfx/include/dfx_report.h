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
 
#ifndef DYNAMIC_LIB_DFX_REPORT_H
#define DYNAMIC_LIB_DFX_REPORT_H
 
#include <cstdio>
#include <cinttypes>
#include "hilog/log.h"
#include "hisysevent.h"
#include "hitrace_meter.h"
 
namespace OHOS {
namespace CameraStandard {
 
class CameraReportUtils {
public:
    static CameraReportUtils &GetInstance()
    {
        static CameraReportUtils instance;
        return instance;
    }
 
    static void ReportCameraCreateNullptr(std::string funcName,
        std::string useFunc);
    static void ReportCameraFalse(std::string funcName, std::string useFunc);
 
    template<typename T>
    static void ReportCameraError(std::string funcName, std::string useFunc, T ret);
 
    static void ReportCameraGetNullStr(std::string funcName, std::string useFunc);
    static void ReportCameraFail(std::string funcName, std::string useFunc);
};
} // namespace CameraStandard
} // namespace OHOS
 
#endif // DYNAMIC_LIB_DFX_REPORT_H