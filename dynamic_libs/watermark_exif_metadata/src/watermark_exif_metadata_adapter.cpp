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

#include "watermark_exif_metadata_adapter.h"

#include <cmath>
#include <ctime>
#include <iomanip>
#include <securec.h>

#include "camera_log.h"
#include "camera_watermark_info.h"
#include "exif_metadata.h"

namespace OHOS {
namespace CameraStandard {
// LCOV_EXCL_START
static constexpr int64_t EXPOTIME_UNIT = 1000000000;
static constexpr int64_t EXPOTIME_USHRT_MAX = 65535;
static constexpr int64_t SENSITIVITY_TYPE = 2;
static constexpr int64_t EXPOTIME_BOUNDARY = 250000000;
WatermarkExifMetadataAdapter::WatermarkExifMetadataAdapter()
{
    MEDIA_DEBUG_LOG("WatermarkExifMetadataAdapter ctor");
}

std::string TransFractionString(int64_t minNum, int64_t maxNum)
{
    CHECK_RETURN_RET(minNum <= 0 || maxNum <= 0, "");
    int64_t numerator = 1;
    double tempValue = static_cast<double>(maxNum) / minNum;

    if (minNum > EXPOTIME_BOUNDARY) {
        double value = static_cast<double>(minNum) / maxNum;
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << value;
        return oss.str();
    } else {
        int64_t denominator = static_cast<int64_t>(std::roundl(tempValue));
        return std::to_string(numerator) + "/" + std::to_string(denominator);
    }
}

std::string TimestampToDateTimeString(int64_t timestamp)
{
    std::time_t timeDate = static_cast<std::time_t>(timestamp);
    std::tm* time = std::localtime(&timeDate);
    constexpr size_t iLen = 20;
    char* dateTimeStr = reinterpret_cast<char*>(malloc(iLen));
    CHECK_RETURN_RET_ELOG(dateTimeStr == nullptr, "", "malloc failed");
    if (memset_s(dateTimeStr, iLen, 0, iLen) != 0) {
        MEDIA_ERR_LOG("memset_s return error");
        free(dateTimeStr);
        return "";
    }
    int ret = snprintf_s(dateTimeStr, iLen, iLen - 1, "%04d:%02d:%02d %02d:%02d:%02d",
        time->tm_year + 1900,
        time->tm_mon + 1, time->tm_mday, time->tm_hour, time->tm_min, time->tm_sec);
    if (ret < 0) {
        MEDIA_ERR_LOG("snprintf_s return error");
        free(dateTimeStr);
        return "";
    }
    std::string dateTime(dateTimeStr);
    free(dateTimeStr);
    MEDIA_DEBUG_LOG("dateTime is %{public}s", dateTime.c_str());
    return dateTime;
}

void SetWaterInfoExifMetaData(std::shared_ptr<Media::ExifMetadata> exifData, const WatermarkInfo &info)
{
    std::string expoTimeStr = TransFractionString(info.expoTime, EXPOTIME_UNIT);
    exifData->SetValue("ExposureTime", expoTimeStr);
    exifData->SetValue("FNumber", std::to_string(info.expoFNumber));
    exifData->SetValue("FocalLengthIn35mmFilm", std::to_string(static_cast<int64_t>(info.expoEfl)));
    std::string dataTimeString = TimestampToDateTimeString(info.captureTime);
    exifData->SetValue("DateTimeOriginal", dataTimeString);

    if (info.expoIso > static_cast<int>(EXPOTIME_USHRT_MAX)) {
        exifData->SetValue("ISOSpeedRatings", std::to_string(EXPOTIME_USHRT_MAX));
        exifData->SetValue("SensitivityType", std::to_string(SENSITIVITY_TYPE));
        exifData->SetValue("RecommendedExposureIndex", std::to_string(info.expoIso));
    } else {
        exifData->SetValue("ISOSpeedRatings", std::to_string(info.expoIso));
    }
    MEDIA_DEBUG_LOG("SetWaterInfoExifMetaData expoTime:%{public}s, expoIso: %{public}s, expoFNumber: %{public}s,"
        "expoEfl: %{public}s, captureTime: %{public}s",
        expoTimeStr.c_str(), std::to_string(info.expoIso).c_str(), std::to_string(info.expoFNumber).c_str(),
        std::to_string(static_cast<int64_t>(info.expoEfl)).c_str(), dataTimeString.c_str());
}

void WatermarkExifMetadataAdapter::SetWatermarkExifMetadata(
    std::unique_ptr<Media::PixelMap> &pixelMap, const WatermarkInfo &info)
{
    MEDIA_INFO_LOG("WatermarkExifMetadataAdapter::SetWatermarkExifMetadata called");
    std::shared_ptr<Media::ExifMetadata> exifMetaData = std::make_shared<Media::ExifMetadata>();
    if (exifMetaData != nullptr) {
        bool result = exifMetaData->CreateExifdata();
        CHECK_PRINT_ELOG(!result, "CreateExifdata failed");
        SetWaterInfoExifMetaData(exifMetaData, info);
        pixelMap->SetExifMetadata(exifMetaData);
    }
}

// LCOV_EXCL_STOP
extern "C" WatermarkExifMetadataIntf *createWatermarkExifMetadataIntf()
{
    return new  WatermarkExifMetadataAdapter();
}
}  // namespace CameraStandard
}  // namespace OHOS