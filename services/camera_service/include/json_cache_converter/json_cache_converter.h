/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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
#ifndef JSON_CACHE_CONVERTER_H
#define JSON_CACHE_CONVERTER_H

#include "camera_log.h"
#include "hcamera_restore_param.h"
#include "metadata_utils.h"
#include "hstream_capture.h"

#include "nlohmann/json.hpp"

#include <iostream>
#include <fstream>
#include <map>
#include <string>


namespace OHOS {
namespace CameraStandard {

namespace {
    const std::string SAVE_RESTORE_FILE_PATH = "/data/service/el1/public/camera_service/SaveRestore.json";
    const int32_t ENUM_LIMIT = 1000;
    const int JSON_INDENT_SPACES_FOR_DEBUG = 4;
    const int UINT8_MIN_VAL = 0;
    const int UINT8_MAX_VAL = 255;
    enum class JsonKeyType {
        INTEGER,
        BOOLEAN,
        ENUMERATION
    };

    struct JsonKeyInfo {
        const char* keyName;
        JsonKeyType type;
        int minValue;  // 用于枚举类型，表示最小值
        int maxValue;  // 用于枚举类型，表示最大值
    };
}

class JsonCacheConverter {
public:
    JsonCacheConverter() = default;
    virtual ~JsonCacheConverter() = default;
    static bool ParseJsonFileToMap(const std::string& jsonFilePath, std::map<std::string,
                                   std::map<std::string, sptr<HCameraRestoreParam>>>& pMap,
                                   std::map<std::string, sptr<HCameraRestoreParam>>& tMap,
                                   std::string& clientName, std::string& cameraId);
    static bool SaveMapToJsonFile(const std::string& jsonFilePath, const std::map<std::string,
                                  std::map<std::string, sptr<HCameraRestoreParam>>>& pMap,
                                  const std::map<std::string, sptr<HCameraRestoreParam>>& tMap,
                                  const std::string& clientName, const std::string& cameraId);
private:
    static bool ParseJsonToPMap(const nlohmann::json& rootJson,
                                std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>>& pMap_);
    static bool ParseJsonToTMap(const nlohmann::json& rootJson,
                                std::map<std::string, sptr<HCameraRestoreParam>>& tMap_);
    static bool ParseJsonToIndex(const nlohmann::json& rootJson,
                                 std::string& clientName, std::string& cameraId);
    static bool ParseJsonToParam(const nlohmann::json& paramJson, sptr<HCameraRestoreParam>& cameraRestoreParam);
    static bool ParseJsonToStreamInfos(const nlohmann::json& streamInfosJson,
                                       std::vector<StreamInfo_V1_1>& streamInfos);
    static bool ParseJsonToStreamInfoV1_0(const nlohmann::json& streamInfoV1_0Json,
                                          OHOS::HDI::Camera::V1_0::StreamInfo& v1_0);
    static bool CheckStreamInfoV1_0Json(const nlohmann::json& streamInfoV1_0Json);
    static bool ParseJsonToExtendedInfo(const nlohmann::json& extendedInfosJson,
                                        std::vector<OHOS::HDI::Camera::V1_1::ExtendedStreamInfo>& extendedStreamInfos);
    static bool ParseJsonToSettings(const nlohmann::json& metadataJson,
                                    std::shared_ptr<OHOS::Camera::CameraMetadata>& settings);
    static bool ParseJsonToCloseCameraTime(const nlohmann::json& closeCameraTimeJson, timeval& closeCameraTime);

    static void SavePMapToJson(const std::map<std::string, std::map<std::string,
                               sptr<HCameraRestoreParam>>> &persistentParamMap,
                               nlohmann::json& pmapJson);
    static void SaveTMapToJson(const std::map<std::string, sptr<HCameraRestoreParam>> &transitentParamMap,
                               nlohmann::json& tmapJson);
    static void SaveIndexToJson(const std::string& clientName, const std::string& cameraId, nlohmann::json& index);

    static void SaveParamToJson(nlohmann::json& paramJson, const sptr<HCameraRestoreParam>& param);

    static void SaveStreamInfosToJson(const std::vector<StreamInfo_V1_1> &streamInfos, nlohmann::json& streamInfosJson);
    static void SaveSettingsToJson(const std::shared_ptr<OHOS::Camera::CameraMetadata> settings,
                                   nlohmann::json& metadataJson);

    static bool CheckParamJson(const nlohmann::json& paramJson);
    static bool OutputToJsonFile(const std::string& jsonFilePath, const nlohmann::json& pmapJson,
                                 const nlohmann::json& tmapJson, const nlohmann::json& indexJson);
    static bool CreateProducerForPrelaunch(OHOS::HDI::Camera::V1_0::StreamInfo &v1_0);
    static bool CreateProducerForPrelaunch(std::vector<OHOS::HDI::Camera::V1_1::ExtendedStreamInfo>
                                           &extendedStreamInfos);
};
} // namespace CameraStandard
} // namespace OHOS
#endif