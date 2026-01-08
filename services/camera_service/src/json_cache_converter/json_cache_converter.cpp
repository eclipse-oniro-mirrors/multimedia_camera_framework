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

#include "json_cache_converter.h"

namespace OHOS {
namespace CameraStandard {
bool JsonCacheConverter::ParseJsonFileToMap(const std::string& jsonFilePath,
    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>>& pMap,
    std::map<std::string, sptr<HCameraRestoreParam>>& tMap,
    std::string& clientName, std::string& cameraId)
{
    MEDIA_DEBUG_LOG("Parse JsonFile: To Map Begin!");
    CHECK_RETURN_RET_ELOG(!std::filesystem::exists(jsonFilePath) ||
                          !std::filesystem::is_regular_file(jsonFilePath),
                          false,
                          "invalid jsonFilePath");
    pMap.clear();
    tMap.clear();
    std::ifstream inFile(jsonFilePath);
    CHECK_RETURN_RET_ELOG(!inFile.is_open(), false,
                          "Failed to open file for reading");
    std::stringstream buffer;
    buffer << inFile.rdbuf();
    CHECK_RETURN_RET_ELOG(!inFile.good(), false, "Failed to read file content");
    std::string fileContent = buffer.str();
    CHECK_RETURN_RET_ELOG(fileContent.empty() || !nlohmann::json::accept(fileContent), false,
                          "Failed to parse JSON content");
    nlohmann::json rootJson = nlohmann::json::parse(fileContent);
    CHECK_RETURN_RET_ELOG(!ParseJsonToTMap(rootJson, tMap), false, "failed to parse content to tMap!");
    CHECK_RETURN_RET_ELOG(!ParseJsonToPMap(rootJson, pMap), false, "failed to parse content to pMap!");
    CHECK_RETURN_RET_ELOG(!ParseJsonToIndex(rootJson, clientName, cameraId), false,
                          "failed to parse content to index!");
    return true;
}

bool JsonCacheConverter::ParseJsonToPMap(const nlohmann::json& rootJson,
                                         std::map<std::string, std::map<std::string,
                                         sptr<HCameraRestoreParam>>>& pMap_)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::ParseJsonToPMap Begin!");
    CHECK_RETURN_RET_ELOG(!rootJson.contains("PmapJson"), false, "key PmapJson not in rootJson.");
    nlohmann::json PmapJson = rootJson["PmapJson"];
    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>> tempPmap;
    for (const auto& [clientName, outerJson] : PmapJson.items()) {
        for (const auto& [cameraId, innerJson] : outerJson.items()) {
            sptr<HCameraRestoreParam> cameraRestoreParam = new HCameraRestoreParam(clientName, cameraId);
            CHECK_RETURN_RET_ELOG(!ParseJsonToParam(innerJson, cameraRestoreParam), false,
                                  "Failed to parse json To param");
            tempPmap[clientName][cameraId] =  cameraRestoreParam;
        }
    }
    pMap_ = tempPmap;
    return true;
}

bool JsonCacheConverter::ParseJsonToTMap(const nlohmann::json& rootJson,
                                         std::map<std::string, sptr<HCameraRestoreParam>>& tMap_)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::ParseJsonToTMap Begin!");
    CHECK_RETURN_RET_ELOG(!rootJson.contains("TmapJson"), false, "key TmapJson not in rootJson.");
    nlohmann::json tMapJson = rootJson["TmapJson"];
    std::map<std::string, sptr<HCameraRestoreParam>> tempTmap;
    for (const auto& [key, paramJson] : tMapJson.items()) {
        CHECK_RETURN_RET_ELOG(!paramJson.contains("clientName"), false, "Key clientName not in paramJson.");
        CHECK_RETURN_RET_ELOG(!paramJson.contains("cameraId"), false, "Key cameraId not in paramJson.");
        CHECK_RETURN_RET_ELOG(!paramJson["clientName"].is_string(), false, "illegal value for clientName");
        CHECK_RETURN_RET_ELOG(!paramJson["cameraId"].is_string(), false, "illegal value for cameraId");
        std::string clientName = paramJson["clientName"];
        std::string cameraId = paramJson["cameraId"];
        sptr<HCameraRestoreParam> cameraRestoreParam = new HCameraRestoreParam(clientName, cameraId);
        CHECK_RETURN_RET_ELOG(!ParseJsonToParam(paramJson, cameraRestoreParam), false,
                              "Failed to parse json to param");
        tempTmap[key] = cameraRestoreParam;
    }
    tMap_ = tempTmap;
    return true;
}

bool JsonCacheConverter::ParseJsonToIndex(const nlohmann::json& rootJson,
                                          std::string& clientName,
                                          std::string& cameraId)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::ParseJsonToIndex Begin!");
    CHECK_RETURN_RET_ELOG(!rootJson.contains("IndexJson"), false, "key IndexJson not in rootJson.");
    nlohmann::json IndexJson = rootJson["IndexJson"];

    CHECK_RETURN_RET_ELOG(!IndexJson.contains("clientName"), false, "key clientName not in IndexJson.");
    CHECK_RETURN_RET_ELOG(!IndexJson.contains("cameraId"), false, "key cameraId not in IndexJson.");
    CHECK_RETURN_RET_ELOG(!IndexJson["clientName"].is_string(), false,
                          "ParseJsonToIndex : illegal value for clientName");
    CHECK_RETURN_RET_ELOG(!IndexJson["cameraId"].is_string(), false,
                          "ParseJsonToIndex : illegal value for cameraId");
    clientName = IndexJson["clientName"];
    cameraId = IndexJson["cameraId"];
    return true;
}

bool JsonCacheConverter::ParseJsonToParam(const nlohmann::json& paramJson,
                                          sptr<HCameraRestoreParam>& cameraRestoreParam)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::ParseJsonToParam Begin!");
    CHECK_RETURN_RET_ELOG(cameraRestoreParam == nullptr, false, "cameraRestoreParam == nullptr.");
    CHECK_RETURN_RET_ELOG(!CheckParamJson(paramJson), false, "Lack of keys, ParseJsonToParam failed.");

    nlohmann::json streamInfosJson = paramJson["streamInfos"];
    std::vector<StreamInfo_V1_1> streamInfos;
    CHECK_RETURN_RET(!ParseJsonToStreamInfos(streamInfosJson, streamInfos), false);
    cameraRestoreParam->SetStreamInfo(streamInfos);

    nlohmann::json metadataJson = paramJson["settings"];
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = nullptr;
    CHECK_RETURN_RET(!ParseJsonToSettings(metadataJson, settings), false);
    cameraRestoreParam->SetSetting(settings);

    nlohmann::json closeCameraTimeJson = paramJson["closeCameraTime"];
    timeval closeCameraTime;
    CHECK_RETURN_RET(!ParseJsonToCloseCameraTime(closeCameraTimeJson, closeCameraTime), false);
    cameraRestoreParam->SetCloseCameraTime(closeCameraTime);

    CHECK_RETURN_RET_ELOG(!paramJson["restoreParamType"].is_number_integer(), false,
                          "ParseJsonToParam : restoreParamType from json is not int.");
    CHECK_RETURN_RET_ELOG(paramJson["restoreParamType"] < RestoreParamTypeOhos::NO_NEED_RESTORE_PARAM_OHOS
                          || paramJson["restoreParamType"] > ENUM_LIMIT,
                          false,
                          "ParseJsonToParam : value of restoreParamType should be 0, 1, 2.");
    RestoreParamTypeOhos restoreParamType = paramJson["restoreParamType"].get<RestoreParamTypeOhos>();
    cameraRestoreParam->SetRestoreParamType(restoreParamType);

    CHECK_RETURN_RET_ELOG(!paramJson["startActiveTime"].is_number_integer(), false,
                          "ParseJsonToParam : startActiveTime from json is not int.");
    int startActiveTime = paramJson["startActiveTime"].get<int>();
    cameraRestoreParam->SetStartActiveTime(startActiveTime);

    CHECK_RETURN_RET_ELOG(!paramJson["cameraOpMode"].is_number_integer(), false,
                          "ParseJsonToParam : cameraOpMode from json is not int.");
    int32_t opMode = paramJson["cameraOpMode"].get<int32_t>();
    cameraRestoreParam->SetCameraOpMode(opMode);

    CHECK_RETURN_RET_ELOG(!paramJson["foldStatus"].is_number_integer(), false,
                          "ParseJsonToParam : foldStatus from json is not int.");
    int foldStatus = paramJson["foldStatus"].get<int>();
    cameraRestoreParam->SetFoldStatus(foldStatus);
    return true;
}

bool JsonCacheConverter::ParseJsonToStreamInfos(const nlohmann::json& streamInfosJson,
                                                std::vector<StreamInfo_V1_1>& streamInfos)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::ParseJsonToStreamInfos Begin!");
    for (const nlohmann::json& streamInfoJson : streamInfosJson) {
        StreamInfo_V1_1 streamInfo;
        CHECK_RETURN_RET_ELOG(!streamInfoJson.contains("v1_0"), false, "key v1_0 not in streamInfoJson.");
        nlohmann::json streamInfoV1_0Json = streamInfoJson["v1_0"];
        OHOS::HDI::Camera::V1_0::StreamInfo v1_0;
        CHECK_RETURN_RET(!ParseJsonToStreamInfoV1_0(streamInfoV1_0Json, v1_0), false);
        CHECK_RETURN_RET(!CreateProducerForPrelaunch(v1_0), false);

        CHECK_RETURN_RET_ELOG(!streamInfoJson.contains("extendedStreamInfos"), false,
                              "key extendedStreamInfos not in streamInfoJson.");
        nlohmann::json extendedInfosJson = streamInfoJson["extendedStreamInfos"];
        std::vector<OHOS::HDI::Camera::V1_1::ExtendedStreamInfo> extendedStreamInfos;
        CHECK_RETURN_RET(!ParseJsonToExtendedInfo(extendedInfosJson, extendedStreamInfos), false);
        CHECK_RETURN_RET(!CreateProducerForPrelaunch(extendedStreamInfos), false);
        streamInfo.v1_0 = v1_0;
        streamInfo.extendedStreamInfos = extendedStreamInfos;
        streamInfos.push_back(streamInfo);
    }
    return true;
}

bool JsonCacheConverter::ParseJsonToStreamInfoV1_0(const nlohmann::json& streamInfoV1_0Json,
                                                   OHOS::HDI::Camera::V1_0::StreamInfo& v1_0)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::ParseJsonToStreamInfoV1_0 Begin!");
    CHECK_RETURN_RET(!CheckStreamInfoV1_0Json(streamInfoV1_0Json), false);
    v1_0.streamId_ = streamInfoV1_0Json["streamId"].get<int32_t>();
    v1_0.width_ = streamInfoV1_0Json["width"].get<int32_t>();
    v1_0.height_ = streamInfoV1_0Json["height"].get<int32_t>();
    v1_0.format_ = streamInfoV1_0Json["format"].get<int32_t>();
    v1_0.dataspace_ = streamInfoV1_0Json["dataspace"].get<int32_t>();
    v1_0.intent_ = streamInfoV1_0Json["intent"].get<HDI::Camera::V1_0::StreamIntent>();
    v1_0.tunneledMode_ = streamInfoV1_0Json["tunneledMode"].get<bool>();
    v1_0.minFrameDuration_ = streamInfoV1_0Json["minFrameDuration"].get<int32_t>();
    v1_0.encodeType_ = streamInfoV1_0Json["encodeType"].get<HDI::Camera::V1_0::EncodeType>();
    return true;
}

bool JsonCacheConverter::CheckStreamInfoV1_0Json(const nlohmann::json& streamInfoV1_0Json)
{
    std::vector<JsonKeyInfo> keyInfos = {
        {"streamId", JsonKeyType::INTEGER, 0, 0},
        {"width", JsonKeyType::INTEGER, 0, 0},
        {"height", JsonKeyType::INTEGER, 0, 0},
        {"format", JsonKeyType::INTEGER, 0, 0},
        {"dataspace", JsonKeyType::INTEGER, 0, 0},
        {"intent", JsonKeyType::ENUMERATION, PREVIEW, ENUM_LIMIT},
        {"tunneledMode", JsonKeyType::BOOLEAN, 0, 0},
        {"minFrameDuration", JsonKeyType::INTEGER, 0, 0},
        {"encodeType", JsonKeyType::ENUMERATION, ENCODE_TYPE_NULL, ENUM_LIMIT},
    };

    for (const auto& keyInfo : keyInfos) {
        CHECK_RETURN_RET_ELOG(!streamInfoV1_0Json.contains(keyInfo.keyName), false,
                              "key %{public}s not in streamInfoV1_0Json.", keyInfo.keyName);
        // 检查键的类型
        switch (keyInfo.type) {
            case JsonKeyType::INTEGER:
                CHECK_RETURN_RET_ELOG(!streamInfoV1_0Json[keyInfo.keyName].is_number_integer(), false,
                                      "CheckStreamInfoV1_0Json : %{public}s from json is not int.", keyInfo.keyName);
                break;
            case JsonKeyType::BOOLEAN:
                CHECK_RETURN_RET_ELOG(!streamInfoV1_0Json[keyInfo.keyName].is_boolean(), false,
                                      "CheckStreamInfoV1_0Json : %{public}s from json is not bool.", keyInfo.keyName);
                break;
            case JsonKeyType::ENUMERATION:
                CHECK_RETURN_RET_ELOG(!streamInfoV1_0Json[keyInfo.keyName].is_number_integer(), false,
                                      "CheckStreamInfoV1_0Json : %{public}s from json is not int.", keyInfo.keyName);
                CHECK_RETURN_RET_ELOG(streamInfoV1_0Json[keyInfo.keyName] < keyInfo.minValue ||
                                      streamInfoV1_0Json[keyInfo.keyName] > keyInfo.maxValue, false,
                                      "CheckStreamInfoV1_0Json : illegal value of json %{public}s.", keyInfo.keyName);
                break;
            default:
                CHECK_RETURN_RET_ELOG(true, false, "Unknown type for key %s.", keyInfo.keyName);
        }
    }
    return true;
}

bool JsonCacheConverter::ParseJsonToExtendedInfo(const nlohmann::json& extendedInfosJson,
    std::vector<OHOS::HDI::Camera::V1_1::ExtendedStreamInfo>& extendedStreamInfos)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::ParseJsonToExtendedInfo Begin!");
    for (const nlohmann::json& extendedInfoJson: extendedInfosJson) {
        OHOS::HDI::Camera::V1_1::ExtendedStreamInfo extendedInfo;
        CHECK_RETURN_RET_ELOG(!extendedInfoJson.contains("type"), false,
                              "key type not in extendedInfoJson.");
        CHECK_RETURN_RET_ELOG(!extendedInfoJson.contains("width"), false,
                              "key width not in extendedInfoJson.");
        CHECK_RETURN_RET_ELOG(!extendedInfoJson.contains("height"), false,
                              "key height not in extendedInfoJson.");
        CHECK_RETURN_RET_ELOG(!extendedInfoJson.contains("format"), false,
                              "key format not in extendedInfoJson.");
        CHECK_RETURN_RET_ELOG(!extendedInfoJson.contains("dataspace"), false,
                              "key dataspace not in extendedInfoJson.");

        CHECK_RETURN_RET_ELOG(!extendedInfoJson["type"].is_number_integer(), false,
                              "ParseJsonToExtendedInfo : type from json is not int.");
        CHECK_RETURN_RET_ELOG(
            extendedInfoJson["type"] < HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL ||
            extendedInfoJson["type"] > ENUM_LIMIT, false,
            "ParseJsonToExtendedInfo : illegal value of type from json.");
        extendedInfo.type = extendedInfoJson["type"].get<HDI::Camera::V1_1::ExtendedStreamInfoType>();
        CHECK_RETURN_RET_ELOG(!extendedInfoJson["width"].is_number_integer(), false,
                              "ParseJsonToExtendedInfo : width from json is not int.");
        extendedInfo.width = extendedInfoJson["width"].get<int32_t>();
        CHECK_RETURN_RET_ELOG(!extendedInfoJson["height"].is_number_integer(), false,
                              "ParseJsonToExtendedInfo : height from json is not int.");
        extendedInfo.height = extendedInfoJson["height"].get<int32_t>();
        CHECK_RETURN_RET_ELOG(!extendedInfoJson["format"].is_number_integer(), false,
                              "ParseJsonToExtendedInfo : format from json is not int.");
        extendedInfo.format = extendedInfoJson["format"].get<int32_t>();
        CHECK_RETURN_RET_ELOG(!extendedInfoJson["dataspace"].is_number_integer(), false,
                              "ParseJsonToExtendedInfo : dataspace from json is not int.");
        extendedInfo.dataspace = extendedInfoJson["dataspace"].get<int32_t>();
        extendedStreamInfos.push_back(extendedInfo);
    }
    return true;
}

bool JsonCacheConverter::ParseJsonToSettings(const nlohmann::json& metadataJson,
                                             std::shared_ptr<OHOS::Camera::CameraMetadata>& settings)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::ParseJsonToSettings Begin!");
    std::vector<uint8_t> metadataBytes;
    if (!metadataJson.is_null()) {
        for (auto& elem : metadataJson) {
            CHECK_RETURN_RET_ELOG(!elem.is_number_integer(), false,
                                  "ParseJsonToSettings: elem from json is not int");
            int tempElem = elem.get<int>();
            CHECK_RETURN_RET_ELOG(tempElem < UINT8_MIN_VAL || tempElem > UINT8_MAX_VAL, false,
                                  "ParseJsonToSettings: illegal value of elem from json");
            metadataBytes.push_back(elem.get<uint8_t>());
        }
        OHOS::Camera::MetadataUtils::ConvertVecToMetadata(metadataBytes, settings);
        CHECK_RETURN_RET_ELOG(settings == nullptr, false, "Failed to convert vec to settings.");
    }
    CHECK_PRINT_ELOG(settings == nullptr, "Get null settings from json file.");
    return true;
}

bool JsonCacheConverter::ParseJsonToCloseCameraTime(const nlohmann::json&  closeCameraTimeJson,
    timeval& closeCameraTime)
{
    CHECK_RETURN_RET_ELOG(!closeCameraTimeJson.contains("tv_sec"), false,
                          "key tv_sec not in closeCameraTimeJson");
    CHECK_RETURN_RET_ELOG(!closeCameraTimeJson.contains("tv_usec"), false,
                          "key tv_usec not in closeCameraTimeJson");
    CHECK_RETURN_RET_ELOG(!closeCameraTimeJson["tv_sec"].is_number_integer(), false,
                          "ParseJsonToCloseCameraTime: tv_sec from json is not int");
    CHECK_RETURN_RET_ELOG(!closeCameraTimeJson["tv_usec"].is_number_integer(), false,
                          "ParseJsonToCloseCameraTime: tv_usec from json is not int");

    closeCameraTime.tv_sec = closeCameraTimeJson["tv_sec"].get<time_t>();
    closeCameraTime.tv_usec = closeCameraTimeJson["tv_usec"].get<suseconds_t>();
    return true;
}

bool JsonCacheConverter::SaveMapToJsonFile(const std::string& jsonFilePath,
    const std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>>& pMap,
    const std::map<std::string, sptr<HCameraRestoreParam>>& tMap,
    const std::string& clientName, const std::string& cameraId)
{
    MEDIA_INFO_LOG("JsonCacheConverter::SaveMapToJsonFile Begin!");
    nlohmann::json pMapJson;
    SavePMapToJson(pMap, pMapJson);
    nlohmann::json tMapJson;
    SaveTMapToJson(tMap, tMapJson);
    nlohmann::json indexJson;
    SaveIndexToJson(clientName, cameraId, indexJson);

    CHECK_RETURN_RET_ELOG(!OutputToJsonFile(jsonFilePath, pMapJson, tMapJson, indexJson),
                          false,
                          "Failed to OutputToJsonFile");
    return true;
}

void JsonCacheConverter::SavePMapToJson(const std::map<std::string,
                                        std::map<std::string, sptr<HCameraRestoreParam>>> &persistentParamMap,
                                        nlohmann::json& pMapJson)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::SavePMapToJson Begin!");
    nlohmann::json persistentParamMapJson;
    for (const auto& outerPair : persistentParamMap) {
        const std::string& outerKey = outerPair.first;
        const auto& innerMap = outerPair.second;
        nlohmann::json outerJson;
        for (const auto& innerPair : innerMap) {
            const std::string& innerKey = innerPair.first;
            const sptr<HCameraRestoreParam>& param = innerPair.second;
            CHECK_EXECUTE(!param, continue);
            nlohmann::json paramJson;
            SaveParamToJson(paramJson, param);
            outerJson[innerKey] = paramJson;
        }
        persistentParamMapJson[outerKey] = outerJson;
    }
    pMapJson = persistentParamMapJson;
}

void JsonCacheConverter::SaveTMapToJson(const std::map<std::string,
                                        sptr<HCameraRestoreParam>> &transitentParamMap,
                                        nlohmann::json& tMapJson)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::SaveTMapToJson Begin!");
    nlohmann::json transitentParamMapJson;
    for (const auto& pair : transitentParamMap) {
        const std::string& key = pair.first;
        const sptr<HCameraRestoreParam>& param = pair.second;
        CHECK_EXECUTE(!param, continue);
        nlohmann::json paramJson;
        SaveParamToJson(paramJson, param);
        transitentParamMapJson[key] = paramJson;
    }
    tMapJson = transitentParamMapJson;
}

void JsonCacheConverter::SaveParamToJson(nlohmann::json& paramJson, const sptr<HCameraRestoreParam>& param)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::SaveParamToJson Begin!");
    paramJson["clientName"] = param->GetClientName();
    paramJson["cameraId"] = param->GetCameraId();

    nlohmann::json streamInfosJson = nlohmann::json::array();
    const auto& streamInfos = param->GetStreamInfo();
    SaveStreamInfosToJson(streamInfos, streamInfosJson);
    paramJson["streamInfos"] = streamInfosJson;

    const auto& settings = param->GetSetting();
    SaveSettingsToJson(settings, paramJson);

    const RestoreParamTypeOhos restoreParamType = param->GetRestoreParamType();
    paramJson["restoreParamType"] = static_cast<int>(restoreParamType);

    const timeval& closeCameraTime = param->GetCloseCameraTime();
    nlohmann::json closeCameraTimeJson;
    closeCameraTimeJson["tv_sec"] = closeCameraTime.tv_sec;
    closeCameraTimeJson["tv_usec"] = closeCameraTime.tv_usec;
    paramJson["closeCameraTime"] = closeCameraTimeJson;

    paramJson["cameraOpMode"] = param->GetCameraOpMode();
    paramJson["foldStatus"] = param->GetFlodStatus();
    paramJson["startActiveTime"] = param->GetStartActiveTime();
}

void JsonCacheConverter::SaveStreamInfosToJson(const std::vector<StreamInfo_V1_1> &streamInfos,
                                               nlohmann::json& streamInfosJson)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::SaveStreamInfosToJson Begin!");
    for (const auto& streamInfo : streamInfos) {
        nlohmann::json streamInfoJson;

        const auto& v1_0 = streamInfo.v1_0;
        nlohmann::json streamInfoV1_0Json;
        streamInfoV1_0Json["streamId"] = v1_0.streamId_;
        streamInfoV1_0Json["width"] = v1_0.width_;
        streamInfoV1_0Json["height"] = v1_0.height_;
        streamInfoV1_0Json["format"] = v1_0.format_;
        streamInfoV1_0Json["dataspace"] = v1_0.dataspace_;
        streamInfoV1_0Json["intent"] = static_cast<int>(v1_0.intent_);
        streamInfoV1_0Json["tunneledMode"] = v1_0.tunneledMode_;
        streamInfoV1_0Json["minFrameDuration"] = v1_0.minFrameDuration_;
        streamInfoV1_0Json["encodeType"] = static_cast<int>(v1_0.encodeType_);
        streamInfoJson["v1_0"] = streamInfoV1_0Json;

        const auto& extendedInfos = streamInfo.extendedStreamInfos;
        nlohmann::json extendedInfosJson = nlohmann::json::array();
        for (const auto& extendedInfo : extendedInfos) {
            nlohmann::json extendedInfoJson;
            extendedInfoJson["type"] = static_cast<int>(extendedInfo.type);
            extendedInfoJson["width"] = extendedInfo.width;
            extendedInfoJson["height"] = extendedInfo.height;
            extendedInfoJson["format"] = extendedInfo.format;
            extendedInfoJson["dataspace"] = extendedInfo.dataspace;
            extendedInfosJson.push_back(extendedInfoJson);
        }
        streamInfoJson["extendedStreamInfos"] = extendedInfosJson;
        streamInfosJson.push_back(streamInfoJson);
    }
}

void JsonCacheConverter::SaveSettingsToJson(const std::shared_ptr<OHOS::Camera::CameraMetadata> settings,
                                            nlohmann::json& paramJson)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::SaveSettingsToJson Begin!");
    if (settings) {
        std::vector<uint8_t> metadataBytes;
        if (OHOS::Camera::MetadataUtils::ConvertMetadataToVec(settings, metadataBytes)) {
            nlohmann::json metadataJson = nlohmann::json::array();
            for (uint8_t byte : metadataBytes) {
                metadataJson.push_back(byte);
            }
            paramJson["settings"] = metadataJson;
        } else {
            MEDIA_ERR_LOG("Failed to Convert Settings To Vec.");
            paramJson["settings"] = nlohmann::json::value_t::null;
        }
    } else {
        MEDIA_ERR_LOG("settings is nullptr.");
        paramJson["settings"] = nlohmann::json::value_t::null;
    }
}

void JsonCacheConverter::SaveIndexToJson(const std::string& clientName,
                                         const std::string& cameraId,
                                         nlohmann::json& indexJson)
{
    indexJson["clientName"] = clientName;
    indexJson["cameraId"] = cameraId;
}

bool JsonCacheConverter::CheckParamJson(const nlohmann::json& paramJson)
{
    CHECK_RETURN_RET_ELOG(!paramJson.contains("streamInfos"), false, "key streamInfos not in paramJson");
    CHECK_RETURN_RET_ELOG(!paramJson.contains("settings"), false, "key settings not in paramJson");
    CHECK_RETURN_RET_ELOG(!paramJson.contains("closeCameraTime"), false, "key closeCameraTime not in paramJson");
    CHECK_RETURN_RET_ELOG(!paramJson.contains("restoreParamType"), false, "key restoreParamType not in paramJson");
    CHECK_RETURN_RET_ELOG(!paramJson.contains("startActiveTime"), false, "key startActiveTime not in paramJson");
    CHECK_RETURN_RET_ELOG(!paramJson.contains("cameraOpMode"), false, "key cameraOpMode not in paramJson");
    CHECK_RETURN_RET_ELOG(!paramJson.contains("foldStatus"), false, "key foldStatus not in paramJson");
    return true;
}

bool JsonCacheConverter::OutputToJsonFile(const std::string& jsonFilePath,
                                          const nlohmann::json& pMapJson,
                                          const nlohmann::json& tMapJson,
                                          const nlohmann::json& indexJson)
{
    MEDIA_DEBUG_LOG("JsonCacheConverter::OutputToJsonFile Begin!");
    nlohmann::json rootJson;
    rootJson["PmapJson"] = pMapJson;
    rootJson["TmapJson"] = tMapJson;
    rootJson["IndexJson"] = indexJson;

    std::ofstream outFile(jsonFilePath);
    CHECK_RETURN_RET_ELOG(!outFile.is_open(), false, "Failed to open file");
    std::string jsonStr = rootJson.dump(JSON_INDENT_SPACES_FOR_DEBUG);
    outFile << jsonStr;
    CHECK_RETURN_RET_ELOG(!outFile.good(), false, "failed to write to json file");
    outFile.flush();
    CHECK_RETURN_RET_ELOG(!outFile.good(), false, "failed to flush to json file");
    return true;
}

bool JsonCacheConverter::CreateProducerForPrelaunch(OHOS::HDI::Camera::V1_0::StreamInfo &v1_0)
{
    MEDIA_DEBUG_LOG("Create Producer of StreamInfo For Prelaunch !");
    sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(v1_0.format_,
                                                                           v1_0.width_,
                                                                           v1_0.height_);
    CHECK_RETURN_RET_ELOG(streamCapture == nullptr, false, "Failed to create streamCapture");
    CHECK_RETURN_RET_ELOG(streamCapture->surface_ == nullptr, false, "surface_ == nullptr");
    v1_0.bufferQueue_ = new BufferProducerSequenceable(streamCapture->surface_->GetProducer());
    return true;
}

bool JsonCacheConverter::CreateProducerForPrelaunch(std::vector<OHOS::HDI::Camera::V1_1::ExtendedStreamInfo>
                                                    &extendedStreamInfos)
{
    MEDIA_DEBUG_LOG("Create Producer of ExtendedStreamInfo For Prelaunch !");
    for (auto& extendedStreamInfo : extendedStreamInfos) {
        sptr<HStreamCapture> streamCapture = new (std::nothrow) HStreamCapture(extendedStreamInfo.format,
                                                                            extendedStreamInfo.width,
                                                                            extendedStreamInfo.height);
        CHECK_RETURN_RET_ELOG(streamCapture == nullptr, false, "Failed to create streamCapture");
        CHECK_RETURN_RET_ELOG(streamCapture->surface_ == nullptr, false, "surface_ == nullptr");
        extendedStreamInfo.bufferQueue = new BufferProducerSequenceable(streamCapture->surface_->GetProducer());
    }
    return true;
}
}
}