#include <fuzzer/FuzzedDataProvider.h>
#include "camera_log.h"
#include "nlohmann/json.hpp"
#include "json_cache_converter/json_cache_converter.h"
#include "hcamera_restore_param.h"
#include <fstream>
#include "test_token.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;

static const int32_t STR_MAX_LEN = 32;
static const std::string RESOURCE_PATH = "/data/local/tmp";
static const std::string JSON_FILE_PATH = "/data/local/tmp/SaveRestore.json";
nlohmann::json g_rootJson;
void ParseJsonToPMapTest1(FuzzedDataProvider& fdp)
{
    // 生成随机的文件路径
    std::string jsonFilePath = RESOURCE_PATH + fdp.ConsumeRandomLengthString(STR_MAX_LEN);

    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>> pMap;
    std::map<std::string, sptr<HCameraRestoreParam>> tMap;
    std::string clientName;
    std::string cameraId;

    // fuzzed path input
    JsonCacheConverter::ParseJsonFileToMap(jsonFilePath, pMap, tMap, clientName, cameraId);

    // normal path input
    JsonCacheConverter::ParseJsonFileToMap(JSON_FILE_PATH, pMap, tMap, clientName, cameraId);
}

void ParseJsonToPMapTest2(FuzzedDataProvider& fdp)
{
    // 生成随机的JSON内容
    nlohmann::json fuzzedRootJson;

    // 生成随机的客户端名称和cameraId
    std::string clientName = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string cameraId = fdp.ConsumeRandomLengthString(STR_MAX_LEN);

    // 构建随机的PmapJson结构
    nlohmann::json PmapJson;
    nlohmann::json innerJson;

    // 随机生成innerJson的内容
    innerJson["cameraId"] = cameraId;
    innerJson["cameraOpMode"] = fdp.ConsumeIntegral<int32_t>();
    innerJson["clientName"] = clientName;
    innerJson["closeCameraTime"] = { { "tv_sec", fdp.ConsumeIntegral<int32_t>() },
        { "tv_usec", fdp.ConsumeIntegral<int32_t>() } };
    innerJson["foldStatus"] = fdp.ConsumeIntegral<int32_t>();
    innerJson["restoreParamType"] = fdp.ConsumeIntegral<int32_t>();
    innerJson["settings"] = fdp.ConsumeIntegral<int32_t>();
    innerJson["startActiveTime"] = fdp.ConsumeIntegral<int32_t>();

    // 将innerJson添加到PmapJson中
    PmapJson[clientName][cameraId] = innerJson;

    // 将PmapJson添加到rootJson中
    fuzzedRootJson["PmapJson"] = PmapJson;

    // fuzzed json input
    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>> pMap;
    JsonCacheConverter::ParseJsonToPMap(fuzzedRootJson, pMap);

    // normal json input
    JsonCacheConverter::ParseJsonToPMap(g_rootJson, pMap);
}

void ParseJsonToIndexTest(FuzzedDataProvider& fdp)
{
    // 生成随机的JSON内容
    nlohmann::json fuzzedRootJson;

    // 生成随机的clientName和cameraId
    std::string clientName = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string cameraId = fdp.ConsumeRandomLengthString(STR_MAX_LEN);

    // 构建随机的IndexJson结构
    nlohmann::json IndexJson;
    IndexJson["clientName"] = clientName;
    IndexJson["cameraId"] = cameraId;

    // 将IndexJson添加到rootJson中
    fuzzedRootJson["IndexJson"] = IndexJson;

    // 调用ParseJsonToIndex函数
    std::string parsedClientName;
    std::string parsedCameraId;
    JsonCacheConverter::ParseJsonToIndex(fuzzedRootJson, parsedClientName, parsedCameraId);

    // normal json input
    JsonCacheConverter::ParseJsonToIndex(g_rootJson, parsedClientName, parsedCameraId);
}

void ParseJsonToParamTest(FuzzedDataProvider& fdp)
{
    // 生成随机的JSON内容
    nlohmann::json fuzzedParamJson;

    // 生成随机的参数值
    std::string clientName = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string cameraId = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
    int32_t cameraOpMode = fdp.ConsumeIntegral<int32_t>();
    int32_t foldStatus = fdp.ConsumeIntegral<int32_t>();
    int32_t restoreParamType = fdp.ConsumeIntegral<int32_t>();
    int32_t startActiveTime = fdp.ConsumeIntegral<int32_t>();

    // 随机生成streamInfos数组
    nlohmann::json streamInfosJson =
        fdp.ConsumeIntegral<uint32_t>() % 2 ? nlohmann::json::array() : nlohmann::json::array();
    for (size_t i = 0; i < fdp.ConsumeIntegral<uint32_t>() % 10; ++i) {
        nlohmann::json streamInfo;
        streamInfo["extendedStreamInfos"] = nlohmann::json::array();
        streamInfo["v1_0"] = nlohmann::json();
        streamInfosJson.push_back(streamInfo);
    }

    // 随机生成settings数组
    nlohmann::json settingsJson = nlohmann::json::array();
    for (size_t i = 0; i < fdp.ConsumeIntegral<uint32_t>() % 10; ++i) {
        settingsJson.push_back(fdp.ConsumeIntegral<int32_t>());
    }

    // 随机生成closeCameraTime
    nlohmann::json closeCameraTimeJson;
    closeCameraTimeJson["tv_sec"] = fdp.ConsumeIntegral<int32_t>();
    closeCameraTimeJson["tv_usec"] = fdp.ConsumeIntegral<int32_t>();

    // 构建完整的paramJson
    fuzzedParamJson["cameraId"] = cameraId;
    fuzzedParamJson["cameraOpMode"] = cameraOpMode;
    fuzzedParamJson["clientName"] = clientName;
    fuzzedParamJson["closeCameraTime"] = closeCameraTimeJson;
    fuzzedParamJson["foldStatus"] = foldStatus;
    fuzzedParamJson["restoreParamType"] = restoreParamType;
    fuzzedParamJson["settings"] = settingsJson;
    fuzzedParamJson["startActiveTime"] = startActiveTime;
    fuzzedParamJson["streamInfos"] = streamInfosJson;

    // 创建HCameraRestoreParam对象
    sptr<HCameraRestoreParam> cameraRestoreParam = new HCameraRestoreParam(clientName, cameraId);

    // 调用ParseJsonToParam函数
    JsonCacheConverter::ParseJsonToParam(fuzzedParamJson, cameraRestoreParam);

    // normal json input
    nlohmann::json normalParamJson = g_rootJson["PmapJson"]["com.huawei.hmos.camera"]["device/0"];
    JsonCacheConverter::ParseJsonToParam(normalParamJson, cameraRestoreParam);
}

void ParseJsonToStreamInfosTest(FuzzedDataProvider& fdp)
{
    // 生成随机的JSON内容
    nlohmann::json fuzzedStreamInfosJson;

    // 随机生成streamInfos数组
    size_t streamInfosCount = fdp.ConsumeIntegral<uint32_t>() % 10;
    for (size_t i = 0; i < streamInfosCount; ++i) {
        nlohmann::json streamInfoJson;

        // 生成随机的v1_0内容
        nlohmann::json v1_0Json;
        v1_0Json["dataspace"] = fdp.ConsumeIntegral<int32_t>();
        v1_0Json["encodeType"] = fdp.ConsumeIntegral<int32_t>();
        v1_0Json["format"] = fdp.ConsumeIntegral<int32_t>();
        v1_0Json["hasBufferQueue"] = fdp.ConsumeBool();
        v1_0Json["height"] = fdp.ConsumeIntegral<int32_t>();
        v1_0Json["intent"] = fdp.ConsumeIntegral<int32_t>();
        v1_0Json["minFrameDuration"] = fdp.ConsumeIntegral<int32_t>();
        v1_0Json["streamId"] = fdp.ConsumeIntegral<int32_t>();
        v1_0Json["tunneledMode"] = fdp.ConsumeBool();
        v1_0Json["width"] = fdp.ConsumeIntegral<int32_t>();

        // 生成随机的extendedStreamInfos数组
        size_t extendedInfosCount = fdp.ConsumeIntegral<uint32_t>() % 5;
        nlohmann::json extendedInfosJson = nlohmann::json::array();
        for (size_t j = 0; j < extendedInfosCount; ++j) {
            nlohmann::json extendedInfoJson;
            extendedInfoJson["dataspace"] = fdp.ConsumeIntegral<int32_t>();
            extendedInfoJson["format"] = fdp.ConsumeIntegral<int32_t>();
            extendedInfoJson["hasBufferQueue"] = fdp.ConsumeBool();
            extendedInfoJson["height"] = fdp.ConsumeIntegral<int32_t>();
            extendedInfoJson["type"] = fdp.ConsumeIntegral<int32_t>();
            extendedInfoJson["width"] = fdp.ConsumeIntegral<int32_t>();
            extendedInfosJson.push_back(extendedInfoJson);
        }

        // 将v1_0和extendedStreamInfos添加到streamInfoJson
        streamInfoJson["v1_0"] = v1_0Json;
        streamInfoJson["extendedStreamInfos"] = extendedInfosJson;

        // 将streamInfoJson添加到streamInfosJson数组中
        fuzzedStreamInfosJson.push_back(streamInfoJson);
    }

    // 创建存储流信息的向量
    std::vector<StreamInfo_V1_1> streamInfos;

    // 调用ParseJsonToStreamInfos函数
    JsonCacheConverter::ParseJsonToStreamInfos(fuzzedStreamInfosJson, streamInfos);

    // normal json input
    nlohmann::json normalStreamInfosJson = g_rootJson["PmapJson"]["com.huawei.hmos.camera"]["device/0"]["streamInfos"];
    JsonCacheConverter::ParseJsonToStreamInfos(normalStreamInfosJson, streamInfos);
}

void ParseJsonToStreamInfoV1_0Test(FuzzedDataProvider& fdp)
{
    // 生成随机的JSON内容
    nlohmann::json fuzzedStreamInfoJson;

    // 生成随机的字段值
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    int32_t width = fdp.ConsumeIntegral<int32_t>();
    int32_t height = fdp.ConsumeIntegral<int32_t>();
    int32_t format = fdp.ConsumeIntegral<int32_t>();
    int32_t dataspace = fdp.ConsumeIntegral<int32_t>();
    int32_t intent = fdp.ConsumeIntegral<int32_t>();
    bool tunneledMode = fdp.ConsumeBool();
    int32_t minFrameDuration = fdp.ConsumeIntegral<int32_t>();
    int32_t encodeType = fdp.ConsumeIntegral<int32_t>();

    // 构建随机的StreamInfo JSON
    fuzzedStreamInfoJson["streamId"] = streamId;
    fuzzedStreamInfoJson["width"] = width;
    fuzzedStreamInfoJson["height"] = height;
    fuzzedStreamInfoJson["format"] = format;
    fuzzedStreamInfoJson["dataspace"] = dataspace;
    fuzzedStreamInfoJson["intent"] = intent;
    fuzzedStreamInfoJson["tunneledMode"] = tunneledMode;
    fuzzedStreamInfoJson["minFrameDuration"] = minFrameDuration;
    fuzzedStreamInfoJson["encodeType"] = encodeType;

    // 创建StreamInfo对象
    OHOS::HDI::Camera::V1_0::StreamInfo streamInfo;

    // 调用ParseJsonToStreamInfoV1_0函数
    bool result = JsonCacheConverter::ParseJsonToStreamInfoV1_0(fuzzedStreamInfoJson, streamInfo);

    // normal json input
    nlohmann::json normalStreamInfoJson =
        g_rootJson["PmapJson"]["com.huawei.hmos.camera"]["device/0"]["streamInfos"][0]["v1_0"];
    result = JsonCacheConverter::ParseJsonToStreamInfoV1_0(normalStreamInfoJson, streamInfo);
}

void CheckStreamInfoV1_0JsonTest(FuzzedDataProvider& fdp)
{
    // 生成随机的JSON内容
    nlohmann::json fuzzedStreamInfoJson;

    // 生成随机的字段值
    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    int32_t width = fdp.ConsumeIntegral<int32_t>();
    int32_t height = fdp.ConsumeIntegral<int32_t>();
    int32_t format = fdp.ConsumeIntegral<int32_t>();
    int32_t dataspace = fdp.ConsumeIntegral<int32_t>();
    int32_t intent = fdp.ConsumeIntegral<int32_t>();
    bool tunneledMode = fdp.ConsumeBool();
    int32_t minFrameDuration = fdp.ConsumeIntegral<int32_t>();
    int32_t encodeType = fdp.ConsumeIntegral<int32_t>();
    bool hasBufferQueue = fdp.ConsumeBool();

    // 构建随机的StreamInfo JSON
    fuzzedStreamInfoJson["streamId"] = streamId;
    fuzzedStreamInfoJson["width"] = width;
    fuzzedStreamInfoJson["height"] = height;
    fuzzedStreamInfoJson["format"] = format;
    fuzzedStreamInfoJson["dataspace"] = dataspace;
    fuzzedStreamInfoJson["intent"] = intent;
    fuzzedStreamInfoJson["tunneledMode"] = tunneledMode;
    fuzzedStreamInfoJson["minFrameDuration"] = minFrameDuration;
    fuzzedStreamInfoJson["encodeType"] = encodeType;
    fuzzedStreamInfoJson["hasBufferQueue"] = hasBufferQueue;

    // 调用CheckStreamInfoV1_0Json函数
    bool result = JsonCacheConverter::CheckStreamInfoV1_0Json(fuzzedStreamInfoJson);

    // normal json input
    nlohmann::json normalStreamInfoJson =
        g_rootJson["PmapJson"]["com.huawei.hmos.camera"]["device/0"]["streamInfos"][0]["v1_0"];
    result = JsonCacheConverter::CheckStreamInfoV1_0Json(normalStreamInfoJson);
}

void ParseJsonToExtendedInfoTest(FuzzedDataProvider& fdp)
{
    // 生成随机的JSON内容
    nlohmann::json fuzzedExtendedInfosJson = nlohmann::json::array();

    // 随机生成1-5个扩展流信息
    size_t extendedInfosCount = fdp.ConsumeIntegral<uint32_t>() % 5 + 1;
    for (size_t i = 0; i < extendedInfosCount; ++i) {
        nlohmann::json extendedInfoJson;

        // 生成随机的字段值
        int32_t type = fdp.ConsumeIntegral<int32_t>() %
                (ENUM_LIMIT - HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL + 1) +
            HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL;
        int32_t width = fdp.ConsumeIntegral<int32_t>();
        int32_t height = fdp.ConsumeIntegral<int32_t>();
        int32_t format = fdp.ConsumeIntegral<int32_t>();
        int32_t dataspace = fdp.ConsumeIntegral<int32_t>();
        bool hasBufferQueue = fdp.ConsumeBool();

        // 构建扩展流信息JSON
        extendedInfoJson["type"] = type;
        extendedInfoJson["width"] = width;
        extendedInfoJson["height"] = height;
        extendedInfoJson["format"] = format;
        extendedInfoJson["dataspace"] = dataspace;
        extendedInfoJson["hasBufferQueue"] = hasBufferQueue;

        fuzzedExtendedInfosJson.push_back(extendedInfoJson);
    }

    // 创建存储扩展流信息的向量
    std::vector<OHOS::HDI::Camera::V1_1::ExtendedStreamInfo> extendedStreamInfos;

    // 调用ParseJsonToExtendedInfo函数
    bool result = JsonCacheConverter::ParseJsonToExtendedInfo(fuzzedExtendedInfosJson, extendedStreamInfos);

    // 使用正常JSON输入进行测试
    nlohmann::json normalExtendedInfosJson =
        g_rootJson["PmapJson"]["com.huawei.hmos.camera"]["device/0"]["streamInfos"][0]["extendedStreamInfos"];
    result = JsonCacheConverter::ParseJsonToExtendedInfo(normalExtendedInfosJson, extendedStreamInfos);
}

void Init()
{
    CHECK_RETURN_ELOG(!TestToken().GetAllCameraPermission(), "Get permission fail");
    std::ifstream file(JSON_FILE_PATH);
    if (!file.is_open()) {
        MEDIA_INFO_LOG("open file fail:%{public}s", JSON_FILE_PATH.c_str());
    }

    // 将文件内容解析为JSON对象
    g_rootJson = nlohmann::json::parse(file);
    MEDIA_INFO_LOG("camera_service_json_fuzzer g_rootJson:%{public}s", g_rootJson.dump().c_str());
}

void ParseJsonToSettingsTest(FuzzedDataProvider& fdp)
{
    // 创建存储设置的智能指针
    std::shared_ptr<OHOS::Camera::CameraMetadata> settings = std::make_shared<OHOS::Camera::CameraMetadata>(300, 100);

    // 测试空JSON输入
    nlohmann::json emptyJson;
    JsonCacheConverter::ParseJsonToSettings(emptyJson, settings);

    // 使用正常JSON输入进行测试
    nlohmann::json normalMetadataJson = g_rootJson["PmapJson"]["com.huawei.hmos.camera"]["device/0"]["settings"];
    JsonCacheConverter::ParseJsonToSettings(normalMetadataJson, settings);
}

void ParseJsonToCloseCameraTimeTest(FuzzedDataProvider& fdp)
{
    // 生成随机的JSON内容
    nlohmann::json fuzzedCloseCameraTimeJson;

    // 随机生成tv_sec和tv_usec字段
    if (fdp.ConsumeBool()) {
        fuzzedCloseCameraTimeJson["tv_sec"] = fdp.ConsumeIntegral<time_t>();
    }
    if (fdp.ConsumeBool()) {
        fuzzedCloseCameraTimeJson["tv_usec"] = fdp.ConsumeIntegral<suseconds_t>();
    }

    // 创建存储关闭时间的结构体
    timeval closeCameraTime;

    // 调用ParseJsonToCloseCameraTime函数
    bool result = JsonCacheConverter::ParseJsonToCloseCameraTime(fuzzedCloseCameraTimeJson, closeCameraTime);

    // 测试正常JSON输入
    nlohmann::json normalCloseCameraTimeJson =
        g_rootJson["PmapJson"]["com.huawei.hmos.camera"]["device/0"]["closeCameraTime"];
    result = JsonCacheConverter::ParseJsonToCloseCameraTime(normalCloseCameraTimeJson, closeCameraTime);

    // 测试边界值
    nlohmann::json boundaryCloseCameraTimeJson1 = { { "tv_sec", INT32_MAX }, { "tv_usec", INT32_MAX } };
    result = JsonCacheConverter::ParseJsonToCloseCameraTime(boundaryCloseCameraTimeJson1, closeCameraTime);

    nlohmann::json boundaryCloseCameraTimeJson2 = { { "tv_sec", INT32_MIN }, { "tv_usec", INT32_MIN } };
    result = JsonCacheConverter::ParseJsonToCloseCameraTime(boundaryCloseCameraTimeJson2, closeCameraTime);
}

void SaveMapToJsonFileTest(FuzzedDataProvider& fdp)
{
    // 生成随机的文件路径
    std::string jsonFilePath = RESOURCE_PATH + fdp.ConsumeRandomLengthString(STR_MAX_LEN);

    // 生成随机的客户端名称和cameraId
    std::string clientName = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string cameraId = fdp.ConsumeRandomLengthString(STR_MAX_LEN);

    // 创建随机的pMap和tMap
    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>> pMap;
    std::map<std::string, sptr<HCameraRestoreParam>> tMap;

    // 随机生成pMap内容
    size_t pMapSize = fdp.ConsumeIntegral<uint32_t>() % 5 + 1;
    for (size_t i = 0; i < pMapSize; ++i) {
        std::string clientKey = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
        std::map<std::string, sptr<HCameraRestoreParam>> innerMap;

        size_t innerMapSize = fdp.ConsumeIntegral<uint32_t>() % 3 + 1;
        for (size_t j = 0; j < innerMapSize; ++j) {
            std::string cameraKey = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
            innerMap[cameraKey] = new HCameraRestoreParam(clientKey, cameraKey);
        }

        pMap[clientKey] = innerMap;
    }

    // 随机生成tMap内容
    size_t tMapSize = fdp.ConsumeIntegral<uint32_t>() % 3 + 1;
    for (size_t i = 0; i < tMapSize; ++i) {
        std::string cameraKey = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
        tMap[cameraKey] = new HCameraRestoreParam(clientName, cameraId);
    }

    // 调用SaveMapToJsonFile函数
    bool result = JsonCacheConverter::SaveMapToJsonFile(jsonFilePath, pMap, tMap, clientName, cameraId);

    // 测试边界情况
    // 空pMap和tMap
    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>> emptyPMap;
    std::map<std::string, sptr<HCameraRestoreParam>> emptyTMap;
    result = JsonCacheConverter::SaveMapToJsonFile(jsonFilePath, emptyPMap, emptyTMap, "", "");

    // 无效文件路径
    std::string invalidPath = "/invalid/path/SaveRestore.json";
    result = JsonCacheConverter::SaveMapToJsonFile(invalidPath, pMap, tMap, clientName, cameraId);
}

void SavePMapToJsonTest(FuzzedDataProvider& fdp)
{
    // 创建随机的pMap
    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>> persistentParamMap;

    // 随机生成pMap内容
    size_t pMapSize = fdp.ConsumeIntegral<uint32_t>() % 5 + 1;
    for (size_t i = 0; i < pMapSize; ++i) {
        std::string clientKey = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
        std::map<std::string, sptr<HCameraRestoreParam>> innerMap;

        size_t innerMapSize = fdp.ConsumeIntegral<uint32_t>() % 3 + 1;
        for (size_t j = 0; j < innerMapSize; ++j) {
            std::string cameraKey = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
            innerMap[cameraKey] = new HCameraRestoreParam(clientKey, cameraKey);
        }

        persistentParamMap[clientKey] = innerMap;
    }

    // 创建空的JSON对象
    nlohmann::json pMapJson;

    // 调用SavePMapToJson函数
    JsonCacheConverter::SavePMapToJson(persistentParamMap, pMapJson);

    // 测试边界情况
    // 空pMap
    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>> emptyPMap;
    nlohmann::json emptyJson;
    JsonCacheConverter::SavePMapToJson(emptyPMap, emptyJson);

    // 单层空映射
    std::map<std::string, std::map<std::string, sptr<HCameraRestoreParam>>> singleLayerPMap;
    singleLayerPMap["client1"] = {};
    nlohmann::json singleLayerJson;
    JsonCacheConverter::SavePMapToJson(singleLayerPMap, singleLayerJson);

    // 验证生成的JSON结构
    for (const auto& outerPair : persistentParamMap) {
        const std::string& outerKey = outerPair.first;
        const auto& innerMap = outerPair.second;

        // 检查外层键是否存在
        if (!pMapJson.contains(outerKey)) {
            continue;
        }

        const auto& outerJson = pMapJson[outerKey];

        for (const auto& innerPair : innerMap) {
            const std::string& innerKey = innerPair.first;

            // 检查内层键是否存在
            if (!outerJson.contains(innerKey)) {
                continue;
            }

            const auto& paramJson = outerJson[innerKey];

            // 验证JSON结构是否正确
            if (!paramJson.contains("cameraId") || !paramJson.contains("clientName") ||
                !paramJson.contains("streamInfos")) {
                continue;
            }

            // 可以进一步验证具体字段值
        }
    }
}

void SaveTMapToJsonTest(FuzzedDataProvider& fdp)
{
    // 创建随机的tMap
    std::map<std::string, sptr<HCameraRestoreParam>> transitentParamMap;

    // 随机生成tMap内容
    size_t tMapSize = fdp.ConsumeIntegral<uint32_t>() % 5 + 1;
    for (size_t i = 0; i < tMapSize; ++i) {
        std::string key = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
        transitentParamMap[key] = new HCameraRestoreParam(
            fdp.ConsumeRandomLengthString(STR_MAX_LEN), fdp.ConsumeRandomLengthString(STR_MAX_LEN));
    }

    // 创建空的JSON对象
    nlohmann::json tMapJson;

    // 调用SaveTMapToJson函数
    JsonCacheConverter::SaveTMapToJson(transitentParamMap, tMapJson);

    // 测试边界情况
    // 空tMap
    std::map<std::string, sptr<HCameraRestoreParam>> emptyTMap;
    nlohmann::json emptyJson;
    JsonCacheConverter::SaveTMapToJson(emptyTMap, emptyJson);

    // 包含空指针的tMap
    std::map<std::string, sptr<HCameraRestoreParam>> nullPointerTMap;
    nullPointerTMap["key1"] = nullptr;
    nlohmann::json nullPointerJson;
    JsonCacheConverter::SaveTMapToJson(nullPointerTMap, nullPointerJson);

    // 验证生成的JSON结构
    for (const auto& pair : transitentParamMap) {
        const std::string& key = pair.first;

        // 检查键是否存在
        if (!tMapJson.contains(key)) {
            continue;
        }

        const auto& paramJson = tMapJson[key];

        // 验证JSON结构是否正确
        if (!paramJson.contains("cameraId") || !paramJson.contains("clientName") ||
            !paramJson.contains("streamInfos")) {
            continue;
        }

        // 可以进一步验证具体字段值
    }
}

void SaveParamToJsonTest(FuzzedDataProvider& fdp)
{
    // 创建随机的HCameraRestoreParam对象
    std::string clientName = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string cameraId = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
    sptr<HCameraRestoreParam> param = new HCameraRestoreParam(clientName, cameraId);

    // 设置随机的流信息
    size_t streamCount = fdp.ConsumeIntegral<uint32_t>() % 5 + 1;
    std::vector<StreamInfo_V1_1> streamInfos;
    for (size_t i = 0; i < streamCount; ++i) {
        StreamInfo_V1_1 streamInfo;
        streamInfo.v1_0.streamId_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.width_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.height_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.format_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.dataspace_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.intent_ = static_cast<StreamIntent>(fdp.ConsumeIntegral<int32_t>() % 3);
        streamInfo.v1_0.tunneledMode_ = fdp.ConsumeBool();
        streamInfo.v1_0.minFrameDuration_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.encodeType_ = static_cast<EncodeType>(fdp.ConsumeIntegral<int32_t>() % 2);
        streamInfos.push_back(streamInfo);
    }
    param->SetStreamInfo(streamInfos);

    // 设置随机的其他参数
    param->SetRestoreParamType(static_cast<RestoreParamTypeOhos>(fdp.ConsumeIntegral<int32_t>() % 2));
    param->SetCloseCameraTime({ fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>() });
    param->SetCameraOpMode(fdp.ConsumeIntegral<int32_t>() % 3);
    param->SetStartActiveTime(fdp.ConsumeIntegral<int32_t>());

    // 创建空的JSON对象
    nlohmann::json paramJson;

    // 调用SaveParamToJson函数
    JsonCacheConverter::SaveParamToJson(paramJson, param);
}

void SaveStreamInfosToJsonTest(FuzzedDataProvider& fdp)
{
    // 创建随机的流信息向量
    std::vector<StreamInfo_V1_1> streamInfos;
    size_t streamCount = fdp.ConsumeIntegral<uint32_t>() % 5 + 1;
    for (size_t i = 0; i < streamCount; ++i) {
        StreamInfo_V1_1 streamInfo;
        streamInfo.v1_0.streamId_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.width_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.height_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.format_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.dataspace_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.intent_ = static_cast<StreamIntent>(fdp.ConsumeIntegral<int32_t>() % 3);
        streamInfo.v1_0.tunneledMode_ = fdp.ConsumeBool();
        streamInfo.v1_0.minFrameDuration_ = fdp.ConsumeIntegral<int32_t>();
        streamInfo.v1_0.encodeType_ = static_cast<EncodeType>(fdp.ConsumeIntegral<int32_t>() % 2);

        // 设置扩展流信息
        size_t extendedCount = fdp.ConsumeIntegral<uint32_t>() % 3;
        for (size_t j = 0; j < extendedCount; ++j) {
            OHOS::HDI::Camera::V1_1::ExtendedStreamInfo extendedInfo;
            extendedInfo.type =
                static_cast<OHOS::HDI::Camera::V1_1::ExtendedStreamInfoType>(fdp.ConsumeIntegral<int32_t>() % 2);
            extendedInfo.width = fdp.ConsumeIntegral<int32_t>();
            extendedInfo.height = fdp.ConsumeIntegral<int32_t>();
            extendedInfo.format = fdp.ConsumeIntegral<int32_t>();
            extendedInfo.dataspace = fdp.ConsumeIntegral<int32_t>();
            streamInfo.extendedStreamInfos.push_back(extendedInfo);
        }

        streamInfos.push_back(streamInfo);
    }

    // 创建空的JSON数组
    nlohmann::json streamInfosJson;

    // 调用SaveStreamInfosToJson函数
    JsonCacheConverter::SaveStreamInfosToJson(streamInfos, streamInfosJson);

    for (size_t i = 0; i < streamInfos.size(); ++i) {
        const auto& streamInfoJson = streamInfosJson[i];
        const auto& streamInfo = streamInfos[i];

        // 验证v1_0字段
        const auto& v1_0Json = streamInfoJson["v1_0"];
        if (v1_0Json["streamId"] != streamInfo.v1_0.streamId_ || v1_0Json["width"] != streamInfo.v1_0.width_ ||
            v1_0Json["height"] != streamInfo.v1_0.height_ || v1_0Json["format"] != streamInfo.v1_0.format_ ||
            v1_0Json["dataspace"] != streamInfo.v1_0.dataspace_ ||
            v1_0Json["intent"] != static_cast<int>(streamInfo.v1_0.intent_) ||
            v1_0Json["tunneledMode"] != streamInfo.v1_0.tunneledMode_ ||
            v1_0Json["minFrameDuration"] != streamInfo.v1_0.minFrameDuration_ ||
            v1_0Json["encodeType"] != static_cast<int>(streamInfo.v1_0.encodeType_)) {
            return;
        }

        // 验证extendedStreamInfos字段
        const auto& extendedInfosJson = streamInfoJson["extendedStreamInfos"];
        if (extendedInfosJson.size() != streamInfo.extendedStreamInfos.size()) {
            return;
        }

        for (size_t j = 0; j < streamInfo.extendedStreamInfos.size(); ++j) {
            const auto& extendedInfoJson = extendedInfosJson[j];
            const auto& extendedInfo = streamInfo.extendedStreamInfos[j];

            if (extendedInfoJson["type"] != static_cast<int>(extendedInfo.type) ||
                extendedInfoJson["width"] != extendedInfo.width || extendedInfoJson["height"] != extendedInfo.height ||
                extendedInfoJson["format"] != extendedInfo.format ||
                extendedInfoJson["dataspace"] != extendedInfo.dataspace) {
                return;
            }
        }
    }
}

void SaveIndexToJsonTest(FuzzedDataProvider& fdp)
{
    // 生成随机的客户端名称和cameraId
    std::string clientName = fdp.ConsumeRandomLengthString(STR_MAX_LEN);
    std::string cameraId = fdp.ConsumeRandomLengthString(STR_MAX_LEN);

    // 创建空的JSON对象
    nlohmann::json indexJson;

    // 调用SaveIndexToJson函数
    JsonCacheConverter::SaveIndexToJson(clientName, cameraId, indexJson);
}

void CheckParamJsonTest(FuzzedDataProvider& fdp)
{
    // 生成随机的JSON内容
    nlohmann::json fuzzedParamJson;
    // 随机决定是否包含所有必需字段
    bool hasAllRequiredFields = fdp.ConsumeBool();
    if (hasAllRequiredFields) {
        // 包含所有必需字段
        fuzzedParamJson["streamInfos"] = nlohmann::json::array();
        fuzzedParamJson["settings"] = nlohmann::json::array();
        fuzzedParamJson["closeCameraTime"] = { { "tv_sec", 0 }, { "tv_usec", 0 } };
        fuzzedParamJson["restoreParamType"] = 0;
        fuzzedParamJson["startActiveTime"] = 0;
        fuzzedParamJson["cameraOpMode"] = 0;
        fuzzedParamJson["foldStatus"] = 0;
    } else {
        // 随机移除一个或多个必需字段
        std::vector<std::string> requiredFields = { "streamInfos", "settings", "closeCameraTime", "restoreParamType",
            "startActiveTime", "cameraOpMode", "foldStatus" };

        size_t fieldsToRemove = fdp.ConsumeIntegral<uint32_t>() % requiredFields.size() + 1;
        for (size_t i = 0; i < fieldsToRemove; ++i) {
            size_t index = fdp.ConsumeIntegral<uint32_t>() % requiredFields.size();
            std::string field = requiredFields[index];
            requiredFields.erase(requiredFields.begin() + index);

            // 确保该字段不存在于JSON中
            if (fuzzedParamJson.contains(field)) {
                fuzzedParamJson.erase(field);
            }
        }
    }

    // 调用CheckParamJson函数
    JsonCacheConverter::CheckParamJson(fuzzedParamJson);

    // 测试边界情况
    // 空JSON对象
    nlohmann::json emptyJson;
    JsonCacheConverter::CheckParamJson(emptyJson);

    // 只包含部分字段的JSON
    nlohmann::json partialJson;
    partialJson["streamInfos"] = nlohmann::json::array();
    partialJson["settings"] = nlohmann::json::array();
    JsonCacheConverter::CheckParamJson(partialJson);
    // 测试closeCameraTime字段的各种情况
    nlohmann::json validTime = { { "tv_sec", 1234567890 }, { "tv_usec", 123456 } };
    nlohmann::json invalidTime1 = { { "tv_sec", 1234567890 } };                       // 缺少tv_usec
    nlohmann::json invalidTime2 = { { "tv_usec", 123456 } };                          // 缺少tv_sec
    nlohmann::json invalidTime3 = { { "tv_sec", "invalid" }, { "tv_usec", 123456 } }; // tv_sec不是数字

    nlohmann::json timeTestJson = partialJson;
    timeTestJson["closeCameraTime"] = validTime;
    timeTestJson["restoreParamType"] = 0;
    timeTestJson["startActiveTime"] = 0;
    timeTestJson["cameraOpMode"] = 0;
    timeTestJson["foldStatus"] = 0;

    JsonCacheConverter::CheckParamJson(timeTestJson);

    timeTestJson["closeCameraTime"] = invalidTime1;
    JsonCacheConverter::CheckParamJson(timeTestJson);

    timeTestJson["closeCameraTime"] = invalidTime2;
    JsonCacheConverter::CheckParamJson(timeTestJson);

    timeTestJson["closeCameraTime"] = invalidTime3;
    JsonCacheConverter::CheckParamJson(timeTestJson);

    // 测试streamInfos字段的各种情况
    nlohmann::json invalidStreamInfos1 = nlohmann::json::object();                            // 不是数组
    nlohmann::json invalidStreamInfos2 = nlohmann::json::array({ nlohmann::json::object() }); // 包含无效元素

    timeTestJson["closeCameraTime"] = validTime;
    timeTestJson["streamInfos"] = invalidStreamInfos1;
    JsonCacheConverter::CheckParamJson(timeTestJson);
    timeTestJson["streamInfos"] = invalidStreamInfos2;
    JsonCacheConverter::CheckParamJson(timeTestJson);

    // 测试settings字段的各种情况
    nlohmann::json invalidSettings1 = nlohmann::json::object();             // 不是数组
    nlohmann::json invalidSettings2 = nlohmann::json::array({ "invalid" }); // 包含非数字元素

    timeTestJson["streamInfos"] = nlohmann::json::array();
    timeTestJson["settings"] = invalidSettings1;
    JsonCacheConverter::CheckParamJson(timeTestJson);

    timeTestJson["settings"] = invalidSettings2;
    JsonCacheConverter::CheckParamJson(timeTestJson);
}

void OutputToJsonFileTest1(FuzzedDataProvider& fdp)
{
    // 生成随机文件路径
    std::string jsonFilePath = "/data/local/tmp/" + fdp.ConsumeRandomLengthString(32);

    // 生成随机的PmapJson内容
    nlohmann::json pMapJson;
    size_t pMapSize = fdp.ConsumeIntegral<uint32_t>() % 5 + 1;
    for (size_t i = 0; i < pMapSize; ++i) {
        std::string clientKey = fdp.ConsumeRandomLengthString(32);
        nlohmann::json innerJson;
        innerJson["cameraId"] = fdp.ConsumeRandomLengthString(32);
        innerJson["clientName"] = clientKey;
        pMapJson[clientKey] = innerJson;
    }

    // 生成随机的TmapJson内容
    nlohmann::json tMapJson;
    tMapJson["cameraId"] = fdp.ConsumeRandomLengthString(32);
    tMapJson["clientName"] = fdp.ConsumeRandomLengthString(32);

    // 生成随机的IndexJson内容
    nlohmann::json indexJson;
    indexJson["cameraId"] = fdp.ConsumeRandomLengthString(32);
    indexJson["clientName"] = fdp.ConsumeRandomLengthString(32);

    // 调用测试函数
    JsonCacheConverter::OutputToJsonFile(jsonFilePath, pMapJson, tMapJson, indexJson);

    // 测试边界情况
    // 空JSON输入
    JsonCacheConverter::OutputToJsonFile(jsonFilePath, nlohmann::json(), nlohmann::json(), nlohmann::json());

    // 无效文件路径
    JsonCacheConverter::OutputToJsonFile("/invalid/path/test.json", pMapJson, tMapJson, indexJson);

    // 大型JSON数据
    nlohmann::json largePMapJson;
    for (size_t i = 0; i < 100; ++i) {
        std::string key = "client_" + std::to_string(i);
        nlohmann::json innerJson;
        innerJson["cameraId"] = "camera_" + std::to_string(i);
        innerJson["clientName"] = key;
        largePMapJson[key] = innerJson;
    }
    JsonCacheConverter::OutputToJsonFile(jsonFilePath, largePMapJson, tMapJson, indexJson);
}

void CreateProducerForPrelaunchTest(FuzzedDataProvider& fdp)
{
    // 生成随机的StreamInfo_V1_0结构
    OHOS::HDI::Camera::V1_0::StreamInfo streamInfo;

    // 随机设置StreamInfo的各个字段
    streamInfo.streamId_ = fdp.ConsumeIntegral<int32_t>();
    streamInfo.width_ = fdp.ConsumeIntegral<int32_t>();
    streamInfo.height_ = fdp.ConsumeIntegral<int32_t>();
    streamInfo.format_ = fdp.ConsumeIntegral<int32_t>();
    streamInfo.dataspace_ = fdp.ConsumeIntegral<int32_t>();
    streamInfo.intent_ = static_cast<StreamIntent>(fdp.ConsumeIntegral<int32_t>() % 3);
    streamInfo.tunneledMode_ = fdp.ConsumeBool();
    streamInfo.minFrameDuration_ = fdp.ConsumeIntegral<int32_t>();
    streamInfo.encodeType_ = static_cast<EncodeType>(fdp.ConsumeIntegral<int32_t>() % 2);

    // 测试正常路径
    bool result = JsonCacheConverter::CreateProducerForPrelaunch(streamInfo);

    // 测试边界情况
    // 测试无效的streamInfo（width/height为0）
    OHOS::HDI::Camera::V1_0::StreamInfo invalidStreamInfo1;
    invalidStreamInfo1.width_ = 0;
    invalidStreamInfo1.height_ = fdp.ConsumeIntegral<int32_t>();
    invalidStreamInfo1.format_ = fdp.ConsumeIntegral<int32_t>();
    result = JsonCacheConverter::CreateProducerForPrelaunch(invalidStreamInfo1);

    OHOS::HDI::Camera::V1_0::StreamInfo invalidStreamInfo2;
    invalidStreamInfo2.width_ = fdp.ConsumeIntegral<int32_t>();
    invalidStreamInfo2.height_ = 0;
    invalidStreamInfo2.format_ = fdp.ConsumeIntegral<int32_t>();
    result = JsonCacheConverter::CreateProducerForPrelaunch(invalidStreamInfo2);

    // 测试无效的format
    OHOS::HDI::Camera::V1_0::StreamInfo invalidFormatStreamInfo;
    invalidFormatStreamInfo.width_ = fdp.ConsumeIntegral<int32_t>();
    invalidFormatStreamInfo.height_ = fdp.ConsumeIntegral<int32_t>();
    invalidFormatStreamInfo.format_ = -1; // 无效的format值
    result = JsonCacheConverter::CreateProducerForPrelaunch(invalidFormatStreamInfo);
}

void CreateProducerForPrelaunchTest2(FuzzedDataProvider& fdp)
{
    // 生成随机的ExtendedStreamInfo结构
    OHOS::HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo;

    // 随机设置ExtendedStreamInfo的各个字段
    extendedStreamInfo.format = fdp.ConsumeIntegral<int32_t>();
    extendedStreamInfo.width = fdp.ConsumeIntegral<int32_t>();
    extendedStreamInfo.height = fdp.ConsumeIntegral<int32_t>();
    extendedStreamInfo.type = static_cast<OHOS::HDI::Camera::V1_1::ExtendedStreamInfoType>(
        fdp.ConsumeIntegral<int32_t>() % 5); // 生成0-4的类型值
    extendedStreamInfo.dataspace = fdp.ConsumeIntegral<int32_t>();

    // 测试正常路径
    bool result = JsonCacheConverter::CreateProducerForPrelaunch(extendedStreamInfo);

    // 测试边界情况
    // 测试无效的format
    OHOS::HDI::Camera::V1_1::ExtendedStreamInfo invalidFormatInfo;
    invalidFormatInfo.format = -1; // 无效的format值
    invalidFormatInfo.width = fdp.ConsumeIntegral<int32_t>();
    invalidFormatInfo.height = fdp.ConsumeIntegral<int32_t>();
    result = JsonCacheConverter::CreateProducerForPrelaunch(invalidFormatInfo);

    // 测试width/height为0
    OHOS::HDI::Camera::V1_1::ExtendedStreamInfo zeroSizeInfo;
    zeroSizeInfo.format = fdp.ConsumeIntegral<int32_t>();
    zeroSizeInfo.width = 0;
    zeroSizeInfo.height = 0;
    result = JsonCacheConverter::CreateProducerForPrelaunch(zeroSizeInfo);
}

void Test(FuzzedDataProvider& fdp)
{
    auto func = fdp.PickValueInArray({
        ParseJsonToPMapTest1,
        ParseJsonToPMapTest2,
        ParseJsonToIndexTest,
        ParseJsonToParamTest,
        ParseJsonToStreamInfosTest,
        ParseJsonToStreamInfoV1_0Test,
        CheckStreamInfoV1_0JsonTest,
        ParseJsonToExtendedInfoTest,
        ParseJsonToSettingsTest,
        ParseJsonToCloseCameraTimeTest,
        SaveMapToJsonFileTest,
        SavePMapToJsonTest,
        SaveTMapToJsonTest,
        SaveParamToJsonTest,
        SaveStreamInfosToJsonTest,
        SaveIndexToJsonTest,
        CheckParamJsonTest,
        OutputToJsonFileTest1,
        CreateProducerForPrelaunchTest,
        CreateProducerForPrelaunchTest2
    });
    func(fdp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    Test(fdp);
    return 0;
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    Init();
    return 0;
}