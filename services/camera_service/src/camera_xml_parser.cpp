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

#include "camera_xml_parser.h"

#include <dlfcn.h>
#include <string>
#include <map>
#include <set>
#include <atomic>
#include <mutex>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "camera_log.h"
namespace OHOS {
namespace CameraStandard {

const char *LIBXML_SO_PATH = "libxml2.z.so";
static const int8_t SUCCESS = 0;
static const int8_t FAIL = -1;

struct XmlFuncHandle {
    void *libHandle = nullptr;
    xmlDoc *(*xmlReadFile)(const char *fileName, const char *encoding, int32_t options);
    xmlNode *(*xmlDocGetRootElement)(xmlDoc *doc);
    bool (*xmlHasProp)(const xmlNode *node, const xmlChar *propName);
    xmlChar *(*xmlGetProp)(const xmlNode *node, const xmlChar *propName);
    void (*xmlFreeDoc)(xmlDoc *doc);
    void (*xmlFree)(xmlChar *content);
    void (*xmlCleanupParser)();
    int32_t (*xmlStrcmp)(const xmlChar *propName1, const xmlChar *propName2);
    xmlChar *(*xmlNodeGetContent)(const xmlNode *cur);
};

class DlopenUtils {
public:
    static bool Init();
    static void DeInit();
    static std::shared_ptr<XmlFuncHandle> GetHandle();
private:
    static std::atomic<int32_t> refCount_;
    static std::shared_ptr<XmlFuncHandle> xmlFuncHandle_;
    static std::mutex dlMutex_;
};

std::atomic<int32_t> DlopenUtils::refCount_{0};
std::shared_ptr<XmlFuncHandle> DlopenUtils::xmlFuncHandle_ = nullptr;
std::mutex DlopenUtils::dlMutex_;

class CameraXmlNodeInner : public CameraXmlNode {
public:
    CameraXmlNodeInner();
    CameraXmlNodeInner(const CameraXmlNodeInner &obj);
    CameraXmlNodeInner &operator=(const CameraXmlNodeInner &obj);
    ~CameraXmlNodeInner() override;

    std::shared_ptr<CameraXmlNode> GetChildrenNode() override;
    std::shared_ptr<CameraXmlNode> GetCopyNode() override;
    int32_t Config(const char *fileName, const char *encoding, int32_t options) override;
    void MoveToNext() override;
    void MoveToChildren() override;

    bool IsNodeValid() override;
    bool CompareName(const char *propName) override;
    bool IsElementNode() override;
    bool HasProp(const char *propName) override;
    int32_t GetProp(const char *propName, std::string &result) override;
    int32_t GetContent(std::string &result) override;
    std::string GetName() override;

    void FreeDoc() override;
    void FreeProp(char *propName) override;
    void CleanUpParser() override;

private:
    int32_t StrcmpXml(const xmlChar *propName1, const xmlChar *propName2);
    xmlDoc *doc_ = nullptr;
    xmlNode *curNode_ = nullptr;
    std::shared_ptr<XmlFuncHandle> xmlFuncHandle_ = nullptr;
};

bool DlopenUtils::Init()
{
    std::lock_guard<std::mutex> lock(dlMutex_);
    if (refCount_.load() == 0) {
        void *libHandle = dlopen(LIBXML_SO_PATH, RTLD_NOW);
        CHECK_ERROR_RETURN_RET_LOG(libHandle == nullptr, false, "dlopen failed!");
        xmlFuncHandle_ = std::make_shared<XmlFuncHandle>();
        xmlFuncHandle_->libHandle = libHandle;
        xmlFuncHandle_->xmlReadFile =
            reinterpret_cast<decltype(xmlFuncHandle_->xmlReadFile)>(dlsym(libHandle, "xmlReadFile"));
        xmlFuncHandle_->xmlDocGetRootElement =
            reinterpret_cast<decltype(xmlFuncHandle_->xmlDocGetRootElement)>(dlsym(libHandle, "xmlDocGetRootElement"));
        xmlFuncHandle_->xmlHasProp =
            reinterpret_cast<decltype(xmlFuncHandle_->xmlHasProp)>(dlsym(libHandle, "xmlHasProp"));
        xmlFuncHandle_->xmlGetProp =
            reinterpret_cast<decltype(xmlFuncHandle_->xmlGetProp)>(dlsym(libHandle, "xmlGetProp"));
        xmlFuncHandle_->xmlFreeDoc =
            reinterpret_cast<decltype(xmlFuncHandle_->xmlFreeDoc)>(dlsym(libHandle, "xmlFreeDoc"));
        xmlFuncHandle_->xmlFree =
            reinterpret_cast<decltype(xmlFuncHandle_->xmlFree)>(dlsym(libHandle, "xmlFree"));
        xmlFuncHandle_->xmlCleanupParser =
            reinterpret_cast<decltype(xmlFuncHandle_->xmlCleanupParser)>(dlsym(libHandle, "xmlCleanupParser"));
        xmlFuncHandle_->xmlStrcmp =
            reinterpret_cast<decltype(xmlFuncHandle_->xmlStrcmp)>(dlsym(libHandle, "xmlStrcmp"));
        xmlFuncHandle_->xmlNodeGetContent =
            reinterpret_cast<decltype(xmlFuncHandle_->xmlNodeGetContent)>(dlsym(libHandle, "xmlNodeGetContent"));
        MEDIA_INFO_LOG("Libxml2 open success");
    }
    refCount_.store(refCount_.load() + 1);
    return true;
}

void DlopenUtils::DeInit()
{
    std::lock_guard<std::mutex> lock(dlMutex_);
    refCount_.store(refCount_.load() - 1);
    if (refCount_.load() == 0 && xmlFuncHandle_.use_count() == 1) {
        dlclose(xmlFuncHandle_->libHandle);
        xmlFuncHandle_ = nullptr;
        MEDIA_INFO_LOG("Libxml2 close success");
    }
}

std::shared_ptr<XmlFuncHandle> DlopenUtils::GetHandle()
{
    std::lock_guard<std::mutex> lock(dlMutex_);
    return xmlFuncHandle_;
}

std::shared_ptr<CameraXmlNode> CameraXmlNode::Create()
{
    return std::make_shared<CameraXmlNodeInner>();
}

std::shared_ptr<CameraXmlNode> CameraXmlNodeInner::GetChildrenNode()
{
    std::shared_ptr<CameraXmlNodeInner> copyNode = std::make_shared<CameraXmlNodeInner>(*this);
    copyNode->MoveToChildren();
    return copyNode;
}

std::shared_ptr<CameraXmlNode> CameraXmlNodeInner::GetCopyNode()
{
    return std::make_shared<CameraXmlNodeInner>(*this);
}

CameraXmlNodeInner::CameraXmlNodeInner()
{
    CHECK_ERROR_RETURN_LOG(!DlopenUtils::Init(), "open so fail!");
    xmlFuncHandle_ = DlopenUtils::GetHandle();
    CHECK_ERROR_RETURN_LOG(xmlFuncHandle_ == nullptr, "get xmlFuncHandle failed!");
}

CameraXmlNodeInner::CameraXmlNodeInner(const CameraXmlNodeInner &obj)
{
    // only the main node has doc and freedoc() when destruct
    doc_ = nullptr;
    curNode_ = obj.curNode_;
    CHECK_ERROR_RETURN_LOG(!DlopenUtils::Init(), "open so fail!");
    xmlFuncHandle_ = DlopenUtils::GetHandle();
}

CameraXmlNodeInner &CameraXmlNodeInner::operator=(const CameraXmlNodeInner &obj)
{
    // only the main node has doc and freedoc() when destruct
    doc_ = nullptr;
    curNode_ = obj.curNode_;
    if (!DlopenUtils::Init()) {
        MEDIA_INFO_LOG("init openUtils fail!");
    }
    xmlFuncHandle_ = DlopenUtils::GetHandle();
    return *this;
}

CameraXmlNodeInner::~CameraXmlNodeInner()
{
    if (xmlFuncHandle_ != nullptr && doc_ != nullptr) {
        xmlFuncHandle_->xmlFreeDoc(doc_);
        xmlFuncHandle_->xmlCleanupParser();
        doc_ = nullptr;
    }
    curNode_ = nullptr;
    xmlFuncHandle_ = nullptr;
    DlopenUtils::DeInit();
}

int32_t CameraXmlNodeInner::Config(const char *fileName, const char *encoding, int32_t options)
{
    CHECK_ERROR_RETURN_RET_LOG(xmlFuncHandle_ == nullptr, FAIL, "xmlFuncHandle is nullptr!");
    doc_ = xmlFuncHandle_->xmlReadFile(fileName, encoding, options);
    CHECK_ERROR_RETURN_RET_LOG(doc_ == nullptr, FAIL, "xmlReadFile failed! fileName :%{public}s", fileName);
    curNode_ = xmlFuncHandle_->xmlDocGetRootElement(doc_);
    CHECK_ERROR_RETURN_RET_LOG(curNode_ == nullptr, FAIL, "xmlDocGetRootElement failed!");
    return SUCCESS;
}

void CameraXmlNodeInner::MoveToNext()
{
    CHECK_ERROR_RETURN_LOG(curNode_ == nullptr, "curNode_ is nullptr! Cannot MoveToNext!");
    curNode_ = curNode_->next;
}

void CameraXmlNodeInner::MoveToChildren()
{
    CHECK_ERROR_RETURN_LOG(curNode_ == nullptr, "curNode_ is nullptr! Cannot MoveToChildren!");
    curNode_ = curNode_->children;
}

bool CameraXmlNodeInner::IsNodeValid()
{
    return curNode_ != nullptr;
}

// need check curNode_ isvalid before use
bool CameraXmlNodeInner::HasProp(const char *propName)
{
    CHECK_ERROR_RETURN_RET_LOG(xmlFuncHandle_ == nullptr, false, "xmlFuncHandle is nullptr!");
    return xmlFuncHandle_->xmlHasProp(curNode_, reinterpret_cast<const xmlChar*>(propName));
}

// need check curNode_ isvalid before use
int32_t CameraXmlNodeInner::GetProp(const char *propName, std::string &result)
{
    result = "";
    CHECK_ERROR_RETURN_RET_LOG(xmlFuncHandle_ == nullptr, FAIL, "xmlFuncHandle is nullptr!");
    auto xmlFunc = reinterpret_cast<xmlChar *(*)(const xmlNode *node, const xmlChar *propName)>
        (dlsym(xmlFuncHandle_->libHandle, "xmlGetProp"));
    xmlChar *tempValue = xmlFunc(curNode_, reinterpret_cast<const xmlChar*>(propName));
    CHECK_ERROR_RETURN_RET_LOG(tempValue == nullptr, FAIL, "GetProp Fail! curNode has no prop: %{public}s", propName);
    result = reinterpret_cast<char*>(tempValue);
    return SUCCESS;
}

int32_t CameraXmlNodeInner::GetContent(std::string &result)
{
    CHECK_ERROR_RETURN_RET_LOG(xmlFuncHandle_ == nullptr, FAIL, "xmlFuncHandle is nullptr!");
    xmlChar *tempContent = xmlFuncHandle_->xmlNodeGetContent(curNode_);
    CHECK_ERROR_RETURN_RET_LOG(tempContent == nullptr, FAIL, "GetContent Fail!");
    result = reinterpret_cast<char*>(tempContent);
    return SUCCESS;
}

std::string CameraXmlNodeInner::GetName()
{
    CHECK_ERROR_RETURN_RET_LOG(curNode_ == nullptr, "", "curNode_ is nullptr! Cannot GetName!");
    return reinterpret_cast<char*>(const_cast<xmlChar*>(curNode_->name));
}

void CameraXmlNodeInner::FreeDoc()
{
    CHECK_ERROR_RETURN_LOG(xmlFuncHandle_ == nullptr, "xmlFuncHandle is nullptr!");
    if (doc_ != nullptr) {
        xmlFuncHandle_->xmlFreeDoc(doc_);
        doc_ = nullptr;
    }
}

void CameraXmlNodeInner::FreeProp(char *propName)
{
    CHECK_ERROR_RETURN_LOG(xmlFuncHandle_ == nullptr, "xmlFuncHandle is nullptr!");
    xmlFuncHandle_->xmlFree(reinterpret_cast<xmlChar*>(propName));
}

void CameraXmlNodeInner::CleanUpParser()
{
    CHECK_ERROR_RETURN_LOG(xmlFuncHandle_ == nullptr, "xmlFuncHandle is nullptr!");
    xmlFuncHandle_->xmlCleanupParser();
}

int32_t CameraXmlNodeInner::StrcmpXml(const xmlChar *propName1, const xmlChar *propName2)
{
    CHECK_ERROR_RETURN_RET_LOG(xmlFuncHandle_ == nullptr, 1, "xmlFuncHandle is nullptr!");
    return xmlFuncHandle_->xmlStrcmp(propName1, propName2);
}

bool CameraXmlNodeInner::CompareName(const char *propName)
{
    CHECK_ERROR_RETURN_RET_LOG(curNode_ == nullptr, false, "curNode_ is nullptr! Cannot CompareName!");
    return curNode_->type == XML_ELEMENT_NODE &&
        (StrcmpXml(curNode_->name, reinterpret_cast<const xmlChar*>(propName)) == 0);
}

bool CameraXmlNodeInner::IsElementNode()
{
    CHECK_ERROR_RETURN_RET_LOG(curNode_ == nullptr, false, "curNode_ is nullptr! Cannot CompareElementNode!");
    return curNode_->type == XML_ELEMENT_NODE;
}

} // namespace CameraStandard
} // namespace OHOS
