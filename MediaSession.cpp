/*
 * Copyright 2016-2017 TATA ELXSI
 * Copyright 2016-2017 Metrological
 *
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

#include "MediaSession.h"
#include "Policy.h"

#include <assert.h>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <string.h>
#include <sys/utsname.h>

#include <core/core.h>

#define NYI_KEYSYSTEM "keysystem-placeholder"

using namespace std;

namespace CDMi {

WPEFramework::Core::CriticalSection g_lock;

MediaKeySession::MediaKeySession(widevine::Cdm *cdm, int32_t licenseType)
    : m_cdm(cdm)
    , m_CDMData("")
    , m_initData("")
    , m_initDataType(widevine::Cdm::kCenc)
    , m_licenseType((widevine::Cdm::SessionType)licenseType)
    , m_sessionId("") {
  m_cdm->createSession(m_licenseType, &m_sessionId);

  ::memset(m_IV, 0 , sizeof(m_IV));;
}

MediaKeySession::~MediaKeySession(void) {
}


void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {

  if (f_piMediaKeySessionCallback) {
    m_piCallback = const_cast<IMediaKeySessionCallback*>(f_piMediaKeySessionCallback);

    widevine::Cdm::Status status = m_cdm->generateRequest(m_sessionId, m_initDataType, m_initData);
    if (widevine::Cdm::kSuccess != status) {
       printf("generateRequest failed\n");
       m_piCallback->OnKeyMessage((const uint8_t *) "", 0, "");
    }
  }
  else {
      m_piCallback = nullptr;
  }
}

void MediaKeySession::onMessage(widevine::Cdm::MessageType f_messageType, const std::string& f_message) {
  std::string destUrl;
  std::string message;

  switch (f_messageType) {
  case widevine::Cdm::kLicenseRequest:
  case widevine::Cdm::kLicenseRenewal:
  case widevine::Cdm::kLicenseRelease:
  {
    destUrl.assign(kLicenseServer); 

    // FIXME: Errrr, this is weird.
    //if ((Cdm::MessageType)f_message[1] == (Cdm::kIndividualizationRequest + 1)) {
    //  LOGI("switching message type to kIndividualizationRequest");
    //  messageType = Cdm::kIndividualizationRequest;
    //}
    
    message = std::to_string(f_messageType) + ":Type:";
    break;
  }
  default:
    printf("unsupported message type %d\n", f_messageType);
    break;
  }
  message.append(f_message.c_str(),  f_message.size());
  m_piCallback->OnKeyMessage((const uint8_t*) message.c_str(), message.size(), (char*) destUrl.c_str());
}

static const char* widevineKeyStatusToCString(widevine::Cdm::KeyStatus widevineStatus)
{
    switch (widevineStatus) {
    case widevine::Cdm::kUsable:
        return "KeyUsable";
        break;
    case widevine::Cdm::kExpired:
        return "KeyExpired";
        break;
    case widevine::Cdm::kOutputRestricted:
        return "KeyOutputRestricted";
        break;
    case widevine::Cdm::kStatusPending:
        return "KeyStatusPending";
        break;
    case widevine::Cdm::kInternalError:
        return "KeyInternalError";
        break;
    case widevine::Cdm::kReleased:
        return "KeyReleased";
        break;
    default:
        return "UnknownError";
        break;
    }
}

void MediaKeySession::onKeyStatusChange()
{
    widevine::Cdm::KeyStatusMap map;
    if (widevine::Cdm::kSuccess != m_cdm->getKeyStatuses(m_sessionId, &map))
        return;

    for (const auto& pair : map) {
        const std::string& keyValue = pair.first;
        widevine::Cdm::KeyStatus keyStatus = pair.second;

        m_piCallback->OnKeyStatusUpdate(widevineKeyStatusToCString(keyStatus),
                                        reinterpret_cast<const uint8_t*>(keyValue.c_str()),
                                        keyValue.length());
    }
    m_piCallback->OnKeyStatusesUpdated();
}

void MediaKeySession::onKeyStatusError(widevine::Cdm::Status status) {
  std::string errorStatus;
  switch (status) {
  case widevine::Cdm::kNeedsDeviceCertificate:
    errorStatus = "NeedsDeviceCertificate";
    break;
  case widevine::Cdm::kSessionNotFound:
    errorStatus = "SessionNotFound";
    break;
  case widevine::Cdm::kDecryptError:
    errorStatus = "DecryptError";
    break;
  case widevine::Cdm::kTypeError:
    errorStatus = "TypeError";
    break;
  case widevine::Cdm::kQuotaExceeded:
    errorStatus = "QuotaExceeded";
    break;
  case widevine::Cdm::kNotSupported:
    errorStatus = "NotSupported";
    break;
  default:
    errorStatus = "UnExpectedError";
    break;
  }
  m_piCallback->OnError(0, CDMi_S_FALSE, errorStatus.c_str());
}

void MediaKeySession::onRemoveComplete() {
    widevine::Cdm::KeyStatusMap map;
    if (widevine::Cdm::kSuccess == m_cdm->getKeyStatuses(m_sessionId, &map)) {
        for (const auto& pair : map) {
            const std::string& keyValue = pair.first;

            m_piCallback->OnKeyStatusUpdate("KeyReleased",
                                        reinterpret_cast<const uint8_t*>(keyValue.c_str()),
                                        keyValue.length());
        }
        m_piCallback->OnKeyStatusesUpdated();
    }
}

void MediaKeySession::onDeferredComplete(widevine::Cdm::Status) {
}

void MediaKeySession::onDirectIndividualizationRequest(const string&) {
}

CDMi_RESULT MediaKeySession::Load(void) {
  CDMi_RESULT ret = CDMi_S_FALSE;
  g_lock.Lock();
  widevine::Cdm::Status status = m_cdm->load(m_sessionId);
  if (widevine::Cdm::kSuccess != status)
    onKeyStatusError(status);
  else
    ret = CDMi_SUCCESS;
  g_lock.Unlock();
  return ret;
}

void MediaKeySession::Update(
    const uint8_t *f_pbKeyMessageResponse,
    uint32_t f_cbKeyMessageResponse) {
  std::string keyResponse(reinterpret_cast<const char*>(f_pbKeyMessageResponse),
      f_cbKeyMessageResponse);
  g_lock.Lock();
  if (widevine::Cdm::kSuccess != m_cdm->update(m_sessionId, keyResponse))
     onKeyStatusChange();
  g_lock.Unlock();
}

CDMi_RESULT MediaKeySession::Remove(void) {
  CDMi_RESULT ret = CDMi_S_FALSE;
  g_lock.Lock();
  widevine::Cdm::Status status = m_cdm->remove(m_sessionId);
  if (widevine::Cdm::kSuccess != status)
    onKeyStatusError(status);
  else
    ret =  CDMi_SUCCESS;
  g_lock.Unlock();
  return ret;
}

CDMi_RESULT MediaKeySession::Close(void) {
  CDMi_RESULT status = CDMi_S_FALSE;
  g_lock.Lock();
  if (widevine::Cdm::kSuccess == m_cdm->close(m_sessionId))
    status = CDMi_SUCCESS;
  g_lock.Unlock();
  return status;
}

const char* MediaKeySession::GetSessionId(void) const {
  return m_sessionId.c_str();
}

const char* MediaKeySession::GetKeySystem(void) const {
  return NYI_KEYSYSTEM;//TODO: replace with keysystem and test
}

CDMi_RESULT MediaKeySession::Init(
    int32_t licenseType,
    const char *f_pwszInitDataType,
    const uint8_t *f_pbInitData,
    uint32_t f_cbInitData,
    const uint8_t *f_pbCDMData,
    uint32_t f_cbCDMData) {
  switch ((LicenseType)licenseType) {
  case PersistentUsageRecord:
    m_licenseType = widevine::Cdm::kPersistentUsageRecord;
    break;
  case PersistentLicense:
    m_licenseType = widevine::Cdm::kPersistentLicense;
    break;
  default:
    m_licenseType = widevine::Cdm::kTemporary;
    break;
  }

  if (f_pwszInitDataType) {
    if (!strcmp(f_pwszInitDataType, "cenc"))
       m_initDataType = widevine::Cdm::kCenc;
    else if (!strcmp(f_pwszInitDataType, "webm"))
       m_initDataType = widevine::Cdm::kWebM;
  }

  if (f_pbInitData && f_cbInitData)
    m_initData.assign((const char*) f_pbInitData, f_cbInitData);

  if (f_pbCDMData && f_cbCDMData)
    m_CDMData.assign((const char*) f_pbCDMData, f_cbCDMData);
  return CDMi_SUCCESS;
}

#define ENABLE_SDP 1
#ifdef ENABLE_SDP
typedef struct native_handle
{
    int version;        /* sizeof(native_handle_t) */
    int numFds;         /* number of file-descriptors at &data[0] */
    int numInts;        /* number of ints at &data[numFds] */
    int data[4];        /* numFds + numInts ints */
} native_handle_t;
#endif

CDMi_RESULT MediaKeySession::Decrypt(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t *f_pdwSubSampleMapping,
    uint32_t f_cdwSubSampleMapping,
    const uint8_t *f_pbIV,
    uint32_t f_cbIV,
    const uint8_t *f_pbData,
    uint32_t f_cbData,
    uint32_t *f_pcbOpaqueClearContent,
    uint8_t **f_ppbOpaqueClearContent,
    const uint8_t keyIdLength,
    const uint8_t* keyId,
    bool initWithLast15,
    int secureFd,
    uint32_t secureSize)
{
  g_lock.Lock();
  widevine::Cdm::KeyStatusMap map;
  std::string keyStatus;

  CDMi_RESULT status = CDMi_S_FALSE;
  *f_pcbOpaqueClearContent = 0;

  memcpy(m_IV, f_pbIV, (f_cbIV > 16 ? 16 : f_cbIV));
  if (f_cbIV < 16) {
    memset(&(m_IV[f_cbIV]), 0, 16 - f_cbIV);
  }

  if (widevine::Cdm::kSuccess == m_cdm->getKeyStatuses(m_sessionId, &map)) {
    widevine::Cdm::KeyStatusMap::iterator it;
    if(keyIdLength > 0) {
      // if keyid is provided, find it in the map
      std::string keyIdString((const char*) keyId, (size_t) keyIdLength);
      it = map.find(keyIdString);
      if (it == map.end()) {
        printf("ERROR: key ID is not found!\n");
        return status;
      }
    } else {
      // if no keyid is provided, use the first one in the map
      it = map.begin();
    }

    // FIXME: We just check the first key? How do we know that's the Widevine key and not, say, a PlayReady one?
    if (widevine::Cdm::kUsable == it->second) {
      widevine::Cdm::OutputBuffer output;
      uint8_t *outputBuffer = NULL;

      uint32_t defaultSubSampleMapping[2];
      const uint32_t *subSampleMapping = NULL;
      uint32_t subSampleCount = 0;
      uint32_t offset = 0;

#ifdef ENABLE_SDP
      native_handle_t handle = {sizeof(native_handle_t), 2, 2, {0,0,0,0}};
#endif

      if(f_cdwSubSampleMapping == 0) {
        /* When there is no subsample information, data is completely encrypted. */
        defaultSubSampleMapping[0] = 0;         /* Clear data */
        defaultSubSampleMapping[1] = f_cbData;  /* Encrypted data */
        subSampleMapping = defaultSubSampleMapping;
        subSampleCount = 2;
      } else {
        subSampleMapping = f_pdwSubSampleMapping;
        subSampleCount = f_cdwSubSampleMapping;
      }

#ifdef ENABLE_SDP
      output.is_secure = (secureFd >= 0);
#else
      output.is_secure = false;
#endif

      if(output.is_secure == false) {
        outputBuffer = (uint8_t*) malloc(f_cbData * sizeof(uint8_t));
      }

      for(uint32_t subSampleIndex = 0; subSampleIndex < subSampleCount; subSampleIndex++) {

        if(subSampleMapping[subSampleIndex] == 0) {
          continue;
        }

  #ifdef ENABLE_SDP
        if(output.is_secure) {
          handle.data[0] = secureFd;
          handle.data[1] = -1; /* Shared memory. Not used for decryption. */
          handle.data[2] = secureSize;
          handle.data[3] = 0;  /* Shared memory size */
          output.data = (uint8_t *)&handle;
          output.data_length = secureSize;
          output.data_offset = offset;
        } else {
          output.data = outputBuffer + offset;
          output.data_length = subSampleMapping[subSampleIndex];
          output.data_offset = 0;
        }
  #else
        output.data = outputBuffer + offset;
        output.data_length = subSampleMapping[subSampleIndex];
        output.data_offset = 0;
  #endif
        widevine::Cdm::InputBuffer input;
        input.data = f_pbData + offset;
        input.data_length = subSampleMapping[subSampleIndex];
        input.key_id = reinterpret_cast<const uint8_t*>((it->first).c_str());
        input.key_id_length = (it->first).size();
        input.iv = m_IV;
        input.iv_length = sizeof(m_IV);
        /* Even subsamples are clear, odd subsamples are encrypted */
        input.encryption_scheme = (subSampleIndex % 2) ? widevine::Cdm::kAesCtr : widevine::Cdm::kClear;

        if (widevine::Cdm::kSuccess != m_cdm->decrypt(input, output)) {
          free(outputBuffer);
          return CDMi_S_FALSE;
        }

        offset += subSampleMapping[subSampleIndex];
      }

      if(output.is_secure == false)
      {
        /* Return clear content */
        *f_pcbOpaqueClearContent = f_cbData;
        *f_ppbOpaqueClearContent = outputBuffer;
      }
      status = CDMi_SUCCESS;
    }
  }

  g_lock.Unlock();
  return status;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ){
  CDMi_RESULT ret = CDMi_S_FALSE;
  if (f_pbClearContentOpaque) {
    free(f_pbClearContentOpaque);
    ret = CDMi_SUCCESS;
  }
  return ret;
}

}  // namespace CDMi
