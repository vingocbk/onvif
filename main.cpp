#include "soapDeviceBindingProxy.h"
#include "soapMediaBindingProxy.h"
#include "soapPTZBindingProxy.h"
#include "soapPullPointSubscriptionBindingProxy.h"
#include "soapRemoteDiscoveryBindingProxy.h" 
#include "plugin/wsddapi.h"
#include "plugin/wsseapi.h"
#include "plugin/httpget.h"
// #include "custom/struct_timeval.h"
#include "httplib.h"
#include "wsdd.nsmap"
#include "define.h"
#define USERNAME "admin"
#define PASSWORD "elcom_123"

#define AUTHEN
// #define HOSTNAME "http://192.168.51.150/onvif/device_service"
#define HOSTNAME "http://192.168.51.14:8080/onvif/device_service"
// using http instead of https is not safe unless you secure message integrity with WS-Security by uncommenting:
// #define PROTECT

#ifdef PROTECT
// define some global data that is set once, to keep this example simple
EVP_PKEY *privk = NULL;
X509 *cert = NULL;
#endif



int CRYPTO_thread_setup();
void CRYPTO_thread_cleanup();

// to report an error
void report_error(struct soap *soap)
{
  std::cerr << "Oops, something went wrong:" << std::endl;
  soap_stream_fault(soap, std::cerr);
  exit(EXIT_FAILURE);
}

// to set the timestamp and authentication credentials in a request message
void set_credentials(struct soap *soap)
{
#ifdef AUTHEN
  soap_wsse_delete_Security(soap);
  if (soap_wsse_add_Timestamp(soap, "Time", 10)
  //  || soap_wsse_add_UsernameTokenDigest(soap, NULL, USERNAME, PASSWORD))
   || soap_wsse_add_UsernameTokenText(soap, "Auth", USERNAME, PASSWORD))
    report_error(soap);

#endif
#ifdef PROTECT
  if (!privk)
  {
    FILE *fd = fopen("client.pem";
    if (fd)
    {
      privk = PEM_read_PrivateKey(fd, NULL, NULL, (void*)"password");
      fclose(fd);
    }
    if (!privk)
    {
      fprintf(stderr, "Could not read private key from client.pem\n");
      exit(EXIT_FAILURE);
    }
  }
  if (!cert)
  {
    FILE *fd = fopen("clientcert.pem", "r");
    if (fd)
    {
      cert = PEM_read_X509(fd, NULL, NULL, NULL);
      fclose(fd);
    }
    if (!cert)
    {
      fprintf(stderr, "Could not read certificate from clientcert.pem\n");
      exit(EXIT_FAILURE);
    }
  }
  if (soap_wsse_add_BinarySecurityTokenX509(soap, "X509Token", cert)
   || soap_wsse_add_KeyInfo_SecurityTokenReferenceX509(soap, "#X509Token")
   || soap_wsse_sign_body(soap, SOAP_SMD_SIGN_RSA_SHA256, rsa_privk, 0)
   || soap_wsse_verify_auto(soap, SOAP_SMD_NONE, NULL, 0))
    report_error(soap);
#endif
}

// to check if an ONVIF service response was signed with WS-Security (when enabled)
void check_response(struct soap *soap)
{
#ifdef PROTECT
  // check if the server returned a signed message body, if not error
  if (soap_wsse_verify_body(soap))
    report_error(soap);
  soap_wsse_delete_Security(soap);
#endif
}

// to download a snapshot and save it locally in the current dir as image-1.jpg, image-2.jpg, image-3.jpg ...
void save_snapshot(int i, const char *endpoint)
{
  std::cout << "save_snapshot endpoint: " << endpoint << std::endl;
  char filename[32];
  (SOAP_SNPRINTF_SAFE(filename, 32), "image-%d.jpg", i);
  FILE *fd = fopen(filename, "w");
  if (!fd)
  {
    std::cerr << "Cannot open " << filename << " for writing" << std::endl;
    exit(EXIT_FAILURE);
  }

  // create a temporary context to retrieve the image with HTTP GET
  struct soap *soap = soap_new();
  // struct soap *soap = soap_new1(SOAP_IO_STORE); // use SOAP_IO_CHUNK or SOAP_IO_STORE
  // struct soap *soap = soap_new1(SOAP_XML_STRICT | SOAP_XML_CANONICAL | SOAP_IO_STORE);
  soap->connect_timeout = soap->recv_timeout = soap->send_timeout = 10; // 10 sec

  
  // enable https connections with server certificate verification using cacerts.pem
  // if (soap_ssl_client_context(soap, SOAP_SSL_SKIP_HOST_CHECK, NULL, NULL, "cacerts.pem", NULL, NULL))
  //   report_error(soap);

  soap->userid = USERNAME; 
  soap->passwd = PASSWORD; 

  soap_wsse_delete_Security(soap);
  if (soap_wsse_add_Timestamp(soap, "Time", 10)
   || soap_wsse_add_UsernameTokenDigest(soap, "Auth", USERNAME, PASSWORD))
  //  || soap_wsse_add_UsernameTokenText(soap, "Auth", USERNAME, PASSWORD))
    report_error(soap);
  // set_credentials(soap);
  // HTTP GET and save image
  // if (soap_call_ns__method(&soap, ...))
  if (soap_GET(soap, endpoint, NULL))
    report_error(soap);
  if (soap_begin_recv(soap))
    report_error(soap);

  std::cout << "Retrieving " << filename;
  if (soap->http_content)
    std::cout << " of type " << soap->http_content;
  std::cout << " from " << endpoint << std::endl;

  // this example stores the whole image in memory first, before saving it to the file
  // better is to copy the source code of soap_http_get_body here and
  // modify it to save data directly to the file.
  size_t imagelen;
  char *image = soap_http_get_body(soap, &imagelen); // NOTE: soap_http_get_body was renamed from soap_get_http_body in gSOAP 2.8.73
  soap_end_recv(soap);


  // size_t imagelen;
  // char *image = NULL;
  // if (soap_connect_command(soap, SOAP_GET, endpoint, NULL)
  // || soap_begin_recv(soap)
  // || (image = soap_http_get_body(soap, &imagelen)) != NULL
  // || soap_end_recv(soap))
  //   // soap_print_fault(soap, stderr);
  //   report_error(soap);

  // std::cout << <<
  fwrite(image, 1, imagelen, fd);
  fclose(fd);

  //cleanup
  soap_destroy(soap);
  soap_end(soap);
  soap_free(soap);
}

int main()
{
  // make OpenSSL MT-safe with mutex
  CRYPTO_thread_setup();

  // create a context with strict XML validation and exclusive XML canonicalization for WS-Security enabled
  struct soap *soap = soap_new1(SOAP_XML_STRICT | SOAP_XML_CANONICAL);
  soap->connect_timeout = soap->recv_timeout = soap->send_timeout = 10; // 10 sec
  soap_register_plugin(soap, soap_wsse);

  // enable https connections with server certificate verification using cacerts.pem
  if (soap_ssl_client_context(soap, SOAP_SSL_SKIP_HOST_CHECK, NULL, NULL, "cacerts.pem", NULL, NULL))
    report_error(soap);

  // create the proxies to access the ONVIF service API at HOSTNAME
  DeviceBindingProxy proxyDevice(soap);
  MediaBindingProxy proxyMedia(soap);

  // get device info and print
  // std::cout << "----------------GetDeviceInformation--------------" << std::endl;
  proxyDevice.soap_endpoint = HOSTNAME;
  _tds__GetDeviceInformation GetDeviceInformation;
  _tds__GetDeviceInformationResponse GetDeviceInformationResponse;
  set_credentials(soap);
  if (proxyDevice.GetDeviceInformation(&GetDeviceInformation, GetDeviceInformationResponse))
    report_error(soap);
  check_response(soap);

  // get device capabilities and print media
  // std::cout << "----------------GetCapabilities--------------" << std::endl;
  _tds__GetCapabilities GetCapabilities;
  _tds__GetCapabilitiesResponse GetCapabilitiesResponse;
  // std::cout << "----------------GetDiscoveryMode--------------" << std::endl;
  _tds__GetDiscoveryMode GetDiscoveryMode;
  _tds__GetDiscoveryModeResponse GetDiscoveryModeResponse;
  // std::cout << "----------------GetUsers--------------" << std::endl;
  _tds__GetUsers GetUsers;
  _tds__GetUsersResponse GetUsersResponse;
  // std::cout << "----------------GetProfiles Media--------------" << std::endl;
  _trt__GetProfiles GetProfiles;
  _trt__GetProfilesResponse GetProfilesResponse;
  //for Createuser
  _tds__CreateUsers CreateUsers;
  // CreateUsers.User = soap_new__tds__UserCredential_Extension(soap, -1);
  _tds__CreateUsersResponse CreateUsersResponse;
  
  std::string namestring;
  std::string username_create;
  std::string password_create;
  while (true)
  {
    int mode_view;
    do
    {
      std::cout << "Input 1-View, 2-Setup : ";
      std::cin >> mode_view;
    }
    while(!(mode_view == MODE_VIEW || mode_view == MODE_SETUP));
    std::cout << "------------------" << std::endl;
    switch (mode_view)
      {
      case MODE_VIEW:
        int view_detail;
        do
        {
          std::cout << "Input 1-View Devicemgmt, 2-View Media , 0-To Exit: ";
          std::cin >> view_detail;
        } while (!(view_detail == VIEW_DEVICEMGMT || view_detail == VIEW_MEDIA || view_detail == EXIT_MODE));
        std::cout << "------------------" << std::endl;
        switch (view_detail)
        {
        case VIEW_DEVICEMGMT:
          int view_devicemgmt;
          do
          {
            std::cout << "Input 1- Get Device Information" << std::endl;
            std::cout << "Input 2- Get Discovery Mode" << std::endl;
            std::cout << "Input 3- Get Capabilities" << std::endl;
            std::cout << "Input 4- Get Users" << std::endl;
            std::cout << "Input 0- Exit" << std::endl;
            std::cin >> view_devicemgmt;
          } while (!(view_devicemgmt == DEVICE_INFORMATION 
                  || view_devicemgmt == DEVICE_DISCOVRY_MODE 
                  || view_devicemgmt == DEVICE_CAPABILITIES 
                  || view_devicemgmt == DEVICE_USER 
                  || view_devicemgmt == EXIT_MODE));
          std::cout << "------------------" << std::endl;
          switch (view_devicemgmt)
          {
          case DEVICE_INFORMATION:
            // get device info and print
            std::cout << "----------------GetDeviceInformation--------------" << std::endl;
            proxyDevice.soap_endpoint = HOSTNAME;
            // _tds__GetDeviceInformation GetDeviceInformation;
            // _tds__GetDeviceInformationResponse GetDeviceInformationResponse;
            set_credentials(soap);
            if (proxyDevice.GetDeviceInformation(&GetDeviceInformation, GetDeviceInformationResponse))
              report_error(soap);
            check_response(soap);
            std::cout << "Manufacturer:    " << GetDeviceInformationResponse.Manufacturer << std::endl;
            std::cout << "Model:           " << GetDeviceInformationResponse.Model << std::endl;
            std::cout << "FirmwareVersion: " << GetDeviceInformationResponse.FirmwareVersion << std::endl;
            std::cout << "SerialNumber:    " << GetDeviceInformationResponse.SerialNumber << std::endl;
            std::cout << "HardwareId:      " << GetDeviceInformationResponse.HardwareId << std::endl;
            break;
          case DEVICE_DISCOVRY_MODE:
            std::cout << "----------------GetDiscoveryMode--------------" << std::endl;
            proxyDevice.soap_endpoint = HOSTNAME;
            // _tds__GetDiscoveryMode GetDiscoveryMode;
            // _tds__GetDiscoveryModeResponse GetDiscoveryModeResponse;
            set_credentials(soap);
            //if (proxyDevice.GetDeviceInformation(&GetDeviceInformation, GetDeviceInformationResponse))
            if(proxyDevice.GetDiscoveryMode(&GetDiscoveryMode, GetDiscoveryModeResponse))
              report_error(soap);
            check_response(soap);

            switch (GetDiscoveryModeResponse.DiscoveryMode)
            {
            case tt__DiscoveryMode__Discoverable:
              /* code */
              std::cout << "DiscoveryMode: Discoverable" << std::endl;
              break;
            case tt__DiscoveryMode__NonDiscoverable:
              /* code */
              std::cout << "DiscoveryMode: NonDiscoverable" << std::endl;
              break;
            default:
              break;
            }
            break;
          case DEVICE_CAPABILITIES:
            std::cout << "----------------GetCapabilities--------------" << std::endl;
            proxyDevice.soap_endpoint = HOSTNAME;
            // _tds__GetCapabilities GetCapabilities;
            // _tds__GetCapabilitiesResponse GetCapabilitiesResponse;
            set_credentials(soap);
            if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
              report_error(soap);
            check_response(soap);
            if(GetCapabilitiesResponse.Capabilities->Device)
            {
              std::cout << "Device XAddr:  " << GetCapabilitiesResponse.Capabilities->Device->XAddr << std::endl;
            }
            if(GetCapabilitiesResponse.Capabilities->Analytics)
            {
              std::cout << "Analytics XAddr:  " << GetCapabilitiesResponse.Capabilities->Analytics->XAddr << std::endl;
            }
            if(GetCapabilitiesResponse.Capabilities->Media)
            {
              std::cout << "Media XAddr:  " << GetCapabilitiesResponse.Capabilities->Media->XAddr << std::endl;
            }
            if(GetCapabilitiesResponse.Capabilities->Events)
            {
              std::cout << "Events XAddr:  " << GetCapabilitiesResponse.Capabilities->Events->XAddr << std::endl;
            }
            if(GetCapabilitiesResponse.Capabilities->Imaging)
            {
              std::cout << "Imaging XAddr:  " << GetCapabilitiesResponse.Capabilities->Imaging->XAddr << std::endl;
            }
            if(GetCapabilitiesResponse.Capabilities->PTZ)
            {
              std::cout << "PTZ XAddr:  " << GetCapabilitiesResponse.Capabilities->PTZ->XAddr << std::endl;
            }

            if (GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities)
            {
              if (GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTPMulticast)
                std::cout << "RTPMulticast: " << (*GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTPMulticast ? "yes" : "no") << std::endl;
              if (GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTP_USCORETCP)
                std::cout << "RTP_TCP:      " << (*GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTP_USCORETCP ? "yes" : "no") << std::endl;
              if (GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTP_USCORERTSP_USCORETCP)
                std::cout << "RTP_RTSP_TCP: " << (*GetCapabilitiesResponse.Capabilities->Media->StreamingCapabilities->RTP_USCORERTSP_USCORETCP ? "yes" : "no") << std::endl;
            }
            break;
          case DEVICE_USER:
            std::cout << "----------------GetUsers--------------" << std::endl;
            proxyDevice.soap_endpoint = HOSTNAME;
            // _tds__GetUsers GetUsers;
            // _tds__GetUsersResponse GetUsersResponse;
            set_credentials(soap);
            if(proxyDevice.GetUsers(&GetUsers, GetUsersResponse))
              report_error(soap);
            check_response(soap);
            for (long unsigned int i = 0; i < GetUsersResponse.User.size(); ++i)
            {
              std::cout << "Username " << i << ": " << GetUsersResponse.User[i]->Username << std::endl;
              switch (GetUsersResponse.User[i]->UserLevel)
              {
              case tt__UserLevel__Administrator:
                /* code */
                std::cout << "UserLevel : Administrator" << std::endl;
                break;
              case tt__UserLevel__Operator:
                /* code */
                std::cout << "UserLevel : Operator" << std::endl;
                break;
              case tt__UserLevel__User:
                /* code */
                std::cout << "UserLevel : User" << std::endl;
                break;
              case tt__UserLevel__Anonymous:
                /* code */
                std::cout << "UserLevel : Anonymous" << std::endl;
                break;
              case tt__UserLevel__Extended:
                /* code */
                std::cout << "UserLevel : Extended" << std::endl;
                break;
              default:
                break;
              }
            }
            break;
          case EXIT_MODE:
            goto go_to_exit;
            break;
          default:
            break;
          }
          break;
        case VIEW_MEDIA:
          int view_media;
          do
          {
            std::cout << "Input 1- Get Snapshot URI" << std::endl;
            std::cout << "Input 2- Get Stream URI" << std::endl;
            std::cout << "Input 3- Get Media Profiles" << std::endl;
            std::cout << "Input 0- Exit" << std::endl;
            std::cin >> view_media;
          } while (!(view_media == MEDIA_SNAPSHOT_URI 
                  || view_media == MEDIA_STREAM_URI 
                  || view_media == MEDIA_PROFILES 
                  || view_media == EXIT_MODE));
          std::cout << "------------------" << std::endl;
          switch (view_media)
          {
            case MEDIA_SNAPSHOT_URI:
              //get media endpoint
              proxyDevice.soap_endpoint = HOSTNAME;
              set_credentials(soap);
              if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
                report_error(soap);
              check_response(soap);
              //get snapshot uri
              proxyMedia.soap_endpoint = GetCapabilitiesResponse.Capabilities->Media->XAddr.c_str();
              // _trt__GetProfiles GetProfiles;
              // _trt__GetProfilesResponse GetProfilesResponse;
              set_credentials(soap);
              if (proxyMedia.GetProfiles(&GetProfiles, GetProfilesResponse))
                report_error(soap);
              check_response(soap);
              // for each profile get snapshot
              for (long unsigned int i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
              {
                // get snapshot URI for profile
                _trt__GetSnapshotUri GetSnapshotUri;
                _trt__GetSnapshotUriResponse GetSnapshotUriResponse;
                GetSnapshotUri.ProfileToken = GetProfilesResponse.Profiles[i]->token;
                set_credentials(soap);
                if (proxyMedia.GetSnapshotUri(&GetSnapshotUri, GetSnapshotUriResponse))
                  report_error(soap);
                check_response(soap);
                std::cout << "Profile name        : " << GetProfilesResponse.Profiles[i]->Name << std::endl;
                // std::cout << "Profile token       : " << GetProfilesResponse.Profiles[i]->token << std::endl;
                if (GetSnapshotUriResponse.MediaUri)
                {
                  std::cout << "Snapshot Uri      : " << GetSnapshotUriResponse.MediaUri->Uri.c_str() << std::endl;
                }
              }
              break;
            case MEDIA_STREAM_URI:
              //get media endpoint
              proxyDevice.soap_endpoint = HOSTNAME;
              set_credentials(soap);
              if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
                report_error(soap);
              check_response(soap);
              //get stream uri
              proxyMedia.soap_endpoint = GetCapabilitiesResponse.Capabilities->Media->XAddr.c_str();
              // _trt__GetProfiles GetProfiles;
              // _trt__GetProfilesResponse GetProfilesResponse;
              set_credentials(soap);
              if (proxyMedia.GetProfiles(&GetProfiles, GetProfilesResponse))
                report_error(soap);
              check_response(soap);
              // for each profile get snapshot
              for (long unsigned int i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
              {
                // get stream RTSP URI for profile
                _trt__GetStreamUri *trt__GetStreamUri = soap_new__trt__GetStreamUri(soap, -1);
                trt__GetStreamUri->StreamSetup = soap_new_tt__StreamSetup(soap, -1);
                trt__GetStreamUri->StreamSetup->Stream = tt__StreamType__RTP_Unicast;
                trt__GetStreamUri->StreamSetup->Transport = soap_new_tt__Transport(soap, -1);
                trt__GetStreamUri->StreamSetup->Transport->Protocol = tt__TransportProtocol__RTSP;


                _trt__GetStreamUriResponse *trt__GetStreamUriResponse = soap_new__trt__GetStreamUriResponse(soap, -1);
                trt__GetStreamUri->ProfileToken = GetProfilesResponse.Profiles[i]->token;
                set_credentials(soap);
                if (proxyMedia.GetStreamUri(trt__GetStreamUri, *trt__GetStreamUriResponse))
                  report_error(soap);
                check_response(soap);
                std::cout << "Profile name        : " << GetProfilesResponse.Profiles[i]->Name << std::endl;
                // std::cout << "Profile token       : " << GetProfilesResponse.Profiles[i]->token << std::endl;
                if(trt__GetStreamUriResponse->MediaUri)
                {
                  std::cout << "Stream RTSP Uri   : " << trt__GetStreamUriResponse->MediaUri->Uri.c_str() << std::endl;
                }
                // get stream HTTP URI for profile
                trt__GetStreamUri->StreamSetup->Transport->Protocol = tt__TransportProtocol__HTTP;
                set_credentials(soap);
                if (proxyMedia.GetStreamUri(trt__GetStreamUri, *trt__GetStreamUriResponse))
                  report_error(soap);
                check_response(soap);
                if(trt__GetStreamUriResponse->MediaUri)
                {
                  std::cout << "Stream HTTP Uri   : " << trt__GetStreamUriResponse->MediaUri->Uri.c_str() << std::endl;
                }
              }
              break;
            case MEDIA_PROFILES:
              //get media endpoint
              proxyDevice.soap_endpoint = HOSTNAME;
              set_credentials(soap);
              if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
                report_error(soap);
              check_response(soap);
              //get stream uri
              proxyMedia.soap_endpoint = GetCapabilitiesResponse.Capabilities->Media->XAddr.c_str();
              // _trt__GetProfiles GetProfiles;
              // _trt__GetProfilesResponse GetProfilesResponse;
              set_credentials(soap);
              if (proxyMedia.GetProfiles(&GetProfiles, GetProfilesResponse))
                report_error(soap);
              check_response(soap);
              // for each profile get snapshot
              for (long unsigned int i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
              {
                if(GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration)
                {
                  std::cout << "-VideoEncoderConfiguration-" << std::endl;
                  std::cout << "token               : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->token << std::endl;
                  std::cout << "Name                : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Name << std::endl;
                  std::cout << "UseCount            : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->UseCount << std::endl;
                  std::cout << "GuaranteedFrameRate : " << (GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->GuaranteedFrameRate ? "true":"false") << std::endl;
                  switch (GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Encoding)
                  {
                  case tt__VideoEncoding__JPEG:
                    std::cout << "Encoding            : JPEG" << std::endl;
                    break;
                  case tt__VideoEncoding__MPEG4:
                    std::cout << "Encoding            : MPEG4" << std::endl;
                    break;
                  case tt__VideoEncoding__H264:
                    std::cout << "Encoding            : H264" << std::endl;
                    break;
                  default:
                    break;
                  }
                  std::cout << "Resolution Width  : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Resolution->Width << std::endl;
                  std::cout << "Resolution Height : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Resolution->Height << std::endl;
                  std::cout << "Quality           : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Quality << std::endl;
                  std::cout << "FrameRateLimit    : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->RateControl->FrameRateLimit << std::endl;
                  std::cout << "EncodingInterval  : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->RateControl->EncodingInterval << std::endl;
                  std::cout << "BitrateLimit      : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->RateControl->BitrateLimit << std::endl;
                  if(GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->MPEG4)
                  {
                    std::cout << "MPEG4 GovLength    : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->MPEG4->GovLength << std::endl;
                    switch (GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->MPEG4->Mpeg4Profile)
                    {
                    case tt__Mpeg4Profile__SP:
                      std::cout << "MPEG4 Mpeg4Profile    : SP" << std::endl;
                      break;
                    case tt__Mpeg4Profile__ASP:
                      std::cout << "MPEG4 Mpeg4Profile    : ASP" << std::endl;
                      break;
                    default:
                      break;
                    }
                  }
                  if(GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->H264)
                  {
                    std::cout << "H264 GovLength      : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->H264->GovLength << std::endl;
                    switch (GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->H264->H264Profile)
                    {
                    case tt__H264Profile__Baseline:
                      std::cout << "H264 H264Profile    : Baseline" << std::endl;
                      break;
                    case tt__H264Profile__Main:
                      std::cout << "H264 H264Profile    : Main" << std::endl;
                      break;
                    case tt__H264Profile__Extended:
                      std::cout << "H264 H264Profile    : Extended" << std::endl;
                      break;
                    case tt__H264Profile__High:
                      std::cout << "H264 H264Profile    : High" << std::endl;
                      break;
                    default:
                      break;
                    }
                  }
                  if(GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Multicast)
                  {
                    switch (GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Multicast->Address->Type)
                    {
                    case tt__IPType__IPv4:
                      std::cout << "Multicast Address IPv4  : " << *GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Multicast->Address->IPv4Address << std::endl;
                      break;
                    case tt__IPType__IPv6:
                      std::cout << "Multicast Address IPv6  : " << *GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->Multicast->Address->IPv6Address << std::endl;
                      break;
                    default:
                      break;
                    }
                  }
                  std::cout << "SessionTimeout      : " << GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->SessionTimeout << std::endl;
                }
              }
              break;
            case EXIT_MODE:
              goto go_to_exit;
              break;
          }
          break;
        case EXIT_MODE:
          goto go_to_exit;
          break;
        default:
          break;
        }
        break;

      case MODE_SETUP:
        int view_setup_mode;
        do
        {
          std::cout << "Input 1- Add New User" << std::endl;
          std::cout << "Input 2- Delete User" << std::endl;
          std::cout << "Input 3- Set Resolution" << std::endl;
          std::cout << "Input 4- Set Frame rate" << std::endl;
          std::cout << "Input 5- Set Maximum bitrate" << std::endl;
          std::cout << "Input 0- Exit" << std::endl;
          std::cin >> view_setup_mode;
        } while (!(view_setup_mode == ADD_NEW_USER 
                || view_setup_mode == DELETE_USER 
                || view_setup_mode == SET_RESOLUTION 
                || view_setup_mode == SET_FRAME_RATE 
                || view_setup_mode == SET_MAX_BITRATE 
                || view_setup_mode == EXIT_MODE));
        std::cout << "------------------" << std::endl;
        
        switch (view_setup_mode)
        {
        case ADD_NEW_USER:
          /* code */
          proxyDevice.soap_endpoint = HOSTNAME;
          std::cout << "Input Username: ";
          std::cin >> username_create;
          std::cout << "Input password: ";
          std::cin >> password_create;
          int UserLevel;
          do
          {
            std::cout << "Input 1- UserLevel Administrator" << std::endl;
            std::cout << "Input 2- UserLevel Operator" << std::endl;
            std::cout << "Input 3- UserLevel User" << std::endl;
            std::cout << "Input 4- UserLevel Anonymous" << std::endl;
            std::cout << "Input 5- UserLevel Extended" << std::endl;
            std::cout << "Input 0- Exit" << std::endl;
            std::cin >> UserLevel;
          }while (!(UserLevel == Administrator 
                || UserLevel == Operator 
                || UserLevel == User 
                || UserLevel == Anonymous 
                || UserLevel == Extended 
                || UserLevel == EXIT_MODE));
          CreateUsers.User[0]->Username = username_create;
          CreateUsers.User[0]->Password = &password_create;
          switch(UserLevel)
          {
          case Administrator:
            CreateUsers.User[0]->UserLevel = tt__UserLevel__Administrator;
            break;
          case Operator:
            CreateUsers.User[0]->UserLevel = tt__UserLevel__Operator;
            break;
          case User:
            CreateUsers.User[0]->UserLevel = tt__UserLevel__User;
            break;
          case Anonymous:
            CreateUsers.User[0]->UserLevel = tt__UserLevel__Anonymous;
            break;
          case Extended:
            CreateUsers.User[0]->UserLevel = tt__UserLevel__Extended;
            break;
          case EXIT_MODE:
            goto go_to_exit;
            break;
          default:
            break;
          }  
          set_credentials(soap);
          if (proxyDevice.CreateUsers(&CreateUsers, CreateUsersResponse))
            report_error(soap);
          check_response(soap);
          break;
        case DELETE_USER:
          /* code */
          
          break;
        case SET_RESOLUTION:
          //for set up video config
          //get media endpoint
          proxyDevice.soap_endpoint = HOSTNAME;
          set_credentials(soap);
          if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
            report_error(soap);
          check_response(soap);
          //get stream uri
          proxyMedia.soap_endpoint = GetCapabilitiesResponse.Capabilities->Media->XAddr.c_str();
          // _trt__GetProfiles GetProfiles;
          // _trt__GetProfilesResponse GetProfilesResponse;
          set_credentials(soap);
          if (proxyMedia.GetProfiles(&GetProfiles, GetProfilesResponse))
            report_error(soap);
          check_response(soap);
          for (long unsigned int i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
          {
            if(GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration)
            {
              std::cout << "Input "<< i+1 << "- "<< GetProfilesResponse.Profiles[i]->Name << std::endl;
            }
          }
          int name_media;
          
          std::cin >> name_media;
          switch (name_media)
          {
          case MJPEG:
            namestring = "MJPEG";
            break;
          case H_264:
            namestring = "H.264";
            break;
          case PLUGINFREE:
            namestring = "PLUGINFREE";
            break;
          case MOBILE:
            namestring = "MOBILE";
            break;
          default:
            break;
          }
          for (long unsigned int i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
          {
            if(GetProfilesResponse.Profiles[i]->Name == namestring)
            {
              _trt__GetVideoEncoderConfiguration *GetVideoEncoderConfiguration = soap_new__trt__GetVideoEncoderConfiguration(soap, -1);
              _trt__GetVideoEncoderConfigurationResponse *GetVideoEncoderConfigurationResponse = soap_new__trt__GetVideoEncoderConfigurationResponse(soap, -1);
              GetVideoEncoderConfiguration->ConfigurationToken = GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->token;
              set_credentials(soap);
              if (proxyMedia.GetVideoEncoderConfiguration(GetVideoEncoderConfiguration, *GetVideoEncoderConfigurationResponse))
                report_error(soap);
              check_response(soap);
              //set up media
              _trt__SetVideoEncoderConfiguration *SetVideoEncoderConfiguration = soap_new__trt__SetVideoEncoderConfiguration(soap, -1);
              _trt__SetVideoEncoderConfigurationResponse *SetVideoEncoderConfigurationResponse = soap_new__trt__SetVideoEncoderConfigurationResponse(soap, -1);
              SetVideoEncoderConfiguration->Configuration = soap_new_tt__VideoEncoderConfiguration(soap, -1);
              SetVideoEncoderConfiguration->Configuration->token = GetVideoEncoderConfigurationResponse->Configuration->token;
              SetVideoEncoderConfiguration->Configuration->Name = GetVideoEncoderConfigurationResponse->Configuration->Name;
              SetVideoEncoderConfiguration->Configuration->UseCount = GetVideoEncoderConfigurationResponse->Configuration->UseCount;
              SetVideoEncoderConfiguration->Configuration->Encoding = GetVideoEncoderConfigurationResponse->Configuration->Encoding;
              SetVideoEncoderConfiguration->Configuration->Resolution = soap_new_tt__VideoResolution(soap, -1);
              std::cout << "Input Width: ";
              int Width;
              std::cin >> Width;
              SetVideoEncoderConfiguration->Configuration->Resolution->Width = Width;
              std::cout << "Input Height: ";
              int Height;
              std::cin >> Height;
              SetVideoEncoderConfiguration->Configuration->Resolution->Height = Height;
              SetVideoEncoderConfiguration->Configuration->Quality = GetVideoEncoderConfigurationResponse->Configuration->Quality;
              SetVideoEncoderConfiguration->Configuration->RateControl = soap_new_tt__VideoRateControl(soap, -1);
              SetVideoEncoderConfiguration->Configuration->RateControl->FrameRateLimit = GetVideoEncoderConfigurationResponse->Configuration->RateControl->FrameRateLimit;
              SetVideoEncoderConfiguration->Configuration->RateControl->EncodingInterval = GetVideoEncoderConfigurationResponse->Configuration->RateControl->EncodingInterval;
              SetVideoEncoderConfiguration->Configuration->RateControl->BitrateLimit = GetVideoEncoderConfigurationResponse->Configuration->RateControl->BitrateLimit;
              if(SetVideoEncoderConfiguration->Configuration->H264){
                SetVideoEncoderConfiguration->Configuration->H264 = soap_new_tt__H264Configuration(soap, -1);
                SetVideoEncoderConfiguration->Configuration->H264->GovLength = GetVideoEncoderConfigurationResponse->Configuration->H264->GovLength;
                SetVideoEncoderConfiguration->Configuration->H264->H264Profile = GetVideoEncoderConfigurationResponse->Configuration->H264->H264Profile;
              }
              if(SetVideoEncoderConfiguration->Configuration->MPEG4){
                SetVideoEncoderConfiguration->Configuration->MPEG4 = soap_new_tt__Mpeg4Configuration(soap, -1);
                SetVideoEncoderConfiguration->Configuration->MPEG4->GovLength = GetVideoEncoderConfigurationResponse->Configuration->MPEG4->GovLength;
                SetVideoEncoderConfiguration->Configuration->MPEG4->Mpeg4Profile = GetVideoEncoderConfigurationResponse->Configuration->MPEG4->Mpeg4Profile;
              }
              SetVideoEncoderConfiguration->Configuration->Multicast = soap_new_tt__MulticastConfiguration(soap, -1);
              SetVideoEncoderConfiguration->Configuration->Multicast->Address = soap_new_tt__IPAddress(soap, -1);
              SetVideoEncoderConfiguration->Configuration->Multicast->Address->Type = GetVideoEncoderConfigurationResponse->Configuration->Multicast->Address->Type;
              switch (SetVideoEncoderConfiguration->Configuration->Multicast->Address->Type)
              {
              case tt__IPType__IPv4:
                SetVideoEncoderConfiguration->Configuration->Multicast->Address->IPv4Address = GetVideoEncoderConfigurationResponse->Configuration->Multicast->Address->IPv4Address;
                break;
              case tt__IPType__IPv6:
                SetVideoEncoderConfiguration->Configuration->Multicast->Address->IPv6Address = GetVideoEncoderConfigurationResponse->Configuration->Multicast->Address->IPv6Address;
                break;
              default:
                break;
              }
              SetVideoEncoderConfiguration->Configuration->Multicast->Port = GetVideoEncoderConfigurationResponse->Configuration->Multicast->Port;
              SetVideoEncoderConfiguration->Configuration->Multicast->TTL = GetVideoEncoderConfigurationResponse->Configuration->Multicast->TTL;
              SetVideoEncoderConfiguration->Configuration->Multicast->AutoStart = GetVideoEncoderConfigurationResponse->Configuration->Multicast->AutoStart;
              SetVideoEncoderConfiguration->Configuration->SessionTimeout = GetVideoEncoderConfigurationResponse->Configuration->SessionTimeout;
              SetVideoEncoderConfiguration->ForcePersistence = false;

              set_credentials(soap);
              if (proxyMedia.SetVideoEncoderConfiguration(SetVideoEncoderConfiguration, *SetVideoEncoderConfigurationResponse))
                report_error(soap);
              check_response(soap);
            
            }
          }
          
          break;
        case SET_FRAME_RATE:
          //get media endpoint
          proxyDevice.soap_endpoint = HOSTNAME;
          set_credentials(soap);
          if (proxyDevice.GetCapabilities(&GetCapabilities, GetCapabilitiesResponse))
            report_error(soap);
          check_response(soap);
          //get stream uri
          proxyMedia.soap_endpoint = GetCapabilitiesResponse.Capabilities->Media->XAddr.c_str();
          // _trt__GetProfiles GetProfiles;
          // _trt__GetProfilesResponse GetProfilesResponse;
          set_credentials(soap);
          if (proxyMedia.GetProfiles(&GetProfiles, GetProfilesResponse))
            report_error(soap);
          check_response(soap);
          for (long unsigned int i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
          {
            if(GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration)
            {
              std::cout << "Input "<< i+1 << "- "<< GetProfilesResponse.Profiles[i]->Name << std::endl;
            }
          }
          // int name_media;
          
          std::cin >> name_media;
          switch (name_media)
          {
          case MJPEG:
            namestring = "MJPEG";
            break;
          case H_264:
            namestring = "H.264";
            break;
          case PLUGINFREE:
            namestring = "PLUGINFREE";
            break;
          case MOBILE:
            namestring = "MOBILE";
            break;
          default:
            break;
          }

          for (long unsigned int i = 0; i < GetProfilesResponse.Profiles.size(); ++i)
          {
            if(GetProfilesResponse.Profiles[i]->Name == namestring)
            {
              _trt__GetVideoEncoderConfiguration *GetVideoEncoderConfiguration = soap_new__trt__GetVideoEncoderConfiguration(soap, -1);
              _trt__GetVideoEncoderConfigurationResponse *GetVideoEncoderConfigurationResponse = soap_new__trt__GetVideoEncoderConfigurationResponse(soap, -1);
              GetVideoEncoderConfiguration->ConfigurationToken = GetProfilesResponse.Profiles[i]->VideoEncoderConfiguration->token;
              set_credentials(soap);
              if (proxyMedia.GetVideoEncoderConfiguration(GetVideoEncoderConfiguration, *GetVideoEncoderConfigurationResponse))
                report_error(soap);
              check_response(soap);
              //set up media
              _trt__SetVideoEncoderConfiguration *SetVideoEncoderConfiguration = soap_new__trt__SetVideoEncoderConfiguration(soap, -1);
              _trt__SetVideoEncoderConfigurationResponse *SetVideoEncoderConfigurationResponse = soap_new__trt__SetVideoEncoderConfigurationResponse(soap, -1);
              SetVideoEncoderConfiguration->Configuration = soap_new_tt__VideoEncoderConfiguration(soap, -1);
              SetVideoEncoderConfiguration->Configuration->token = GetVideoEncoderConfigurationResponse->Configuration->token;
              SetVideoEncoderConfiguration->Configuration->Name = GetVideoEncoderConfigurationResponse->Configuration->Name;
              SetVideoEncoderConfiguration->Configuration->UseCount = GetVideoEncoderConfigurationResponse->Configuration->UseCount;
              SetVideoEncoderConfiguration->Configuration->Encoding = GetVideoEncoderConfigurationResponse->Configuration->Encoding;
              SetVideoEncoderConfiguration->Configuration->Resolution = soap_new_tt__VideoResolution(soap, -1);
              SetVideoEncoderConfiguration->Configuration->Resolution->Width = GetVideoEncoderConfigurationResponse->Configuration->Resolution->Width;
              SetVideoEncoderConfiguration->Configuration->Resolution->Height = GetVideoEncoderConfigurationResponse->Configuration->Resolution->Height;
              SetVideoEncoderConfiguration->Configuration->Quality = GetVideoEncoderConfigurationResponse->Configuration->Quality;
              SetVideoEncoderConfiguration->Configuration->RateControl = soap_new_tt__VideoRateControl(soap, -1);
              // int max_frame;
              int input_frame;
              std::cout << "Input Frame: ";
              std::cin >> input_frame;
              SetVideoEncoderConfiguration->Configuration->RateControl->FrameRateLimit = input_frame;
              SetVideoEncoderConfiguration->Configuration->RateControl->EncodingInterval = GetVideoEncoderConfigurationResponse->Configuration->RateControl->EncodingInterval;
              SetVideoEncoderConfiguration->Configuration->RateControl->BitrateLimit = GetVideoEncoderConfigurationResponse->Configuration->RateControl->BitrateLimit;
              if(SetVideoEncoderConfiguration->Configuration->H264){
                SetVideoEncoderConfiguration->Configuration->H264 = soap_new_tt__H264Configuration(soap, -1);
                SetVideoEncoderConfiguration->Configuration->H264->GovLength = GetVideoEncoderConfigurationResponse->Configuration->H264->GovLength;
                SetVideoEncoderConfiguration->Configuration->H264->H264Profile = GetVideoEncoderConfigurationResponse->Configuration->H264->H264Profile;
              }
              if(SetVideoEncoderConfiguration->Configuration->MPEG4){
                SetVideoEncoderConfiguration->Configuration->MPEG4 = soap_new_tt__Mpeg4Configuration(soap, -1);
                SetVideoEncoderConfiguration->Configuration->MPEG4->GovLength = GetVideoEncoderConfigurationResponse->Configuration->MPEG4->GovLength;
                SetVideoEncoderConfiguration->Configuration->MPEG4->Mpeg4Profile = GetVideoEncoderConfigurationResponse->Configuration->MPEG4->Mpeg4Profile;
              }
              SetVideoEncoderConfiguration->Configuration->Multicast = soap_new_tt__MulticastConfiguration(soap, -1);
              SetVideoEncoderConfiguration->Configuration->Multicast->Address = soap_new_tt__IPAddress(soap, -1);
              SetVideoEncoderConfiguration->Configuration->Multicast->Address->Type = GetVideoEncoderConfigurationResponse->Configuration->Multicast->Address->Type;
              switch (SetVideoEncoderConfiguration->Configuration->Multicast->Address->Type)
              {
              case tt__IPType__IPv4:
                SetVideoEncoderConfiguration->Configuration->Multicast->Address->IPv4Address = GetVideoEncoderConfigurationResponse->Configuration->Multicast->Address->IPv4Address;
                break;
              case tt__IPType__IPv6:
                SetVideoEncoderConfiguration->Configuration->Multicast->Address->IPv6Address = GetVideoEncoderConfigurationResponse->Configuration->Multicast->Address->IPv6Address;
                break;
              default:
                break;
              }
              SetVideoEncoderConfiguration->Configuration->Multicast->Port = GetVideoEncoderConfigurationResponse->Configuration->Multicast->Port;
              SetVideoEncoderConfiguration->Configuration->Multicast->TTL = GetVideoEncoderConfigurationResponse->Configuration->Multicast->TTL;
              SetVideoEncoderConfiguration->Configuration->Multicast->AutoStart = GetVideoEncoderConfigurationResponse->Configuration->Multicast->AutoStart;
              SetVideoEncoderConfiguration->Configuration->SessionTimeout = GetVideoEncoderConfigurationResponse->Configuration->SessionTimeout;
              SetVideoEncoderConfiguration->ForcePersistence = false;

              set_credentials(soap);
              if (proxyMedia.SetVideoEncoderConfiguration(SetVideoEncoderConfiguration, *SetVideoEncoderConfigurationResponse))
                report_error(soap);
              check_response(soap);
            
            }
          }

          break;
        case SET_MAX_BITRATE:
          /* code */
          break;
        case EXIT_MODE:
          /* code */
          break;
        default:
          break;
        }


        
        break;
      default:
        break;
      }
    go_to_exit:
    std::cout << "END" << std::endl;
  }
  

  // free all deserialized and managed data, we can still reuse the context and proxies after this
  soap_destroy(soap);
  soap_end(soap);

  // free the shared context, proxy classes must terminate as well after this
  soap_free(soap);

  // clean up OpenSSL mutex
  CRYPTO_thread_cleanup();

  return 0;
}

/******************************************************************************\
 *
 *	WS-Discovery event handlers must be defined, even when not used
 *
\******************************************************************************/

void wsdd_event_Hello(struct soap *soap, unsigned int InstanceId, const char *SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, const char *EndpointReference, const char *Types, const char *Scopes, const char *MatchBy, const char *XAddrs, unsigned int MetadataVersion)
{ }

void wsdd_event_Bye(struct soap *soap, unsigned int InstanceId, const char *SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, const char *EndpointReference, const char *Types, const char *Scopes, const char *MatchBy, const char *XAddrs, unsigned int *MetadataVersion)
{ }

soap_wsdd_mode wsdd_event_Probe(struct soap *soap, const char *MessageID, const char *ReplyTo, const char *Types, const char *Scopes, const char *MatchBy, struct wsdd__ProbeMatchesType *ProbeMatches)
{
  return SOAP_WSDD_ADHOC;
}

void wsdd_event_ProbeMatches(struct soap *soap, unsigned int InstanceId, const char *SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, struct wsdd__ProbeMatchesType *ProbeMatches)
{ }

soap_wsdd_mode wsdd_event_Resolve(struct soap *soap, const char *MessageID, const char *ReplyTo, const char *EndpointReference, struct wsdd__ResolveMatchType *match)
{
  return SOAP_WSDD_ADHOC;
}

void wsdd_event_ResolveMatches(struct soap *soap, unsigned int InstanceId, const char * SequenceId, unsigned int MessageNumber, const char *MessageID, const char *RelatesTo, struct wsdd__ResolveMatchType *match)
{ }

int SOAP_ENV__Fault(struct soap *soap, char *faultcode, char *faultstring, char *faultactor, struct SOAP_ENV__Detail *detail, struct SOAP_ENV__Code *SOAP_ENV__Code, struct SOAP_ENV__Reason *SOAP_ENV__Reason, char *SOAP_ENV__Node, char *SOAP_ENV__Role, struct SOAP_ENV__Detail *SOAP_ENV__Detail)
{
  // populate the fault struct from the operation arguments to print it
  soap_fault(soap);
  // SOAP 1.1
  soap->fault->faultcode = faultcode;
  soap->fault->faultstring = faultstring;
  soap->fault->faultactor = faultactor;
  soap->fault->detail = detail;
  // SOAP 1.2
  soap->fault->SOAP_ENV__Code = SOAP_ENV__Code;
  soap->fault->SOAP_ENV__Reason = SOAP_ENV__Reason;
  soap->fault->SOAP_ENV__Node = SOAP_ENV__Node;
  soap->fault->SOAP_ENV__Role = SOAP_ENV__Role;
  soap->fault->SOAP_ENV__Detail = SOAP_ENV__Detail;
  // set error
  soap->error = SOAP_FAULT;
  // handle or display the fault here with soap_stream_fault(soap, std::cerr);
  // return HTTP 202 Accepted
  return soap_send_empty_response(soap, SOAP_OK);
}

/******************************************************************************\
 *
 *	OpenSSL
 *
\******************************************************************************/

#ifdef WITH_OPENSSL

struct CRYPTO_dynlock_value
{ MUTEX_TYPE mutex;
};

static MUTEX_TYPE *mutex_buf;

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, int line)
{ struct CRYPTO_dynlock_value *value;
  value = (struct CRYPTO_dynlock_value*)malloc(sizeof(struct CRYPTO_dynlock_value));
  if (value)
    MUTEX_SETUP(value->mutex);
  return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{ if (mode & CRYPTO_LOCK)
    MUTEX_LOCK(l->mutex);
  else
    MUTEX_UNLOCK(l->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
{ MUTEX_CLEANUP(l->mutex);
  free(l);
}

void locking_function(int mode, int n, const char *file, int line)
{ if (mode & CRYPTO_LOCK)
    MUTEX_LOCK(mutex_buf[n]);
  else
    MUTEX_UNLOCK(mutex_buf[n]);
}

unsigned long id_function()
{ return (unsigned long)THREAD_ID;
}

int CRYPTO_thread_setup()
{ int i;
  mutex_buf = (MUTEX_TYPE*)malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  if (!mutex_buf)
    return SOAP_EOM;
  for (i = 0; i < CRYPTO_num_locks(); i++)
    MUTEX_SETUP(mutex_buf[i]);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  CRYPTO_set_dynlock_create_callback(dyn_create_function);
  CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
  CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
  return SOAP_OK;
}

void CRYPTO_thread_cleanup()
{ int i;
  if (!mutex_buf)
    return;
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  CRYPTO_set_dynlock_create_callback(NULL);
  CRYPTO_set_dynlock_lock_callback(NULL);
  CRYPTO_set_dynlock_destroy_callback(NULL);
  for (i = 0; i < CRYPTO_num_locks(); i++)
    MUTEX_CLEANUP(mutex_buf[i]);
  free(mutex_buf);
  mutex_buf = NULL;
}

#else

/* OpenSSL not used */

int CRYPTO_thread_setup()
{
  return SOAP_OK;
}

void CRYPTO_thread_cleanup()
{ }

#endif
