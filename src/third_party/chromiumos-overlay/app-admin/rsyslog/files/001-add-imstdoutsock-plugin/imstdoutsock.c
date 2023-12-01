/* imstdoutsock.c
 *
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

// rsyslog.h must be included before other rsyslog header files.
#include "rsyslog.h"

#include "datetime.h"
#include "dirty.h"
#include "errmsg.h"
#include "glbl.h"
#include "module-template.h"
#include "msg.h"
#include "prop.h"
#include "srUtils.h"
#include "unicode-helper.h"

MODULE_TYPE_INPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("imstdoutsock")

DEF_IMOD_STATIC_DATA
DEFobjCurrIf(glbl)
DEFobjCurrIf(prop)
DEFobjCurrIf(datetime)


#define HANDLE_EINTR(x) ({ \
  __typeof__(x) eintr_wrapper_result; \
  do { \
    eintr_wrapper_result = (x); \
  } while (eintr_wrapper_result == -1 && errno == EINTR); \
  eintr_wrapper_result; \
})


// Configurations:
static const uchar* kInputName = UCHAR_CONSTANT("imstdoutsock");
static const int kCreateMode = 0644;
static const int kSocketBacklogNumber = 5;

struct modConfData_s {
  // Overall config object.
  rsconf_t* pConf;
  // Path to bind an unix socket to.
  uchar* pszBindPath;
};

// Module global configuration parameter definition:
static struct cnfparamdescr modpdescr[] = {
  { "path", eCmdHdlrString, 0 }
};
static struct cnfparamblk modpblk =
  { CNFPARAMBLK_VERSION,
    sizeof(modpdescr)/sizeof(struct cnfparamdescr),
    modpdescr
  };

typedef struct session_s session_t;
typedef struct epoll_entry_s epoll_entry_t;
typedef struct server_s server_t;

// Type of epoll event.
typedef enum {
  EPOLL_EVENT_SERVER,
  EPOLL_EVENT_SESSION
} epoll_entry_type_t;

// Type of epoll descriptor.
struct epoll_entry_s {
  epoll_entry_type_t type;
  struct epoll_event ev;
  union {
    void* raw;
    session_t* session;
    server_t* server;
  } ptr;
};

struct server_s {
  int sock;
  epoll_entry_t* pEpollEntry;

  // First session associated with this server.
  session_t* pSessions;

  uchar* path;
  prop_t* propInputName;
};

struct session_s {
  int sock;
  epoll_entry_t* pEpollEntry;

  // Linked list to other other sessions.
  session_t *prev, *next;

  server_t* pServer;

  // The current state of parse.
  enum {
    PARSING_IN_HEADER,
    PARSING_IN_BODY,
  } parseState;

  // Property of the message.
  uchar* pMessage;
  int iMessageSize;
  int iMaxLine;
  uchar* pTag;
  syslog_pri_t priority;
};


// Forward declaration.
static rsRetVal
InstallEpollEntry(epoll_entry_type_t type, void *ptr, int sock,
  epoll_entry_t **pNewEpollEntry);


// Global variables
static modConfData_t* g_load_mod_conf = NULL;
static server_t* g_server = NULL;
static int g_epoll_fd = -1;


///////////////////////////////////////////////////////////////////////////////
// Utility functions

/* put the string to prop object. */
static rsRetVal
ConvertStringToProp(prop_t** pProp, const uchar* szValueString)
{
  DEFiRet;

  uchar* szSafeValueString;
  // Copy the string to a temporary buffer.
  CHKmalloc(szSafeValueString = ustrdup(szValueString));

  // Store the value into a prop object.
  CHKiRet(prop.Construct(pProp));
  CHKiRet(
    prop.SetString(*pProp, szSafeValueString, ustrlen(szSafeValueString)));
  CHKiRet(prop.ConstructFinalize(*pProp));

finalize_it:
  free(szSafeValueString);

  if (iRet != RS_RET_OK && *pProp != NULL)
    prop.Destruct(pProp);
  RETiRet;
}


///////////////////////////////////////////////////////////////////////////////
// Message parsing and submitting functions
//
// A message consists of header and body. And they are splitted with a blank
// line.
//
// Sample message:
//  > TAG=process[1234]
//  > PRIORITY=5
//  >
//  > this is a stdout from the process
//  > hello, hello, hello, ...

/* submit the message to rsyslog core. */
static rsRetVal
SubmitMessage(const session_t* pSession, const struct syslogTime* stTime,
    time_t ttGenTime)
{
  DEFiRet;

  int line_len = pSession->iMessageSize;

  // Removing a trailing line break from the length.
  if (pSession->pMessage[line_len - 1] == '\n')
    line_len--;

  if (line_len <= 0) {
    // Ignore an empty line or just a line break.
    FINALIZE;
  }

  smsg_t* pMessage;

  // Construct a message.
  CHKiRet(msgConstructWithTime(&pMessage, stTime, ttGenTime));
  MsgSetMSGoffs(pMessage, 0);
  MsgSetFlowControlType(pMessage, eFLOWCTL_LIGHT_DELAY);
  MsgSetRcvFrom(pMessage, glbl.GetLocalHostNameProp());
  MsgSetHOSTNAME(pMessage, glbl.GetLocalHostName(),
                 ustrlen(glbl.GetLocalHostName()));
  MsgSetInputName(pMessage, pSession->pServer->propInputName);
  MsgSetTAG(pMessage, pSession->pTag, ustrlen(pSession->pTag));
  msgSetPRI(pMessage, pSession->priority);
  // Removing a trailing line break from the length.
  MsgSetRawMsg(pMessage, (char*)pSession->pMessage, line_len);

  // Submit the message to the rsyslogd core.
  CHKiRet(submitMsg2(pMessage));

finalize_it:
  RETiRet;
}


/* process a header line.
 * We supprts only "TAG" and "PRIORITY" headers. */
static rsRetVal
ProcessHeaderLine(session_t* pSession)
{
  // Reasonable limit (256 char) of maximum header line.
  const int kMaximumHeaderLineLength = MIN(256, pSession->iMaxLine - 1);

  DEFiRet;

  int line_len = pSession->iMessageSize;

  // Remove a trailing line break from the current line.
  if (pSession->pMessage[line_len - 1] == '\n')
    line_len--;

  if (line_len >= kMaximumHeaderLineLength) {
    // Ignore an overflown part of a long header line.
    line_len = kMaximumHeaderLineLength;
  }

  const char kTagHeaderPrefix[] = "TAG=";
  const int kLengthOfTagHeaderPrefix = sizeof(kTagHeaderPrefix) - 1;

  const char kPriorityHeaderPrefix[] = "PRIORITY=";
  const int kLengthOfPriorityHeaderPrefix = sizeof(kPriorityHeaderPrefix) - 1;

  if (line_len > kLengthOfTagHeaderPrefix &&
      strncmp((char*)pSession->pMessage, kTagHeaderPrefix,
              kLengthOfTagHeaderPrefix) == 0) {

    // Calculate the tag length by removing lengths of the tag header and a
    // terminating null.
    const int tag_length = line_len - kLengthOfTagHeaderPrefix;
    // The raw tag + a following collon ':' + a following null '\0'.
    const int tag_buffer_length = tag_length + 2;

    CHKmalloc(pSession->pTag = malloc(tag_buffer_length));
    memcpy(pSession->pTag, (pSession->pMessage + kLengthOfTagHeaderPrefix),
           tag_length);
    // Replace a non-graphable char with an underscore.
    for (int i = 0; i < tag_length; i++) {
      if (!isgraph(pSession->pTag[i]))
        pSession->pTag[i] = '_';
    }
    pSession->pTag[tag_length + 0] = ':';
    pSession->pTag[tag_length + 1] = '\0';
  } else if (line_len > kLengthOfPriorityHeaderPrefix &&
      strncmp((char*)pSession->pMessage, kPriorityHeaderPrefix,
              kLengthOfPriorityHeaderPrefix) == 0) {
    int priority = LOG_DEBUG;

    // The format is valid: a single character.
    if (line_len == kLengthOfPriorityHeaderPrefix + 1) {
      // Priority must be a single integer character.
      priority = pSession->pMessage[kLengthOfPriorityHeaderPrefix] - '0';

      // Drop an invalid value.
      if (priority > LOG_DEBUG || priority < 0)
        priority = LOG_DEBUG;
    }

    pSession->priority = priority;
  }

finalize_it:
  RETiRet;
}


/* process a received character. */
static rsRetVal
ProcessReceivedCharacters(
  session_t* pSession, const char c,
  const struct syslogTime* stTime, time_t ttGenTime)
{
  DEFiRet;

  if (pSession->iMessageSize < pSession->iMaxLine)
    pSession->pMessage[pSession->iMessageSize++] = c;

  bool is_buffer_full = (pSession->iMessageSize >= pSession->iMaxLine);

  switch (pSession->parseState) {
    case PARSING_IN_HEADER:
      // If the line is too long, the overflown part is just silently ignored.

      if (c == '\n') {
        if (pSession->iMessageSize == 1) {
          // Transition from HEADER to BODY state, since it's an empty line.
          pSession->parseState = PARSING_IN_BODY;
        } else {
          iRet = ProcessHeaderLine(pSession);
        }
        pSession->iMessageSize = 0;
        CHKiRet(iRet);
      }
      break;
    case PARSING_IN_BODY: {
      if (is_buffer_full) {
        LogError(0, NO_ERRCODE, "imstdoutsock: received line is longer than"
                 " the maximum line length. Line will be splitted.");
      }
      if (is_buffer_full || c == '\n') {
        iRet = SubmitMessage(pSession, stTime, ttGenTime);
        pSession->iMessageSize = 0;
        CHKiRet(iRet);
      }
      break;
    }
  }

finalize_it:
  RETiRet;
}


/* process a received data (stream). */
static rsRetVal
ProcessReceivedData(session_t* pSession, const char* pData, size_t iLen)
{
  DEFiRet;

  assert(pData != NULL);
  assert(iLen > 0);

    // Retrieve the current time.
  struct syslogTime stTime;
  time_t ttGenTime = 0;
  datetime.getCurrTime(&stTime, &ttGenTime, TIME_IN_LOCALTIME);

  const char* pEnd = pData + iLen;
  for (const char* p = pData; p < pEnd; p++) {
    CHKiRet(ProcessReceivedCharacters(pSession, *p, &stTime, ttGenTime));
  }

finalize_it:
  RETiRet;
}


///////////////////////////////////////////////////////////////////////////////
// Session

/* destructor */
static void DestroySession(session_t* pSession) {
  free(pSession->pTag);
  free(pSession->pEpollEntry);
  free(pSession->pMessage);

  // Fill NULLs to prevent use-after-free.
  pSession->pTag = NULL;
  pSession->pEpollEntry = NULL;
  pSession->pMessage = NULL;

  free(pSession);
}


/* constructor */
static rsRetVal CreateSession(server_t* pServer, session_t** pNewSession) {
  DEFiRet;
  session_t* pSession;

  CHKmalloc(pSession = malloc(sizeof(session_t)));

  // Initialize the object.
  pSession->pTag = NULL;
  pSession->pEpollEntry = NULL;
  pSession->priority = LOG_INFO;
  pSession->pServer = pServer;
  pSession->parseState = PARSING_IN_HEADER;
  pSession->iMessageSize = 0;
  pSession->iMaxLine = glbl.GetMaxLine();
  pSession->sock = -1;
  pSession->prev = NULL;
  pSession->next = NULL;

  // Ensure the max line length is bigger than a reasonable limit.
  assert(pSession->iMaxLine >= 80);

  CHKmalloc(pSession->pMessage = malloc(pSession->iMaxLine));

  // Link to the prev and next sessions (bi-linked list).
  pSession->next = pServer->pSessions;
  if (pServer->pSessions != NULL)
    pServer->pSessions->prev = pSession;
  pServer->pSessions = pSession;

  *pNewSession = pSession;
  pSession = NULL;

finalize_it:
  if (pSession != NULL) {
    // Ensure the session is not in the list.
    assert(pSession->next == NULL);
    assert(pServer->pSessions != pSession);

    DestroySession(pSession);
  }

  RETiRet;
}


/* Cleanup the session. This also destries the object. */
static void CloseAndDestroySession(session_t* pSession) {
  close(pSession->sock);

  if (pSession->pServer->pSessions == pSession) {
    assert(pSession->prev == NULL);
    pSession->pServer->pSessions = pSession->next;
  }

  // Unlink from the prev and next sessions (bi-linked list).
  if (pSession->next != NULL)
    pSession->next->prev = pSession->prev;
  if (pSession->prev != NULL)
    pSession->prev->next = pSession->next;

  DestroySession(pSession);
}


///////////////////////////////////////////////////////////////////////////////
// Server

/* destructor */
static void
DestroyServer(server_t* pServer)
{
  if (pServer->propInputName != NULL)
    prop.Destruct(&pServer->propInputName);

  free(pServer->pEpollEntry);
  free(pServer->path);
  free(pServer);
}


/* Close the socket and its sessions. */
static void
CloseServer(const server_t* pServer)
{
  // Close the server socket
  close(pServer->sock);

  // Remove the sock file.
  unlink((char*) pServer->path);

  // Close the sessions.
  while (pServer->pSessions != NULL)
    CloseAndDestroySession(pServer->pSessions);
}


/* accept a connection to the server */
static rsRetVal
AcceptConnection(const server_t* pServer, session_t* pSession)
{
  DEFiRet;

  int sock = HANDLE_EINTR(accept(pServer->sock, NULL, NULL));

  if (sock < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EMFILE)
      ABORT_FINALIZE(RS_RET_NO_MORE_DATA);

    LogError(errno, RS_RET_ACCEPT_ERR, "imstdoutsock: "
             "error on accepting connection on server socket");
    ABORT_FINALIZE(RS_RET_ACCEPT_ERR);
  }

  // Get the current socket flags.
  int sockflags = fcntl(sock, F_GETFL);
  if (sockflags == -1) {
    LogError(errno, RS_RET_IO_ERROR, "imstdoutsock: "
             "error on getting sock flags on accepted sock %d", sock);
    ABORT_FINALIZE(RS_RET_IO_ERROR);
  }

  // Set the socket flags with enabling non-blocking I/O.
  sockflags |= O_NONBLOCK;
  sockflags = fcntl(sock, F_SETFL, sockflags);
  if (sockflags == -1) {
    LogError(errno, RS_RET_IO_ERROR, "imstdoutsock: "
             "error on setting fcntl(O_NONBLOCK) on accepted sock %d", sock);
    ABORT_FINALIZE(RS_RET_IO_ERROR);
  }

  pSession->sock = sock;
  CHKiRet(InstallEpollEntry(EPOLL_EVENT_SESSION, pSession, sock,
      &pSession->pEpollEntry));

finalize_it:
  if (iRet != RS_RET_OK) {
    if (iRet != RS_RET_NO_MORE_DATA) {
      LogError(0, NO_ERRCODE, "imstdoutsock: connection could not be "
               "established.");
    }
    close(sock);
  }

  RETiRet;
}


/* initialize the server */
static rsRetVal StartupServer(server_t* pServer) {
  DEFiRet;

  const uchar* path = pServer->path == NULL ? UCHAR_CONSTANT("") : pServer->path;

  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
    LogError(errno, RS_RET_ERR_CRE_AFUX,
             "imstdoutsock: error on creating server socket");
    ABORT_FINALIZE(RS_RET_ERR_CRE_AFUX);
  }

  struct sockaddr_un local;
  local.sun_family = AF_UNIX;
  strncpy(local.sun_path, (char*)path, sizeof(local.sun_path) - 1);

  // Get the current socket flags.
  int sockflags = fcntl(sock, F_GETFL);
  if (sockflags == -1) {
    LogError(errno, RS_RET_IO_ERROR,
             "imstdoutsock: error on getting sock flags on server socket");
    ABORT_FINALIZE(RS_RET_IO_ERROR);
  }

  // Set the socket flags with enabling non-blocking I/O.
  sockflags |= O_NONBLOCK;
  sockflags = fcntl(sock, F_SETFL, sockflags);
  if (sockflags == -1) {
    LogError(errno, RS_RET_IO_ERROR, "imstdoutsock: "
             "error on setting fcntl(O_NONBLOCK) on server socket");
    ABORT_FINALIZE(RS_RET_IO_ERROR);
  }

  if (bind(sock, (struct sockaddr*)&local, SUN_LEN(&local)) < 0) {
    LogError(errno, RS_RET_COULD_NOT_BIND,
             "imstdoutsock: error on binding server socket %s", pServer->path);
    ABORT_FINALIZE(RS_RET_COULD_NOT_BIND);
  }

  if (listen(sock, kSocketBacklogNumber) < 0) {
    LogError(errno, RS_RET_IO_ERROR,
             "imstdoutsock: error on starting listening unix socket");
    ABORT_FINALIZE(RS_RET_IO_ERROR);
  }

  if (chmod(local.sun_path, kCreateMode) != 0) {
    LogError(errno, RS_RET_IO_ERROR,
             "imstdoutsock: error on chmod of unix socket");
    ABORT_FINALIZE(RS_RET_IO_ERROR);
  }

  pServer->sock = sock;
  CHKiRet(InstallEpollEntry(EPOLL_EVENT_SERVER, pServer, sock,
      &pServer->pEpollEntry));

finalize_it:
  if (iRet != RS_RET_OK) {
    close(sock);
    pServer->sock = -1;
  }

  RETiRet;
}


/* constructor */
static rsRetVal
CreateServer(const modConfData_t* pModConf, server_t** pCreatedSrv)
{
  DEFiRet;
  server_t* pServer;

  CHKmalloc(pServer = calloc(1, sizeof(server_t)));
  pServer->pSessions = NULL;
  pServer->sock = -1;
  CHKmalloc(pServer->path = ustrdup(pModConf->pszBindPath));
  CHKiRet(ConvertStringToProp(&pServer->propInputName, kInputName));

  assert(*pCreatedSrv == NULL);
  *pCreatedSrv = pServer;

finalize_it:
  if (iRet != RS_RET_OK && pServer != NULL) {
    DestroyServer(pServer);
    *pCreatedSrv = NULL;
  }

  RETiRet;
}

///////////////////////////////////////////////////////////////////////////////
// epoll handlers and manipulation methods

/* handler on a server socket.
 * This is called when the new connection comes. */
static rsRetVal
OnServerActive(server_t* pServer)
{
  DEFiRet;

  while (glbl.GetGlobalInputTermState() == 0) {
    rsRetVal iLocalRet;
    session_t *pSession = NULL;

    iLocalRet = CreateSession(pServer, &pSession);
    if (iLocalRet != RS_RET_OK) {
      ABORT_FINALIZE(iLocalRet);
    }

    if (glbl.GetGlobalInputTermState() == 1) {
      CloseAndDestroySession(pSession);
      break;
    }

    iLocalRet = AcceptConnection(pServer, pSession);
    if (iLocalRet == RS_RET_NO_MORE_DATA) {
      CloseAndDestroySession(pSession);
      break;
    }
    if (iLocalRet != RS_RET_OK) {
      // Error occurred.
      LogError(errno, RS_RET_IO_ERROR, "imstdoutsock: error on "
               "AcceptConnection().");
      CloseAndDestroySession(pSession);
      break;
    }

    CHKiRet(iLocalRet);
  }

finalize_it:
  RETiRet;
}


/* handler on a established socket.
 * This is called when the new data comes on an establish socket. */
static rsRetVal
OnSessionActive(session_t* pSession)
{
  DEFiRet;

  while (true) {
    char rcvBuf[128*1024];
    const size_t lenBuf = sizeof(rcvBuf);
    int lenRcv = HANDLE_EINTR(recv(pSession->sock, rcvBuf, lenBuf, 0));

    if (lenRcv == 0) {
      // Connection closed.
      ABORT_FINALIZE(RS_RET_IO_ERROR);
      break;
    }

    if (lenRcv < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;

      // An error occurred.
      LogError(errno, RS_RET_IO_ERROR, "imstdoutsock: error on recv().");
      ABORT_FINALIZE(RS_RET_IO_ERROR);
      break;
    }

    // Process the received data
    CHKiRet(ProcessReceivedData(pSession, rcvBuf, lenRcv));
  }

finalize_it:
  if (iRet != RS_RET_OK)
    CloseAndDestroySession(pSession);

  RETiRet;
}


/* Install an epoll entry which hooks the change on socket. */
static rsRetVal
InstallEpollEntry(
  epoll_entry_type_t type, void *ptr, int sock,
  epoll_entry_t **pNewEpollEntry)
{
  DEFiRet;
  epoll_entry_t *pEpollEntry = NULL;

  if (g_epoll_fd == -1) {
    // We shouldn't call this function in the case of invalid the epoll FD, but
    // check here just in case.
    LogError(errno, RS_RET_EPOLL_CTL_FAILED,
             "imstdoutsock: Epoll can't be called, since the FD is invalid.");
    ABORT_FINALIZE(RS_RET_EPOLL_CTL_FAILED);
  }

  CHKmalloc(pEpollEntry = calloc(1, sizeof(epoll_entry_t)));
  pEpollEntry->type = type;
  pEpollEntry->ptr.raw = ptr;
  pEpollEntry->ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
  pEpollEntry->ev.data.ptr = pEpollEntry;

  *pNewEpollEntry = pEpollEntry;

  if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sock, &(pEpollEntry->ev)) != 0) {
    LogError(errno, RS_RET_EPOLL_CTL_FAILED,
             "imstdoutsock: error on adding epoll entry");
    ABORT_FINALIZE(RS_RET_EPOLL_CTL_FAILED);
  }

finalize_it:
  if (iRet != RS_RET_OK) {
    free(pEpollEntry);
    *pNewEpollEntry = NULL;
  }
  RETiRet;
}

/* process an epoll event when happens.
 * This checks the type and calls a handler. */
static void
ProcessEpollEvent(epoll_entry_t* pEpollEntry)
{
  rsRetVal iLocalRet;

  int sock = -1;
  switch(pEpollEntry->type) {
  case EPOLL_EVENT_SERVER:
    OnServerActive(pEpollEntry->ptr.server);
    sock = pEpollEntry->ptr.server->sock;
    break;
  case EPOLL_EVENT_SESSION:
    iLocalRet = OnSessionActive(pEpollEntry->ptr.session);
    sock = pEpollEntry->ptr.session->sock;
    break;
  default:
    LogError(0, RS_RET_INTERNAL_ERROR, "imstdoutsock: "
             "error: invalid epoll_entry_type_t %d", pEpollEntry->type);
    break;
  }

  if (iLocalRet == RS_RET_OK) {
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, sock,
        &(pEpollEntry->ev)) < 0) {
      LogError(errno, RS_RET_ERR_EPOLL_CTL, "imstdoutsock: "
               "error on epoll_ctl().");
    }
  }
}


///////////////////////////////////////////////////////////////////////////////
// rsyslog module entry points

BEGINnewInpInst
CODESTARTnewInpInst
ENDnewInpInst


BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
  g_load_mod_conf = pModConf;
  pModConf->pConf = pConf;
ENDbeginCnfLoad


BEGINsetModCnf
CODESTARTsetModCnf
  struct cnfparamvals* paramVals = nvlstGetParams(lst, &modpblk, NULL);
  if (paramVals == NULL) {
    LogError(0, RS_RET_MISSING_CNFPARAMS, "imstdoutsock: error on "
             "processing module config.");
    ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
  }

  for(int i = 0 ; i < modpblk.nParams ; ++i) {
    if (!paramVals[i].bUsed)
      continue;

    if (!strcmp(modpblk.descr[i].name, "path")) {
      g_load_mod_conf->pszBindPath =
          (uchar*)es_str2cstr(paramVals[i].val.d.estr, NULL);
    }
  }

finalize_it:
  if (paramVals != NULL)
    cnfparamvalsDestruct(paramVals, &modpblk);
ENDsetModCnf


BEGINendCnfLoad
CODESTARTendCnfLoad
  g_load_mod_conf = NULL;
ENDendCnfLoad


BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf


BEGINactivateCnfPrePrivDrop
CODESTARTactivateCnfPrePrivDrop
  assert(g_server == NULL);
  CHKiRet(CreateServer(pModConf, &g_server));
  if (g_server == NULL) {
    LogError(0, RS_RET_NO_LSTN_DEFINED, "imstdoutsock: no socket path "
             "specified. The module can not run.");
    ABORT_FINALIZE(RS_RET_NO_RUN);
  }

  assert(g_epoll_fd == -1);
  g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (g_epoll_fd < 0) {
    LogError(errno, RS_RET_EPOLL_CR_FAILED,
             "imstdoutsock: error on epoll_create()");
    ABORT_FINALIZE(RS_RET_NO_RUN);
  }

  CHKiRet(StartupServer(g_server));

finalize_it:
  if (iRet != RS_RET_OK) {
    if (g_epoll_fd != -1) {
      close(g_epoll_fd);
      g_epoll_fd = -1;
    }

    if (g_server != NULL) {
      DestroyServer(g_server);
      g_server = NULL;
    }

  }

ENDactivateCnfPrePrivDrop


BEGINactivateCnf
CODESTARTactivateCnf
ENDactivateCnf


BEGINfreeCnf
CODESTARTfreeCnf
  free(pModConf->pszBindPath);
ENDfreeCnf


BEGINrunInput
CODESTARTrunInput
  while (glbl.GetGlobalInputTermState() == 0) {
    struct epoll_event events[128];
    int nEvents = epoll_wait(
      g_epoll_fd, events, (sizeof(events) / sizeof(struct epoll_event)),
      -1);

    for(int i = 0; i < nEvents; ++i) {
      if (glbl.GetGlobalInputTermState() != 0)
        break;
      epoll_entry_t* pEpollEntry = (epoll_entry_t*) events[i].data.ptr;
      ProcessEpollEvent(pEpollEntry);
    }
  }
ENDrunInput


BEGINwillRun
CODESTARTwillRun
ENDwillRun


BEGINafterRun
CODESTARTafterRun
  if (g_epoll_fd != -1) {
    close(g_epoll_fd);
    g_epoll_fd = -1;
  }

  if (g_server != NULL) {
    CloseServer(g_server);
    DestroyServer(g_server);
    g_server = NULL;
  }
ENDafterRun


BEGINmodExit
CODESTARTmodExit
  objRelease(glbl, CORE_COMPONENT);
  objRelease(prop, CORE_COMPONENT);
  objRelease(datetime, CORE_COMPONENT);
ENDmodExit


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
  if (eFeat == sFEATURENonCancelInputTermination)
    iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
CODEqueryEtryPt_STD_CONF2_PREPRIVDROP_QUERIES
CODEqueryEtryPt_STD_CONF2_IMOD_QUERIES
CODEqueryEtryPt_IsCompatibleWithFeature_IF_OMOD_QUERIES
ENDqueryEtryPt


BEGINmodInit()
CODESTARTmodInit
  *ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr
  CHKiRet(objUse(glbl, CORE_COMPONENT));
  CHKiRet(objUse(prop, CORE_COMPONENT));
  CHKiRet(objUse(datetime, CORE_COMPONENT));
ENDmodInit

// vim: ts=2:sw=2:tw=80:et: