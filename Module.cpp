#define _WINSOCKAPI_
#include <windows.h>
#include <sal.h>
#include <httpserv.h>
#include <iostream>
#include <sstream>

class User : public IHttpUser
{
public:
	User(IHttpUser* user) : m_user(user)
	{
		user->ReferenceUser();
		m_refs = 1;
	}

	PCWSTR GetRemoteUserName(VOID)
	{
		return m_user->GetRemoteUserName();
	}

	PCWSTR GetUserName(VOID)
	{
		return m_user->GetUserName();
	}

	PCWSTR GetAuthenticationType(VOID)
	{
		return m_user->GetAuthenticationType();
	}

	PCWSTR GetPassword(VOID)
	{
		return m_user->GetPassword();
	}

	HANDLE GetImpersonationToken(VOID)
	{
		return m_user->GetImpersonationToken();
	}

	// This method returns the primary token if it is != NULL && != INVALID
	// Otherwise it will return the value of GetImpersonationToken()
	HANDLE GetPrimaryToken(VOID)
	{
		HANDLE token = m_user->GetPrimaryToken();

		if (token == NULL || token == INVALID_HANDLE_VALUE) 
		{
			token = m_user->GetImpersonationToken();
		}

		return token;
	}

	VOID ReferenceUser(VOID)
	{
		InterlockedIncrement(&m_refs);
	}

	VOID DereferenceUser(VOID)
	{
		if (0 == InterlockedDecrement(&m_refs))
		{
			delete this;
		}
	}

	BOOL SupportsIsInRole(VOID)
	{
		return m_user->SupportsIsInRole();
	}

	HRESULT IsInRole(IN PCWSTR pszRoleName, OUT BOOL* pfInRole)
	{
		return m_user->IsInRole(pszRoleName, pfInRole);
	}

	PVOID GetUserVariable(IN PCSTR pszVariableName)
	{
		return m_user->GetUserVariable(pszVariableName);
	}

private:
	IHttpUser* m_user;
	LONG m_refs;

	virtual ~User()
	{
		m_user->DereferenceUser();
	}
};

static bool EndsWithIgnoreCase(PCWSTR str, PCWSTR suffix)
{
	size_t stringLength = wcslen(str);
	size_t suffixLength = wcslen(suffix);

	return (stringLength >= suffixLength) && _wcsicmp(str + (stringLength - suffixLength), suffix) == 0;
}

class CoreWcfWinAuthHandler : public CHttpModule
{
public:
	REQUEST_NOTIFICATION_STATUS OnAuthenticateRequest(_In_ IHttpContext* pHttpContext, _In_ IAuthenticationProvider* pProvider)
	{
		IHttpUser* user = pHttpContext->GetUser();
		if (user != NULL && (_wcsicmp(user->GetAuthenticationType(), L"negotiate") == 0 || _wcsicmp(user->GetAuthenticationType(), L"ntlm") == 0))
		{
			PCWSTR absPath = pHttpContext->GetRequest()->GetRawHttpRequest()->CookedUrl.pAbsPath;
			if (EndsWithIgnoreCase(absPath, L".svc") || EndsWithIgnoreCase(absPath, L".svc?wsdl"))
			{
				// Looks like a request to a WCF service
				pProvider->SetUser(new User(user));
			}
		}

		// Return processing to the pipeline.
		return RQ_NOTIFICATION_CONTINUE;
	}
};

class CoreWcfWinAuthHandlerFactory : public IHttpModuleFactory
{
public:
	HRESULT GetHttpModule(OUT CHttpModule** ppModule, IN IModuleAllocator* pAllocator)
	{
		UNREFERENCED_PARAMETER(pAllocator);

		CoreWcfWinAuthHandler* pModule = new CoreWcfWinAuthHandler();

		if (!pModule)
		{
			return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		}
		else
		{
			*ppModule = pModule;
			return S_OK;
		}
	}

	void Terminate()
	{
		delete this;
	}
};

// called by IIS
HRESULT __stdcall RegisterModule(DWORD dwServerVersion, IHttpModuleRegistrationInfo* pModuleInfo, IHttpServer* pGlobalInfo)
{
	UNREFERENCED_PARAMETER(dwServerVersion);
	UNREFERENCED_PARAMETER(pGlobalInfo);

	// Set the request notifications and exit.
	return pModuleInfo->SetRequestNotifications(new CoreWcfWinAuthHandlerFactory(), RQ_AUTHENTICATE_REQUEST, 0);
}