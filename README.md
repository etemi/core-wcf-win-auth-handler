## Introduction
CoreWcfWinAuthHandler is a native IIS Module that intercepts URLs that end in `.svc` or `.svc?wsdl`. When a request is intercepted and Windows Authentication is used, it will return the Impersonated Token in GetPrimaryToken() when the primary token is not available. 

The CoreWcfWinAuthHandler module must run **after** the Windows Authentication Module.
This workaround is needed because otherwise old WCF clients (e.g. using .NET Framework) will not work as `TokenImpersonationLevel` is `Identification` by default. For more details see https://github.com/dotnet/aspnetcore/issues/54175

## Prerequisites
- Microsoft Visual C++ Redistributable
