# Third-party notices

Stellaegis.Issuer is licensed under the MIT License (see [LICENSE](LICENSE)).

Its packages contain no third-party code. They reference the packages below, which NuGet installs
alongside them, each under its own license. The table is completed as the packages are written.

| Component | Used by | License (SPDX) | Project |
| --- | --- | --- | --- |
| Stellaegis.Primitives, and Stellaegis.Primitives.Hosting | all packages | MIT | <https://github.com/Stellaegis/Stellaegis.Primitives> |
| Stellaegis.Primitives.AspNetCore | `Stellaegis.Issuer`, `Stellaegis.Issuer.Client`, `Stellaegis.Issuer.Server` | MIT | <https://github.com/Stellaegis/Stellaegis.Primitives> |
| Stellaegis.Primitives.Data | `Stellaegis.Issuer.PostgreSQL`, `Stellaegis.Issuer.SqlServer` | MIT | <https://github.com/Stellaegis/Stellaegis.Primitives> |
| OpenIddict | `Stellaegis.Issuer` | Apache-2.0 | <https://github.com/openiddict/openiddict-core> |
| Npgsql, Npgsql.EntityFrameworkCore.PostgreSQL | `Stellaegis.Issuer.PostgreSQL` | PostgreSQL | <https://github.com/npgsql> |
| Microsoft.EntityFrameworkCore.SqlServer, Microsoft.Data.SqlClient | `Stellaegis.Issuer.SqlServer` | MIT | <https://github.com/dotnet/efcore>, <https://github.com/dotnet/SqlClient> |
| EFCore.NamingConventions | `Stellaegis.Issuer` | Apache-2.0 | <https://github.com/efcore/EFCore.NamingConventions> |
| Microsoft.AspNetCore.Authentication.JwtBearer | `Stellaegis.Issuer.Client` | MIT | <https://github.com/dotnet/aspnetcore> |
| System.Security.Cryptography.Pkcs, System.Security.Cryptography.Xml | `Stellaegis.Issuer.PostgreSQL`, `Stellaegis.Issuer.SqlServer` (pinned above the versions the providers pull in) | MIT | <https://github.com/dotnet/runtime> |
| Microsoft.Extensions.\* | all packages | MIT | <https://github.com/dotnet> |

`Stellaegis.Issuer`, `Stellaegis.Issuer.Client` and `Stellaegis.Issuer.Server` use the ASP.NET Core shared framework, which the host already has.

Test-only dependencies (xUnit, the ASP.NET Core test host, the EF Core SQLite provider) are not part of any package and are not
listed here. The PostgreSQL server that the tests and the publishing workflow use is not part of any
package either.
