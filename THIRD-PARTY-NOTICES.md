# Third-party notices

Stellaegis.Issuer is licensed under the MIT License (see [LICENSE](LICENSE)).

Its packages contain no third-party code. They reference the packages below, which NuGet installs
alongside them, each under its own license. The table is completed as the packages are written.

| Component | Used by | License (SPDX) | Project |
| --- | --- | --- | --- |
| Stellaegis.Primitives, and Stellaegis.Primitives.Hosting | all packages | MIT | <https://github.com/Stellaegis/Stellaegis.Primitives> |
| OpenIddict | `Stellaegis.Issuer` | Apache-2.0 | <https://github.com/openiddict/openiddict-core> |
| Npgsql, Npgsql.EntityFrameworkCore.PostgreSQL | `Stellaegis.Issuer.PostgreSQL` | PostgreSQL | <https://github.com/npgsql> |
| EFCore.NamingConventions | `Stellaegis.Issuer` | Apache-2.0 | <https://github.com/efcore/EFCore.NamingConventions> |
| Microsoft.AspNetCore.Authentication.JwtBearer | `Stellaegis.Issuer.Client` | MIT | <https://github.com/dotnet/aspnetcore> |
| Microsoft.Extensions.\* | all packages | MIT | <https://github.com/dotnet> |

Test-only dependencies (xUnit, the ASP.NET Core test host, the EF Core SQLite provider) are not part of any package and are not
listed here. The PostgreSQL server that the tests and the publishing workflow use is not part of any
package either.
