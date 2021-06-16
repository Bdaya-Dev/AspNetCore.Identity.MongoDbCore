dotnet pack src/AspNetCore.Identity.MongoDbCore.csproj --configuration Release --output nuget_build
dotnet nuget push **/nuget_build/*.nupkg -s gitlab --skip-duplicate
Remove-Item –path nuget_build –recurse