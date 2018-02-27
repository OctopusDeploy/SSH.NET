//////////////////////////////////////////////////////////////////////
// TOOLS
//////////////////////////////////////////////////////////////////////
#tool "nuget:?package=GitVersion.CommandLine&version=4.0.0-beta0007"
#addin "Cake.FileHelpers"
#addin "Cake.ExtendedNuGet"

//////////////////////////////////////////////////////////////////////
// ARGUMENTS
//////////////////////////////////////////////////////////////////////
var target = Argument("target", "Default");
var configuration = Argument("configuration", "Release");
var solutionFile = "./src/Renci.SshNet.VS2017.sln";
var projectFile = "./src/Renci.SshNet/Renci.SshNet.csproj";

///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES
///////////////////////////////////////////////////////////////////////////////
var artifactsDir = "./build/target/";

GitVersion gitVersionInfo;
string nugetVersion;


///////////////////////////////////////////////////////////////////////////////
// SETUP / TEARDOWN
///////////////////////////////////////////////////////////////////////////////
Setup(context =>
{
    gitVersionInfo = GitVersion(new GitVersionSettings {
        OutputType = GitVersionOutput.Json
    });

    // This seems to work better when off master than just NugetVersion.
    nugetVersion = gitVersionInfo.MajorMinorPatch + "-" + gitVersionInfo.PreReleaseLabel + gitVersionInfo.CommitsSinceVersionSourcePadded;

    if(BuildSystem.IsRunningOnTeamCity)
        BuildSystem.TeamCity.SetBuildNumber(nugetVersion);

    Information("Building SSH.NET v{0}", nugetVersion);
    Information("Informational Version {0}", gitVersionInfo.InformationalVersion);
});

Teardown(context =>
{
    Information("Finished running tasks.");
});

//////////////////////////////////////////////////////////////////////
//  PRIVATE TASKS
//////////////////////////////////////////////////////////////////////

Task("Clean")
    .Does(() =>
{
    CleanDirectory(artifactsDir);
    CleanDirectories("./src/**/bin");
    CleanDirectories("./src/**/obj");
    CleanDirectories("./src/**/TestResults");
});

Task("Restore")
    .IsDependentOn("Clean")
    .Does(() => {
        NuGetRestore(solutionFile);
    });


Task("Build")
    .IsDependentOn("Restore")
    .IsDependentOn("Clean")
    .Does(() =>
    {
        MSBuild(projectFile, settings => settings
			.SetConfiguration(configuration)
            .WithProperty("Version", nugetVersion)
			.WithTarget("Build"));
    });

Task("Pack")
    .IsDependentOn("Build")
    .Does(() =>
    {
        NuGetPack(new NuGetPackSettings
            {
                Id                      = "SSH.NET",
                Version                 = nugetVersion,
                Title                   = "SSH.NET",
                Authors                 = new[] {"Renci"},
                Owners                  = new[] {"olegkap", "drieseng"},
                Description             = "SSH.NET is a Secure Shell (SSH) library for .NET, optimized for parallelism and with broad framework support.",
                Summary                 = "A Secure Shell (SSH) library for .NET, optimized for parallelism.",
                ProjectUrl              = new Uri("https://github.com/sshnet/SSH.NET/"),
                LicenseUrl              = new Uri("https://github.com/sshnet/SSH.NET/blob/master/LICENSE"),
                Copyright               = "2012-2017, RENCI",
                Tags                    = new [] {"ssh", "scp", "sftp"},
                RequireLicenseAcceptance= false,
                Symbols                 = false,
                NoPackageAnalysis       = true,
                Files                   = new [] {
                                            new NuSpecContent {Source = "**", Target = "lib/net40"},
                                        },
                BasePath                = "./src/Renci.SshNet/bin/Release",
                OutputDirectory         = artifactsDir
            });
    });

Task("Default")
    .IsDependentOn("Pack");

//////////////////////////////////////////////////////////////////////
// EXECUTION
//////////////////////////////////////////////////////////////////////
RunTarget(target);