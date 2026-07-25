import Lake
import Lake.Load.Workspace

open Lean System

namespace LeanBun.M32

def optionJson (value : Option String) : Json :=
  match value with
  | some value => toJson value
  | none => Json.null

def sourceJson (dep : Lake.Dependency) : Json :=
  match dep.src? with
  | some (.git url revision subDir) => Json.mkObj [
      ("kind", "git"),
      ("url", url),
      ("revision", optionJson revision),
      ("subDir", optionJson (subDir.map toString))
    ]
  | some (.path directory) => Json.mkObj [
      ("kind", "path"),
      ("directory", toString directory)
    ]
  | none => Json.mkObj [("kind", "reservoir")]

def dependencyJson (dep : Lake.Dependency) : Json :=
  Json.mkObj [
    ("name", dep.name.toString (escape := false)),
    ("scope", dep.scope),
    ("version", optionJson dep.version.toString?),
    ("source", sourceJson dep)
  ]

def outputJson (configFile : String) (workspace : Lake.Workspace) : Json :=
  Json.mkObj [
    ("schemaVersion", 1),
    ("rootName", workspace.root.origName.toString (escape := false)),
    ("configFile", configFile),
    ("dependencies", toJson (workspace.root.depConfigs.map dependencyJson))
  ]

def run (workspaceDirectory configFile : String) : IO UInt32 := do
  let some leanSysroot ← IO.getEnv "LEAN_SYSROOT"
    | IO.eprintln "LEAN_SYSROOT unavailable"; return 2
  let lean ← Lake.LeanInstall.get leanSysroot (collocated := true)
  let lake := Lake.LakeInstall.ofLean lean
  Lean.withImporting do
    Lean.loadPlugin lake.sharedLib
  let elan? ← Lake.findElanInstall?
  let env ← (Lake.Env.compute lake lean elan? true).toIO (fun message => IO.userError message)
  let config : Lake.LoadConfig := {
    lakeEnv := env
    wsDir := workspaceDirectory
    relConfigFile := configFile
    reconfigure := true
    updateDeps := false
    updateToolchain := false
    packageOverrides := #[]
  }
  let workspace? ← (Lake.loadWorkspaceRoot config).toBaseIO {
    failLv := .error
    outLv := .warning
    ansiMode := .noAnsi
    out := .stderr
  }
  let some workspace := workspace? | return 3
  IO.println (outputJson configFile workspace).compress
  return 0

end LeanBun.M32

def main (args : List String) : IO UInt32 :=
  match args with
  | [workspaceDirectory, configFile] => LeanBun.M32.run workspaceDirectory configFile
  | _ => do
    IO.eprintln "usage: M32RootDeclarations <workspace-directory> <config-file>"
    return 1
