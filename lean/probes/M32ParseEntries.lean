import Lake.Load.Manifest

open Lean System

namespace LeanBun.M32

def optionJson (value : Option String) : Json :=
  match value with
  | some value => toJson value
  | none => Json.null

def entryJson (entry : Lake.PackageEntry) : Json :=
  let source := match entry.src with
    | .git url revision inputRevision subDir => Json.mkObj [
        ("kind", "git"),
        ("url", url),
        ("revision", revision),
        ("inputRevision", optionJson inputRevision),
        ("subDir", optionJson (subDir.map toString))
      ]
    | .path directory => Json.mkObj [
        ("kind", "path"),
        ("directory", toString directory)
      ]
  Json.mkObj [
    ("name", entry.name.toString (escape := false)),
    ("scope", entry.scope),
    ("inherited", entry.inherited),
    ("configFile", toString entry.configFile),
    ("manifestFile", optionJson (entry.manifestFile?.map toString)),
    ("source", source)
  ]

def run (file : String) : IO UInt32 := do
  let data ← IO.FS.readFile file
  match Lake.Manifest.parseEntries data with
  | .error message => IO.eprintln message; return 2
  | .ok entries =>
    IO.println (Json.mkObj [
      ("schemaVersion", 1),
      ("entries", toJson (entries.map entryJson))
    ]).compress
    return 0

end LeanBun.M32

def main (args : List String) : IO UInt32 :=
  match args with
  | [file] => LeanBun.M32.run file
  | _ => do
    IO.eprintln "usage: M32ParseEntries <projection-file>"
    return 1
